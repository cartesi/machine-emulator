#!/bin/bash
# R9-SUBREFSTATE-2: the PRT referee model (doc/recipes/prt.lua referee over game-transport.lua) binds
# a claim to the TCP connections that posted it. partition_claims subscribes only the connections whose
# claim responses it accepted, and every later request about the claim (reveal_bisection,
# seal_divergence, win_match_by_timeout, commit_uarch_claim, prove_state_transition) goes to, and is
# accepted only from, that fixed audience. An honest player that stops and restarts (R4) comes back
# on a new connection, so it can never again answer for its claim, which then loses by timeout.
#
# Two tournaments over the same epoch (bare-metal emit-output template, three inputs), with the
# honest player (a stored player on an epoch directory, as `prt.lua honest ... <epoch-directory>`)
# joining first and a tamperer (prt-dishonest.lua tamperer 1 0: corrupts its execution of input 1, so
# its claim ends in a different final state) second:
#   run "control": the honest player runs unchanged. Required for the setup: the honest claim wins.
#   run "restart": at its claim's first reveal_bisection request, the honest player stops. While its
#     reply is outstanding (the referee's logical clock cannot advance, so no block passes), it is
#     restarted from its epoch directory as a new process and connection, which reopens the sealed
#     epoch and holds the honest claim's tree; only once the referee has read the new connection's
#     announcement does the first incarnation leave with an announced "done" reply (an EOF would
#     crash the referee, R3-VARREFMODEL-2). Required (A7, R4): the honest claim still wins.
# Exit 0: the honest claim wins after the restart; 1: it loses (bug present); 2: setup error.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${REPO:?run through bugs/run.sh}" "${RECIPES_DIR:?}" "${HARNESS_WORK:?}"
export TEMPLATE="$HARNESS_WORK/configs/baremetal-template/machine"
[ -d "$TEMPLATE" ] || { echo "setup: missing $TEMPLATE (bugs/harness/configs/make-configs.sh)" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/r9-subrefstate-2.XXXXXX") || exit 2
PIDS=()
# Each child leads its own process group (setsid), so the machine servers a player spawns die with it.
kill_all() {
    local pid
    for pid in "${PIDS[@]}"; do kill -TERM -- "-$pid" 2> /dev/null || kill -TERM "$pid" 2> /dev/null; done
    sleep 0.5
    for pid in "${PIDS[@]}"; do kill -KILL -- "-$pid" 2> /dev/null || kill -KILL "$pid" 2> /dev/null; done
    wait 2> /dev/null
    PIDS=()
}
cleanup() {
    kill_all
    if [ -n "${KEEP:-}" ]; then echo "kept $WORK" >&2; else rm -rf "$WORK"; fi
}
trap cleanup EXIT
setup_error() {
    echo "setup: $*" >&2
    exit 2
}

initial_hash=$(lua5.4 -e 'local cartesi = require("cartesi")
local m <close> = cartesi.machine(os.getenv("TEMPLATE"), {})
io.write(cartesi.tohex(m:get_root_hash()))') || setup_error "cannot load $TEMPLATE"

free_port() {
    lua5.4 -e 'local s = require("socket").bind("127.0.0.1", 0); local _, p = s:getsockname(); s:close(); io.write(p)'
}

# Established loopback connections to the port (each appears twice in /proc/net/tcp).
connections_to() {
    local hexport
    hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4 == "01" && (substr($2, length($2) - 4) == p || substr($3, length($3) - 4) == p)' \
        /proc/net/tcp | wc -l | awk '{ print int($1 / 2) }'
}
export -f connections_to

# A listening socket on the port (state 0A); probing with a connection would itself crash the referee.
listening() {
    local hexport
    hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4 == "0A" && substr($2, length($2) - 4) == p' /proc/net/tcp | grep -q .
}

alive() { kill -0 "$1" 2> /dev/null && ! grep -q '^State:.*Z' "/proc/$1/status" 2> /dev/null; }

# start <dir> <name> <command...>: background child in <dir>, stdout/stderr to <name>.stdout/.stderr
start() {
    local dir=$1 name=$2
    shift 2
    (cd "$dir" && exec setsid "$@" > "$name.stdout" 2> "$name.stderr") &
    LAST=$!
    PIDS+=("$LAST")
}

# wait_for <seconds> <command...>: 0 when the command succeeds in time
wait_for() {
    local limit=$1 t0=$SECONDS
    shift
    until "$@"; do
        [ $((SECONDS - t0)) -lt "$limit" ] || return 1
        sleep 0.2
    done
}

# setup_run <mode>: prepares the run directory, starts the referee and joins honest, then tamperer.
setup_run() {
    local mode=$1 dir="$WORK/$1" n=0
    mkdir -p "$dir/state" "$dir/epoch-honest" || setup_error "mkdir"
    ln -s "$TEMPLATE" "$dir/$initial_hash"
    printf 'first input\n' > "$dir/input-0.bin"
    printf 'second input\n' > "$dir/input-1.bin"
    printf 'third input\n' > "$dir/input-2.bin"
    PORT=$(free_port) || setup_error "no free port"
    ADDR="127.0.0.1:$PORT"
    # The referee traces the lines it reads (PRT_GAME_TRACE), so the test can see when it has read the
    # restarted player's announcement.
    start "$dir" referee env PRT_GAME_TRACE=1 lua5.4 "$RECIPES_DIR/prt.lua" referee "$ADDR" "$initial_hash" \
        input-0.bin input-1.bin input-2.bin
    REFEREE_PID=$LAST
    wait_for 60 listening "$PORT" || setup_error "$mode: referee did not listen"$'\n'"$(cat "$dir"/*.stderr)"
    local base
    base=$(connections_to "$PORT")
    join() {
        start "$dir" "$@"
        n=$((n + 1))
        wait_for 120 bash -c '[ "$(connections_to '"$PORT"')" -ge '"$((base + n))"' ]' ||
            setup_error "$mode: $1 did not connect (see stderr below)"$'\n'"$(tail -n 20 "$dir"/*.stderr)"
    }
    join honest lua5.4 "$HERE/honest-first.lua" "$ADDR" "$initial_hash" honest "$dir/epoch-honest" "$dir/state" "$mode"
    HONEST_PID=$LAST
    join tamperer lua5.4 "$RECIPES_DIR/prt-dishonest.lua" tamperer "$ADDR" "$initial_hash" 1 0 tamperer
    start "$dir" phase_closer lua5.4 "$RECIPES_DIR/prt.lua" phase_closer "$ADDR"
    RUN_DIR=$dir
}

has_winner() { grep -q 'Tournament winner is claim' "$RUN_DIR/verdict" 2> /dev/null; }
no_survivor() { grep -q '^Match 1: no claim survives' "$RUN_DIR/tournament" 2> /dev/null; }
referee_down() { ! alive "$REFEREE_PID"; }
decided() { has_winner || no_survivor || referee_down; }
winner_hash() { sed -n 's/^Winner computation hash: //p' "$RUN_DIR/verdict" 2> /dev/null; }
honest_claim() { tr -d '[:space:]' < "$RUN_DIR/state/claim.hex" 2> /dev/null; }

# ---- run "control": the honest player is never stopped -------------------------------------------
setup_run control
wait_for 480 decided
has_winner || {
    echo "control run: no winner (referee alive: $(alive "$REFEREE_PID" && echo yes || echo no))" >&2
    tail -n 20 "$RUN_DIR"/*.stderr "$RUN_DIR"/tournament >&2
    exit 2
}
echo "control: tournament:"
sed 's/^/  /' "$RUN_DIR/tournament"
[ -n "$(honest_claim)" ] && [ "$(winner_hash)" = "$(honest_claim)" ] || {
    echo "control run: the honest claim $(honest_claim) did not win (winner $(winner_hash))" >&2
    exit 2
}
final_state() { sed -n 's/^Winner final state hash: //p' "$RUN_DIR/verdict" 2> /dev/null; }
honest_final=$(final_state)
echo "control: the honest claim $(honest_claim) wins (no restart), final state $honest_final"
kill_all

# ---- run "restart": the honest player stops at its claim's first turn and restarts -------------------
setup_run restart
wait_for 300 bash -c '[ -f "'"$RUN_DIR"'/state/stopping" ] || ! kill -0 '"$REFEREE_PID"' 2>/dev/null' ||
    setup_error "restart run: the honest claim was never asked to open a node"
[ -f "$RUN_DIR/state/stopping" ] || setup_error "restart run: referee exited before the honest turn"$'\n'"$(tail -n 20 "$RUN_DIR"/referee.stderr)"
read -r _ stop_hash stop_position stop_height < "$RUN_DIR/state/stopping"
echo "restart: first incarnation stops at reveal_bisection(position=$stop_position, height=$stop_height) of claim $stop_hash"
echo "  (its reply is outstanding, so the referee's logical clock cannot advance)"
start "$RUN_DIR" restarted lua5.4 "$HERE/honest-restarted.lua" "$ADDR" "$initial_hash" "honest (restarted)" \
    "$RUN_DIR/epoch-honest" "$RUN_DIR/state"
# The restarted player has reopened its epoch directory and holds its claim's tree, and the referee
# has read its announcement, all while the first incarnation's reply is outstanding.
wait_for 120 bash -c '[ -f "'"$RUN_DIR"'/state/restarted-holds" ] && grep -q "honest (restarted)" "'"$RUN_DIR"'/referee.stderr"' ||
    setup_error "restart run: the restarted player did not reopen its directory or connect"$'\n'"$(tail -n 20 "$RUN_DIR"/restarted.stderr)"
alive "$HONEST_PID" || setup_error "restart run: the first incarnation exited before its departure"
echo "restart: second incarnation reopened the epoch directory, holds claim $(tr -d '[:space:]' < "$RUN_DIR/state/restarted-holds"), and is connected"
touch "$RUN_DIR/state/go"
wait_for 60 bash -c '! kill -0 '"$HONEST_PID"' 2>/dev/null' || setup_error "restart run: the first incarnation did not leave"
echo "restart: first incarnation left with an announced departure (done)"
wait_for 480 decided
if referee_down && ! has_winner; then
    echo "restart run: the referee exited without a verdict" >&2
    tail -n 20 "$RUN_DIR"/referee.stderr >&2
    exit 2
fi
has_winner || no_survivor || setup_error "restart run: no decision"
echo "restart: tournament:"
sed 's/^/  /' "$RUN_DIR/tournament"
sed 's/^/  /' "$RUN_DIR"/match_1 2> /dev/null | tail -n 4
claim=$(honest_claim)
claim_requests=$(grep -cE "received ((reveal_bisection|seal_divergence|win_match_by_timeout) $claim|commit_uarch_claim|prove_state_transition)" "$RUN_DIR/restarted.stderr")
echo "restart: requests about the claim received by the restarted player: $claim_requests"
grep 'received' "$RUN_DIR/restarted.stderr" | sort | uniq -c | sed 's/^ */  /' | head -n 8

winner=$(winner_hash)
if [ -n "$winner" ] && [ "$winner" = "$claim" ]; then
    echo "PASS: the honest claim $claim wins after its player restarted"
    exit 0
fi
echo "FAIL (A7/R4): the honest claim $claim lost after its player restarted within its clock"
if [ -n "$winner" ]; then
    echo "  winner: the tamperer's claim $winner, final state $(final_state) (honest final state $honest_final)"
else
    echo "  no claim survives"
fi
echo "  A7: \"No rule of the referee may make the honest claim lose by timeout while it acts within its own clock.\""
echo "  R4: \"After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim.\""
exit 1
