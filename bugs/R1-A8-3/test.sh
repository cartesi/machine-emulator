#!/bin/bash
# R1-A8-3: in the referee model (doc/recipes/prt.lua referee over game-transport.lua), one claimant
# that keeps its connection open and stops answering freezes logical time, so a match it is not in
# (the honest claim's match against a quitter) never reaches its deadline and never settles.
#
# Two tournaments over the same epoch (bare-metal emit-output template, three inputs), four players
# each, joined in this order so the referee pairs them as  match 1 = P1 vs quitter,
# match 2 = honest vs "quitter 1":
#   control: P1 is another quitter (leaves after its claim, as prt-dishonest.lua does)
#   silent:  P1 is silent-quitter.lua (posts its claim, then never answers, socket left open)
# Required (A8): match 2 settles in the silent run as it does in the control run.
# Exit 0: it settles; 1: it does not settle within a bound of 10x the control's settle time
# (at least 60 s) while the control settled; 2: setup error.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${REPO:?run through bugs/run.sh}" "${RECIPES_DIR:?}" "${HARNESS_WORK:?}"
export TEMPLATE="$HARNESS_WORK/configs/baremetal-template/machine"
[ -d "$TEMPLATE" ] || { echo "setup: missing $TEMPLATE (bugs/harness/configs/make-configs.sh)" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/r1-a8-3.XXXXXX") || exit 2
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
setup_error() { echo "setup: $*" >&2; exit 2; }

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

# A listening socket on the port (state 0A); probing with a connection would disturb the referee.
listening() {
    local hexport
    hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4 == "0A" && substr($2, length($2) - 4) == p' /proc/net/tcp | grep -q .
}

alive() { kill -0 "$1" 2>/dev/null; }

# start <dir> <name> <command...>: background child in <dir>, stderr to <name>.stderr
start() {
    local dir=$1 name=$2
    shift 2
    (cd "$dir" && exec setsid "$@" > /dev/null 2> "$name.stderr") &
    LAST=$!
    PIDS+=("$LAST")
}

# wait_for <seconds> <command...>: 0 when the command succeeds in time
wait_for() {
    local limit=$1 t0=$SECONDS
    shift
    until "$@"; do
        [ $((SECONDS - t0)) -lt "$limit" ] || return 1
        sleep 0.5
    done
}

# setup_run <mode>: prepares the run directory, starts the referee and joins the players in order.
setup_run() {
    local mode=$1 dir="$WORK/$1" port n=0
    mkdir -p "$dir" || setup_error "mkdir"
    ln -s "$TEMPLATE" "$dir/$initial_hash"
    printf 'first input\n' > "$dir/input-0.bin"
    printf 'second input\n' > "$dir/input-1.bin"
    printf 'third input\n' > "$dir/input-2.bin"
    port=$(free_port) || setup_error "no free port"
    local addr="127.0.0.1:$port"
    start "$dir" referee lua5.4 "$RECIPES_DIR/prt.lua" referee "$addr" "$initial_hash" input-0.bin input-1.bin input-2.bin
    REFEREE_PID=$LAST
    wait_for 60 listening "$port" || setup_error "$mode: referee did not listen"$'\n'"$(cat "$dir"/*.stderr)"
    local base
    base=$(connections_to "$port")
    join() {
        start "$dir" "$@"
        n=$((n + 1))
        wait_for 120 bash -c '[ "$(connections_to_ '"$port"')" -ge '"$((base + n))"' ]' ||
            setup_error "$mode: $1 did not connect (see stderr below)"$'\n'"$(cat "$dir"/*.stderr)"
    }
    export -f connections_to
    connections_to_() { connections_to "$@"; }
    export -f connections_to_
    if [ "$mode" = silent ]; then
        join silent lua5.4 "$HERE/silent-quitter.lua" "$addr" "$initial_hash" silent
    else
        join quitter_2 lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$addr" "$initial_hash" "quitter 2"
    fi
    join quitter lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$addr" "$initial_hash"
    PRT_GAME_TRACE=1 join honest lua5.4 "$RECIPES_DIR/prt.lua" honest "$addr" "$initial_hash"
    join quitter_1 lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$addr" "$initial_hash" "quitter 1"
    start "$dir" phase_closer lua5.4 "$RECIPES_DIR/prt.lua" phase_closer "$addr"
    RUN_DIR=$dir
}

match2_settled() { grep -q '^Match 2: ' "$RUN_DIR/tournament" 2> /dev/null; }
max_block() {
    grep '^from referee .*"advance_time"' "$RUN_DIR/honest.stderr" 2> /dev/null |
        grep -o '"arguments":\[[0-9]*' | grep -o '[0-9]*$' | sort -n | tail -1
}

# ---- control run --------------------------------------------------------------------------------
setup_run control
t0=$SECONDS
wait_for 300 bash -c 'grep -q "^Match 2: " "'"$RUN_DIR"'/tournament" 2>/dev/null || ! kill -0 '"$REFEREE_PID"
if ! match2_settled; then
    echo "control run: match 2 did not settle (referee alive: $(alive "$REFEREE_PID" && echo yes || echo no))" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
fi
control_seconds=$((SECONDS - t0))
wait_for 120 grep -q 'Tournament winner is claim' "$RUN_DIR/verdict" 2> /dev/null
control_winner=$(grep -h 'Tournament winner is claim' "$RUN_DIR/verdict" 2> /dev/null)
echo "control: claims:"
sed 's/^/  /' "$RUN_DIR/claims"
echo "control: tournament:"
sed 's/^/  /' "$RUN_DIR/tournament"
echo "control: ${control_winner:-no verdict yet}; match 2 settled after ${control_seconds}s; honest saw logical block $(max_block)"
kill_all

# ---- silent run ---------------------------------------------------------------------------------
bound=$((control_seconds * 10))
[ "$bound" -ge 60 ] || bound=60
setup_run silent
t0=$SECONDS
wait_for "$bound" bash -c 'grep -q "^Match 2: " "'"$RUN_DIR"'/tournament" 2>/dev/null || ! kill -0 '"$REFEREE_PID"
alive "$REFEREE_PID" || match2_settled || {
    echo "silent run: referee exited" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
}
grep -q 'stops answering' "$RUN_DIR/silent.stderr" || {
    match2_settled && { echo "silent run: match 2 settled"; exit 0; }
    echo "silent run: the silent claimant was never asked anything after its claim" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
}
echo "silent: claims:"
sed 's/^/  /' "$RUN_DIR/claims" 2> /dev/null
echo "silent: tournament after $((SECONDS - t0))s:"
sed 's/^/  /' "$RUN_DIR/tournament" 2> /dev/null
echo "silent: $(cat "$RUN_DIR/silent.stderr" | tail -1); honest saw logical block $(max_block)"
if match2_settled; then
    echo "PASS: match 2 (honest vs quitter 1) settled although the claimant of match 1 went silent"
    exit 0
fi
echo "FAIL (A8): match 2 (honest vs quitter 1) did not settle within ${bound}s (control: ${control_seconds}s)"
echo "  because the claimant of match 1 went silent with its connection open; logical time stopped."
echo "  A8: \"Failing to process one match's data, for any reason, must not stop, delay or decide any other match.\""
exit 1
