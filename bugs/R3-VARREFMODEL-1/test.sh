#!/bin/bash
# R3-VARREFMODEL-1: the PRT referee model (doc/recipes/prt.lua referee over game-transport.lua)
# takes the phase-closer role from any connection that announces it. That connection decides
# when claim admission closes (and so which claims exist) and can stop the referee at any time.
#
# Runs (bare-metal emit-output template, one input; free loopback ports, no chain):
#   control: referee; a quitter (prt-dishonest.lua, fabricated claim) joins; the honest player
#            (prt.lua honest) joins; the orchestration's phase closer (prt.lua phase_closer)
#            closes admission. The honest claim wins (setup check).
#   stop:    on the control referee, now settled and waiting for output proofs, an arbitrary
#            client sends the phase-closer "stop" announcement (closer-client.lua ... stop).
#            Required (A5): the referee keeps accepting outputs, so it must not end.
#   attack:  as control, but after the quitter joins an arbitrary client announces the
#            phase-closer role and closes admission (closer-client.lua), before the honest player
#            joins. The orchestration's phase closer still runs after the honest player.
#            Required (section 1 goal, A7): the honest claim still enters and wins, i.e. the
#            winner is the control winner.
# Exit 0: both requirements hold; 1: either is violated; 2: setup error.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${REPO:?run through bugs/run.sh}" "${RECIPES_DIR:?}" "${HARNESS_WORK:?}"
export TEMPLATE="$HARNESS_WORK/configs/baremetal-template/machine"
[ -d "$TEMPLATE" ] || { echo "setup: missing $TEMPLATE (bugs/harness/configs/make-configs.sh)" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/r3-varrefmodel-1.XXXXXX") || exit 2
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

# A listening socket on the port (state 0A); probing with a connection would disturb the referee.
listening() {
    local hexport
    hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4 == "0A" && substr($2, length($2) - 4) == p' /proc/net/tcp | grep -q .
}

alive() { kill -0 "$1" 2> /dev/null; }

# start <dir> <name> <command...>: background child in <dir>, stderr to <name>.stderr
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
        sleep 0.5
    done
}

# start_referee <mode>: run directory with the template under its hash name, one input, a referee.
start_referee() {
    local mode=$1
    RUN_DIR="$WORK/$mode"
    mkdir -p "$RUN_DIR" || setup_error "mkdir"
    ln -s "$TEMPLATE" "$RUN_DIR/$initial_hash"
    printf 'first input\n' > "$RUN_DIR/input-0.bin"
    PORT=$(free_port) || setup_error "no free port"
    ADDR="127.0.0.1:$PORT"
    start "$RUN_DIR" referee lua5.4 "$RECIPES_DIR/prt.lua" referee "$ADDR" "$initial_hash" input-0.bin
    REFEREE_PID=$LAST
    wait_for 60 listening "$PORT" || setup_error "$mode: referee did not listen"$'\n'"$(cat "$RUN_DIR"/*.stderr)"
}

# pid_connected <pid> <port>: the process holds an established TCP connection to the port. Other
# players leave over time, so a count of all connections to the port would not tell who joined.
pid_connected() {
    local hexport inodes
    hexport=$(printf '%04X' "$2")
    inodes=$(ls -l "/proc/$1/fd" 2> /dev/null | grep -o 'socket:\[[0-9]*\]' | grep -o '[0-9]*' | tr '\n' ' ')
    [ -n "$inodes" ] || return 1
    awk -v p=":$hexport" -v inodes=" $inodes" '$4 == "01" && substr($3, length($3) - 4) == p && index(inodes, " " $10 " ") { found = 1 }
        END { exit !found }' /proc/net/tcp
}

# join <name> <command...>: start a player and wait until its connection to the referee is established
join() {
    local name=$1
    start "$RUN_DIR" "$@"
    wait_for 120 pid_connected "$LAST" "$PORT" ||
        setup_error "$name did not connect"$'\n'"$(tail -n 20 "$RUN_DIR"/*.stderr)"
    # the player sends its announcement right after connecting; let the referee read it
    sleep 1
}

verdict_or_exit() { grep -q 'Tournament winner is claim' "$RUN_DIR/verdict" 2> /dev/null || ! alive "$REFEREE_PID"; }
winner_hash() { grep -h 'Winner computation hash:' "$RUN_DIR/verdict" 2> /dev/null | awk '{ print $NF }'; }
commit_requests() { grep -c '^from referee .*"commit_mcycle_claim"' "$RUN_DIR/honest.stderr" 2> /dev/null; }

# ---- control run --------------------------------------------------------------------------------
start_referee control
join quitter lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$ADDR" "$initial_hash"
PRT_GAME_TRACE=1 join honest lua5.4 "$RECIPES_DIR/prt.lua" honest "$ADDR" "$initial_hash"
start "$RUN_DIR" phase_closer lua5.4 "$RECIPES_DIR/prt.lua" phase_closer "$ADDR"
wait_for 300 verdict_or_exit
control_winner=$(winner_hash)
echo "control: claims:"
sed 's/^/  /' "$RUN_DIR/claims" 2> /dev/null
echo "control: winner computation hash ${control_winner:-none}; honest got commit_mcycle_claim $(commit_requests) time(s)"
if [ -z "$control_winner" ] || ! grep -q "^Claim ${control_winner:0:10}.*posted by honest" "$RUN_DIR/claims"; then
    echo "control: the honest claim did not win" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
fi
alive "$REFEREE_PID" || setup_error "control: the referee exited after the verdict instead of waiting for outputs"

# ---- stop: an arbitrary client sends the phase-closer stop to the settled referee -------------------
stop_result=$(lua5.4 "$HERE/closer-client.lua" "$ADDR" stop 2>&1)
echo "stop: arbitrary client announced {\"role\":\"phase_closer\",\"command\":\"stop\"}: $stop_result"
# A referee that honours the stop exits at once; one that refuses it keeps waiting for output proofs.
if wait_for 20 bash -c '! kill -0 '"$REFEREE_PID"' 2>/dev/null'; then
    wait "$REFEREE_PID" 2> /dev/null
    stop_status=$?
    stop_violated=1
    echo "stop: the referee ended (exit status $stop_status) while waiting for output proofs; last lines of its stdout:"
    tail -n 3 "$RUN_DIR/referee.stdout" | sed 's/^/  /'
else
    stop_violated=0
    echo "stop: the referee is still running after 20 s"
fi
kill_all

# ---- attack run ---------------------------------------------------------------------------------
start_referee attack
join quitter lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$ADDR" "$initial_hash"
spoof_result=$(lua5.4 "$HERE/closer-client.lua" "$ADDR" 2>&1)
echo "attack: arbitrary client announced {\"role\":\"phase_closer\"} before the honest player joined: $spoof_result"
alive "$REFEREE_PID" || setup_error "attack: the referee died"$'\n'"$(tail -n 20 "$RUN_DIR"/referee.stderr)"
PRT_GAME_TRACE=1 join honest lua5.4 "$RECIPES_DIR/prt.lua" honest "$ADDR" "$initial_hash"
start "$RUN_DIR" phase_closer lua5.4 "$RECIPES_DIR/prt.lua" phase_closer "$ADDR"
wait_for 300 verdict_or_exit
attack_winner=$(winner_hash)
echo "attack: claims:"
sed 's/^/  /' "$RUN_DIR/claims" 2> /dev/null
echo "attack: winner computation hash ${attack_winner:-none}; honest got commit_mcycle_claim $(commit_requests) time(s)"
[ -n "$attack_winner" ] || {
    echo "attack: no verdict (referee alive: $(alive "$REFEREE_PID" && echo yes || echo no))" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
}
sleep 1
echo "attack: the orchestration's phase closer, run after the honest player joined: $(head -n 1 "$RUN_DIR/phase_closer.stderr" 2> /dev/null | cut -c1-160)"
close_violated=0
[ "$attack_winner" = "$control_winner" ] || close_violated=1
kill_all

# ---- verdict ------------------------------------------------------------------------------------
status=0
if [ "$close_violated" = 1 ]; then
    echo "FAIL (section 1 goal, A7): an unauthenticated connection closed claim admission before the honest"
    echo "  player joined; the honest claim never entered and the winner is $attack_winner"
    echo "  ($(grep -h "^Claim ${attack_winner:0:10}" "$WORK/attack/claims" 2> /dev/null | grep -o 'posted by [^)]*'))"
    echo "  instead of the honest claim $control_winner."
    echo "  Section 3: a referee model defect \"in what it accepts or derives is rated as if a deployed referee had it\"."
    status=1
else
    echo "PASS: the honest claim won although an arbitrary client announced the phase-closer role first"
fi
if [ "$stop_violated" = 1 ]; then
    echo "FAIL (A5): an unauthenticated connection stopped the settled referee; it no longer accepts output proofs."
    echo "  A5: \"the referee accepts every output that the settled state commits to, whenever its valid proof is"
    echo "  presented. No party can make it stop accepting them.\""
    status=1
else
    echo "PASS: the settled referee ignored the stop announced by an arbitrary client"
fi
exit "$status"
