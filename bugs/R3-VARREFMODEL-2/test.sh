#!/bin/bash
# R3-VARREFMODEL-2: the PRT referee model (doc/recipes/prt.lua referee over game-transport.lua)
# exits as soon as any TCP connection to it reaches EOF without a "done" reply: the reader
# coroutine of every connection asserts that a line arrived ("unexpected connection loss"), and the
# dispatcher turns a coroutine error into a fatal error. So one connection's loss stops every match
# and output acceptance.
#
# Two tournaments over the same epoch (bare-metal emit-output template, three inputs), four players
# each, joined in the order of bugs/R1-A8-3, so the referee pairs match 1 = P1 vs quitter and
# match 2 = honest vs "quitter 1":
#   run "stray": P1 is a third quitter (leaves with a "done" reply, as prt-dishonest.lua does). Once
#     the tournament has a winner and the referee is waiting for output proofs, a stray TCP client
#     connects to the referee and closes without sending anything.
#     Required (A5): the referee keeps accepting outputs, i.e. it is still running afterwards.
#   run "crash": P1 is crashing-quitter.lua: the same claim, but its process exits at the first
#     request after its claim instead of replying "done" (a crashed or killed claimant).
#     Required (A8): match 2, which does not involve P1, settles as in the stray run, and the
#     referee survives.
# Exit 0: both requirements hold; 1: the referee died of the connection loss (or match 2 did not
# settle) in either case; 2: setup error.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
: "${REPO:?run through bugs/run.sh}" "${RECIPES_DIR:?}" "${HARNESS_WORK:?}"
export TEMPLATE="$HARNESS_WORK/configs/baremetal-template/machine"
[ -d "$TEMPLATE" ] || { echo "setup: missing $TEMPLATE (bugs/harness/configs/make-configs.sh)" >&2; exit 2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/r3-varrefmodel-2.XXXXXX") || exit 2
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
export -f connections_to

# A listening socket on the port (state 0A); probing with a connection would itself trigger the bug.
listening() {
    local hexport
    hexport=$(printf '%04X' "$1")
    awk -v p=":$hexport" '$4 == "0A" && substr($2, length($2) - 4) == p' /proc/net/tcp | grep -q .
}

alive() { kill -0 "$1" 2> /dev/null && ! grep -q '^State:.*Z' "/proc/$1/status" 2> /dev/null; }

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
    local mode=$1 dir="$WORK/$1" n=0
    mkdir -p "$dir" || setup_error "mkdir"
    ln -s "$TEMPLATE" "$dir/$initial_hash"
    printf 'first input\n' > "$dir/input-0.bin"
    printf 'second input\n' > "$dir/input-1.bin"
    printf 'third input\n' > "$dir/input-2.bin"
    PORT=$(free_port) || setup_error "no free port"
    local addr="127.0.0.1:$PORT"
    start "$dir" referee lua5.4 "$RECIPES_DIR/prt.lua" referee "$addr" "$initial_hash" input-0.bin input-1.bin input-2.bin
    REFEREE_PID=$LAST
    wait_for 60 listening "$PORT" || setup_error "$mode: referee did not listen"$'\n'"$(cat "$dir"/*.stderr)"
    local base
    base=$(connections_to "$PORT")
    join() {
        start "$dir" "$@"
        n=$((n + 1))
        wait_for 120 bash -c '[ "$(connections_to '"$PORT"')" -ge '"$((base + n))"' ]' ||
            setup_error "$mode: $1 did not connect (see stderr below)"$'\n'"$(cat "$dir"/*.stderr)"
    }
    if [ "$mode" = crash ]; then
        join crasher lua5.4 "$HERE/crashing-quitter.lua" "$addr" "$initial_hash" crasher
    else
        join quitter_2 lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$addr" "$initial_hash" "quitter 2"
    fi
    join quitter lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$addr" "$initial_hash"
    join honest lua5.4 "$RECIPES_DIR/prt.lua" honest "$addr" "$initial_hash"
    join quitter_1 lua5.4 "$RECIPES_DIR/prt-dishonest.lua" quitter "$addr" "$initial_hash" "quitter 1"
    start "$dir" phase_closer lua5.4 "$RECIPES_DIR/prt.lua" phase_closer "$addr"
    RUN_DIR=$dir
}

match2_settled() { grep -q '^Match 2: ' "$RUN_DIR/tournament" 2> /dev/null; }
has_winner() { grep -q 'Tournament winner is claim' "$RUN_DIR/verdict" 2> /dev/null; }
loss_message() { grep -h -m1 -o 'unexpected connection loss[^"]*' "$RUN_DIR/referee.stderr" 2> /dev/null; }
referee_down() { ! alive "$REFEREE_PID"; }

fail=0

# ---- run "stray": a connect-and-close while the referee accepts outputs (A5) ---------------------
setup_run stray
wait_for 300 bash -c 'grep -q "Tournament winner is claim" "'"$RUN_DIR"'/verdict" 2>/dev/null || ! kill -0 '"$REFEREE_PID"' 2>/dev/null'
has_winner && match2_settled || {
    echo "stray run: the tournament did not reach a winner (referee alive: $(alive "$REFEREE_PID" && echo yes || echo no))" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
}
stray_match2=$(grep -h '^Match 2: ' "$RUN_DIR/tournament")
echo "stray: tournament:"
sed 's/^/  /' "$RUN_DIR/tournament"
echo "stray: $(grep -h 'Tournament winner is claim' "$RUN_DIR/verdict")"
# The referee now waits FOREVER for output proofs (prt.lua wait_for_outputs). Control: it stays up.
sleep 3
alive "$REFEREE_PID" || { echo "stray run: referee exited on its own after the verdict" >&2; tail -n 20 "$RUN_DIR"/*.stderr >&2; exit 2; }
before=$(connections_to "$PORT")
echo "stray: referee alive 3s after the verdict, waiting for output proofs ($before connections open)"
STRAY_PORT=$PORT lua5.4 -e 'local s = assert(require("socket").connect("127.0.0.1", tonumber(os.getenv("STRAY_PORT")))); s:close()' ||
    setup_error "stray connection failed"
echo "stray: a TCP client connected and closed without sending anything"
wait_for 15 referee_down
if alive "$REFEREE_PID"; then
    echo "stray: referee still running 15s after the stray connection closed"
else
    msg=$(loss_message)
    echo "stray: referee EXITED after the stray connection closed: ${msg:-see stderr}"
    tail -n 4 "$RUN_DIR/referee.stderr" | sed 's/^/  referee: /'
    echo "FAIL (A5): one stray connection made the referee stop accepting outputs of the settled state"
    echo "  A5: \"the referee accepts every output that the settled state commits to, whenever its valid proof"
    echo "  is presented. No party can make it stop accepting them.\""
    fail=1
fi
kill_all

# ---- run "crash": a claimant process dies after posting its claim (A8) ----------------------------
setup_run crash
wait_for 120 bash -c 'grep -q "^Match 2: " "'"$RUN_DIR"'/tournament" 2>/dev/null || ! kill -0 '"$REFEREE_PID"' 2>/dev/null'
# let a crash that follows closely be observed too
sleep 2
grep -q 'process dies' "$RUN_DIR/crasher.stderr" 2> /dev/null || {
    if match2_settled && alive "$REFEREE_PID"; then
        setup_error "crash run: the crashing claimant was never asked anything after its claim"
    fi
    echo "crash run: the referee stopped before the claimant crashed" >&2
    tail -n 20 "$RUN_DIR"/*.stderr >&2
    exit 2
}
echo "crash: claims:"
sed 's/^/  /' "$RUN_DIR/claims" 2> /dev/null
echo "crash: tournament:"
sed 's/^/  /' "$RUN_DIR/tournament" 2> /dev/null
echo "crash: $(tail -n 1 "$RUN_DIR/crasher.stderr")"
if match2_settled && alive "$REFEREE_PID"; then
    echo "crash: match 2 settled and the referee is running: $(grep -h '^Match 2: ' "$RUN_DIR/tournament")"
else
    msg=$(loss_message)
    if alive "$REFEREE_PID"; then
        echo "crash: referee running but match 2 did not settle (stray run: $stray_match2)"
    else
        echo "crash: referee EXITED: ${msg:-see stderr}"
        tail -n 4 "$RUN_DIR/referee.stderr" | sed 's/^/  referee: /'
    fi
    echo "FAIL (A8): match 2 (honest vs quitter 1) did not settle because the claimant of match 1 crashed"
    echo "  (stray run, same bracket: $stray_match2)"
    echo "  A8: \"Failing to process one match's data, for any reason, must not stop, delay or decide any other match.\""
    fail=1
fi

if [ "$fail" = 0 ]; then
    echo "PASS: the referee survives connection loss; match 2 settles and outputs stay acceptable"
fi
exit "$fail"
