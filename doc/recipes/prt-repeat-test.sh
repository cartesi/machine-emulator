#!/bin/bash
# Standalone tournament. Record once with test-prt-game, repeat with test-prt-repeat.
set -euo pipefail
: "${RECIPES_DIR:?}"
tmpl=${1:?missing machine template}
rolling_calc_encode=${2:?missing encoded inputs directory}
prt_run=${3:?missing reference tournament directory}
mode=${4:-compare}
forged="$prt_run/forged-input-2.bin"
test_dir=$(mktemp -d)
cleanup() {
    local status=$? pid log
    if [ "$status" -ne 0 ]; then
        for log in "$test_dir"/*.stderr; do
            [ ! -f "$log" ] || { echo "${log##*/}:" >&2; cat "$log" >&2; }
        done
    fi
    for pid in $(jobs -pr); do kill "$pid" 2>/dev/null || true; done
    wait || true
    rm -rf "$test_dir"
}
trap cleanup EXIT
cd "$test_dir"

# Repeat the documented tournament on another port and compare every narration file.
initial_state_hash=$(lua5.4 -e 'local cartesi = require("cartesi")
local machine <close> = cartesi.machine("'"$tmpl"'")
io.write(cartesi.tohex(machine:get_root_hash()))')
ln -sf "$tmpl" "$initial_state_hash"
ln -sf "$rolling_calc_encode"/input-[012].bin .
ln -sf "$RECIPES_DIR/prt.lua" "$RECIPES_DIR/prt-dishonest.lua" "$RECIPES_DIR/prtu.lua" .
children=()
subscriptions_closed=no
start() {
    local name=$1
    shift
    "$@" > /dev/null 2> "$name.stderr" &
    children+=("$!")
}
# These waits coordinate local processes, not logical block time. A crashed child
# must fail the script; successful departures (quitters and the phase closer) are allowed.
check_children() {
    local index pid
    for index in "${!children[@]}"; do
        pid=${children[$index]}
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            if [ "$subscriptions_closed" = no ]; then
                echo 'Child exited before initial subscriptions closed' >&2
                exit 1
            fi
            unset 'children[index]'
        fi
    done
    if ! kill -0 "$referee_pid" 2>/dev/null; then
        echo 'Referee exited before the tournament was stopped' >&2
        exit 1
    fi
}
await() {
    until "$@"; do
        check_children
        sleep 1
    done
    check_children
}
listening() { netstat -ntl 2>&1 | grep '\<8097\>' > /dev/null; }
players_in() { [ "$(($(netstat -nt 2>&1 | grep '\<8097\>' | grep -c ESTABLISHED) / 2))" -ge "$1" ]; }
proved_output() { grep -q 'Result proved against the final state:' verdict 2>/dev/null; }
start referee lua5.4 prt.lua referee 127.0.0.1:8097 "$initial_state_hash" input-0.bin input-1.bin input-2.bin
referee_pid=$!
await listening
start quitter lua5.4 prt-dishonest.lua quitter 127.0.0.1:8097 "$initial_state_hash"
await players_in 1
start tamperer lua5.4 prt-dishonest.lua tamperer 127.0.0.1:8097 "$initial_state_hash" 0 100
await players_in 2
start fabulist lua5.4 prt-dishonest.lua fabulist 127.0.0.1:8097 "$initial_state_hash" 2 2000
await players_in 3
start fixed_fabulist lua5.4 prt-dishonest.lua fabulist 127.0.0.1:8097 "$initial_state_hash" 2 60000 fixed_fabulist
await players_in 4
start forger lua5.4 prt-dishonest.lua forger 127.0.0.1:8097 "$initial_state_hash" 2 "$forged"
await players_in 5
start honest lua5.4 prt.lua honest 127.0.0.1:8097 "$initial_state_hash"
await players_in 6
start quitter_1 lua5.4 prt-dishonest.lua quitter 127.0.0.1:8097 "$initial_state_hash" "quitter 1"
await players_in 7
start quitter_2 lua5.4 prt-dishonest.lua quitter 127.0.0.1:8097 "$initial_state_hash" "quitter 2"
await players_in 8
subscriptions_closed=yes
start phase_closer lua5.4 prt.lua phase_closer 127.0.0.1:8097
await proved_output
lua5.4 prt.lua phase_closer 127.0.0.1:8097 stop > /dev/null 2>> phase_closer.stderr
for pid in "${children[@]}"; do wait "$pid"; done
cat referee.stderr honest.stderr quitter.stderr forger.stderr tamperer.stderr fabulist.stderr fixed_fabulist.stderr quitter_1.stderr quitter_2.stderr phase_closer.stderr >&2
grep -q "A uarch tournament opens over input 2, period 60000" match_[0-9]*
grep -q "claims a timeout win" match_1
[ "$(wc -l < claims)" -eq 8 ]
[ "$(grep -c 'An elimination response from .* removes both inactive claims' match_4)" -eq 1 ]
if [ "$mode" = record ]; then
    cp claims tournament verdict match_* "$prt_run/"
    echo "The standalone PRT tournament completed."
    exit 0
fi
for f in claims tournament verdict match_*; do
    case $f in *_elided) continue;; esac
    diff "$f" "$prt_run/$f"
done
echo "The second run narrated every file identically."
