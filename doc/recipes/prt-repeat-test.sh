#!/bin/bash
# Standalone tournament. Record once with test-prt-game, repeat with test-prt-repeat.
set -euo pipefail
: "${RECIPES_DIR:?}"
tmpl=${1:?missing machine template}
rolling_calc_encode=${2:?missing encoded inputs directory}
# The mcycle offset and uarch cycle of the sd that emits the notice of input 2
notice=$(cat "${3:?missing notice moment}")
notice_mcycle=${notice% *}
notice_ucycle=${notice#* }
prt_run=${4:?missing reference tournament directory}
mode=${5:-compare}
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
    # Removes only the exact names the tournament creates, so a leftover file makes rmdir fail.
    cd "$test_dir" || exit 1
    rm -f input-0.bin input-1.bin input-2.bin prt.lua prt-dishonest.lua prtu.lua claims tournament verdict \
        referee.stderr honest.stderr vandal.stderr tamperer.stderr no_rollback.stderr forger.stderr \
        vandal_1.stderr vandal_2.stderr phase_closer.stderr || exit 1
    if [ -n "${initial_state_hash:-}" ]; then
        rm -f "$initial_state_hash" || exit 1
    fi
    local i=1 j
    while [ -e "match_$i" ]; do
        j=1
        while [ -e "match_${i}_$j" ]; do
            rm -f "match_${i}_$j" || exit 1
            j=$((j + 1))
        done
        rm -f "match_$i" || exit 1
        i=$((i + 1))
    done
    cd / && rmdir "$test_dir" || exit 1
}
trap cleanup EXIT
cd "$test_dir"

# Repeat the documented tournament on another port and compare every narration file.
initial_state_hash=$(lua5.4 -e 'local cartesi = require("cartesi")
local machine <close> = cartesi.machine("'"$tmpl"'")
io.write(cartesi.tohex(machine:get_root_hash()))')
ln -sf "$tmpl" "$initial_state_hash"
ln -sf "$rolling_calc_encode/input-0.bin" "$rolling_calc_encode/input-1.bin" "$rolling_calc_encode/input-2.bin" .
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
# must fail the script; successful departures (vandals and the phase closer) are allowed.
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
listening() { netstat -ant 2>&1 | grep '\<8097\>' | grep -q LISTEN; }
players_in() { [ "$(($(netstat -nt 2>&1 | grep '\<8097\>' | grep -c ESTABLISHED) / 2))" -ge "$1" ]; }
proved_output() { grep -q 'Result proved against the final state:' verdict 2>/dev/null; }
start referee lua5.4 prt.lua referee 127.0.0.1:8097 "$initial_state_hash" input-0.bin input-1.bin input-2.bin
referee_pid=$!
await listening
start vandal lua5.4 prt-dishonest.lua vandal 127.0.0.1:8097 "$initial_state_hash"
await players_in 1
start tamperer lua5.4 prt-dishonest.lua tamperer 127.0.0.1:8097 "$initial_state_hash" 2 "$notice_mcycle" "$notice_ucycle" 42
await players_in 2
start no_rollback lua5.4 prt-dishonest.lua no-rollback 127.0.0.1:8097 "$initial_state_hash"
await players_in 3
start forger lua5.4 prt-dishonest.lua forger 127.0.0.1:8097 "$initial_state_hash" 2 "$forged"
await players_in 4
start vandal_1 lua5.4 prt-dishonest.lua vandal 127.0.0.1:8097 "$initial_state_hash" "vandal 1"
await players_in 5
start vandal_2 lua5.4 prt-dishonest.lua vandal 127.0.0.1:8097 "$initial_state_hash" "vandal 2"
await players_in 6
start honest lua5.4 prt.lua honest 127.0.0.1:8097 "$initial_state_hash"
await players_in 7
subscriptions_closed=yes
start phase_closer lua5.4 prt.lua phase_closer 127.0.0.1:8097
await proved_output
lua5.4 prt.lua phase_closer 127.0.0.1:8097 stop > /dev/null 2>> phase_closer.stderr
for pid in "${children[@]}"; do wait "$pid"; done
cat referee.stderr honest.stderr vandal.stderr tamperer.stderr no_rollback.stderr forger.stderr vandal_1.stderr vandal_2.stderr phase_closer.stderr >&2
grep -q "claims a timeout win" match_1
[ "$(wc -l < claims)" -eq 7 ]
[ "$(grep -c 'An elimination response from .* removes both inactive claims' match_3)" -eq 1 ]
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
