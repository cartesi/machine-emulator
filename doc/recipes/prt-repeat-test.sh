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
    local pid
    for pid in $(jobs -pr); do kill "$pid" 2>/dev/null || true; done
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
players_in() { [ "$(($(netstat -nt 2>&1 | grep '\<8097\>' | grep -c ESTABLISHED) / 2))" -ge "$1" ]; }
lua5.4 prt.lua referee 127.0.0.1:8097 "$initial_state_hash" input-0.bin input-1.bin input-2.bin > /dev/null 2> referee.stderr &
while ! netstat -ntl 2>&1 | grep '\<8097\>' > /dev/null; do sleep 1; done
lua5.4 prt-dishonest.lua quitter 127.0.0.1:8097 "$initial_state_hash" > /dev/null 2> quitter.stderr &
while ! players_in 1; do sleep 1; done
lua5.4 prt-dishonest.lua tamperer 127.0.0.1:8097 "$initial_state_hash" 0 100 > /dev/null 2> tamperer.stderr &
while ! players_in 2; do sleep 1; done
lua5.4 prt-dishonest.lua fabulist 127.0.0.1:8097 "$initial_state_hash" 2 2000 > /dev/null 2> fabulist.stderr &
while ! players_in 3; do sleep 1; done
lua5.4 prt-dishonest.lua fabulist 127.0.0.1:8097 "$initial_state_hash" 2 60000 fixed_fabulist > /dev/null 2> fixed_fabulist.stderr &
while ! players_in 4; do sleep 1; done
lua5.4 prt-dishonest.lua forger 127.0.0.1:8097 "$initial_state_hash" 2 "$forged" > /dev/null 2> forger.stderr &
while ! players_in 5; do sleep 1; done
lua5.4 prt.lua honest 127.0.0.1:8097 "$initial_state_hash" > /dev/null 2> honest.stderr &
while ! players_in 6; do sleep 1; done
lua5.4 prt-dishonest.lua quitter 127.0.0.1:8097 "$initial_state_hash" "quitter 1" > /dev/null 2> quitter_1.stderr &
while ! players_in 7; do sleep 1; done
lua5.4 prt-dishonest.lua quitter 127.0.0.1:8097 "$initial_state_hash" "quitter 2" > /dev/null 2> quitter_2.stderr &
while ! players_in 8; do sleep 1; done
lua5.4 prt.lua phase_closer 127.0.0.1:8097 > /dev/null 2> phase_closer.stderr &
while ! grep -q 'Result proved against the final state:' verdict 2>/dev/null; do sleep 1; done
lua5.4 prt.lua phase_closer 127.0.0.1:8097 stop > /dev/null 2>> phase_closer.stderr
wait
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
