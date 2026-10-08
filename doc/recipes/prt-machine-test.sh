#!/bin/bash
set -euo pipefail
: "${RECIPES_DIR:?}"
fixtures=${1:?missing fixtures}
ln -sf "$fixtures"/input-[012].bin .
initial_hash=$(cat "$fixtures/initial-hash")
ln -sfn "$fixtures/rolling-calculator-template" "$initial_hash"
cartesi-machine --no-init-splash --remote-address=127.0.0.1:0 --remote-spawn --remote-shutdown \
    --load="$initial_hash" --cmio-advance-state=input_file_index_begin:0,input_file_index_end:3 \
    --mcycle-computation-hash=log2_mcycle_period:10,filename:mch.bin --final-hash > mcycle.log 2>&1
cartesi-machine --no-init-splash --remote-address=127.0.0.1:0 --remote-spawn --remote-shutdown \
    --load="$initial_hash" --cmio-advance-state=input_file_index_begin:0,input_file_index_end:3 \
    --uarch-cycle-computation-hash=log2_mcycle_period:10,mcycle_period_index:0,filename:uch.bin > uarch.log 2>&1
lua5.4 "$RECIPES_DIR/prt-test.lua" "$initial_hash" input-[012].bin mch.bin uch.bin
mkdir -p "$fixtures/prt-run"
cp "$fixtures/forged-input-2.bin" "$fixtures/prt-run/"
bash "$RECIPES_DIR/prt-repeat-test.sh" "$fixtures/rolling-calculator-template" "$fixtures" "$fixtures/prt-run" record
expected=$(lua5.4 -l cartesi -e 'io.write(cartesi.tohex(io.read("a")))' < mch.bin)
grep -q "Winner computation hash: $expected" "$fixtures/prt-run/verdict"
