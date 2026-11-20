#!/bin/bash
# Standalone rolling calculator fixture, independent of README extraction.
set -euo pipefail
: "${RECIPES_DIR:?}"
rm -f initial-hash
mkdir -p calc
cp "$RECIPES_DIR/calc.sh" calc/
chmod +x calc/calc.sh
tar --sort=name --mtime=2022-01-01 --owner=1000 --group=1000 --numeric-owner -cf calc.tar --directory=calc .
xgenext2fs -fzB 4096 -i 4096 -a calc.tar calc.ext2
# remove_stored removes only a stored machine's own files and refuses anything else.
if [ -e rolling-calculator-template ]; then
    lua5.4 -e 'require("cartesi").machine:remove_stored("rolling-calculator-template")'
fi
# --final-hash builds the hash tree before --store, so loading the template never rebuilds it.
cartesi-machine --no-init-splash --assert-rolling-template --final-hash \
    --flash-drive=label:calc,data_filename:calc.ext2,user:dapp \
    --store=rolling-calculator-template -- /mnt/calc/calc.sh > template.log 2>&1
initial_hash=$(lua5.4 -e 'local c = require("cartesi"); local m <close> = c.machine("rolling-calculator-template"); io.write(c.tohex(m:get_root_hash()))')
ln -sfn rolling-calculator-template "$initial_hash"
encode_input() {
    cartesi-rollup-data.lua --utf8-payload encode advance <<EOF
{"chain_id":0,"app_contract":"0x0000000000000000000000000000000000000000",
"msg_sender":"$(printf '0x%040d' "$1")","block_number":0,"block_timestamp":0,
"prev_randao":"0x0000000000000000000000000000000000000000000000000000000000000000",
"index":$1,"payload":"$2\n"}
EOF
}
encode_input 0 '6*2^1024 + 3*2^512' > input-0.bin
encode_input 1 'invalid input' > input-1.bin
encode_input 2 '2^2048' > input-2.bin
encode_input 2 '2+2048' > forged-input-2.bin
# The machine after input 0 receives input 2, because the calculator rejects input 1.
if [ -e rolling-calculator-after-input-0 ]; then
    lua5.4 -e 'require("cartesi").machine:remove_stored("rolling-calculator-after-input-0")'
fi
cartesi-machine --no-init-splash --load=rolling-calculator-template --revert-mode=none \
    --cmio-advance-state=input_file_index_begin:0,input_file_index_end:1 \
    --store=rolling-calculator-after-input-0 > after-input-0.log 2>&1
# Writes the moment right after the sd to htif.tohost that emits the notice of an input,
# as its mcycle offset and uarch cycle. The finders report on stderr.
find_notice() {
    local mcycle uarch_cycle
    mcycle=$(lua5.4 "$RECIPES_DIR/find-yield.lua" "$1" "$2" \
        HTIF_YIELD_CMD_AUTOMATIC HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT 2>&1 > /dev/null)
    uarch_cycle=$(lua5.4 "$RECIPES_DIR/find-uarch-tohost-sd.lua" "$1" "$2" "$mcycle" 2>&1 > /dev/null)
    printf '%s %s' "$mcycle" "$uarch_cycle"
}
find_notice rolling-calculator-template input-0.bin > input-0-notice
find_notice rolling-calculator-after-input-0 input-2.bin > input-2-notice
printf '%s' "$initial_hash" > initial-hash
