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
rm -rf rolling-calculator-template
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
printf '%s' "$initial_hash" > initial-hash
