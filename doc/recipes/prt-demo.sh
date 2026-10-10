#!/bin/bash
# Local-chain harness. Mining policy belongs here, outside the bridge and players.
set -euo pipefail
umask 022
: "${RECIPES_DIR:=/work/recipes}"
export RECIPES_DIR
export LUA_PATH="$RECIPES_DIR/?.lua;;"
lua5.4 "$RECIPES_DIR/prt-bridge-test.lua"
fixture="$RECIPES_DIR/cache/game-tests"
make -C "$(dirname "$RECIPES_DIR")" RECIPE_TEST_ENV=yes prt-demo-fixture
output_dir=${PRT_OUTPUT_DIR:-$RECIPES_DIR/cache/prt-chain}
mkdir -p "$output_dir"
run_dir=$(mktemp -d "$output_dir/run.XXXXXX")
cd "$run_dir"
echo "PRT chain artifacts: $run_dir"
initial_hash=$(cat "$fixture/initial-hash")
ln -s "$fixture/rolling-calculator-template" "$initial_hash"
cp "$fixture/forged-input-2.bin" .
mkdir wallets
chmod 700 wallets
umask 077
printf '%s\n' 'test test test test test test test test test test test junk' > wallets/mnemonic
printf '%s\n' 'local-prt-demo' > wallets/password
export CAST_UNSAFE_PASSWORD=local-prt-demo
for index in {0..9}; do
    cast wallet import "player-$index" --keystore-dir wallets --mnemonic wallets/mnemonic \
        --mnemonic-index "$index" > /dev/null
done
unset CAST_UNSAFE_PASSWORD
umask 022
anvil --host 127.0.0.1 --port 8545 --accounts 10 --balance 10000 \
    --hardfork prague --timestamp 1780000000 --silent > anvil.log 2>&1 &
anvil_pid=$!
cleanup() { kill "$anvil_pid" 2>/dev/null || true; wait "$anvil_pid" 2>/dev/null || true; }
trap cleanup EXIT
for _ in {1..100}; do
    if cast block-number --rpc-url http://127.0.0.1:8545 > /dev/null 2>&1; then break; fi
    kill -0 "$anvil_pid"
    sleep 0.1
done
cast block-number --rpc-url http://127.0.0.1:8545 > /dev/null
if [[ ${1:-story} == transactions ]]; then
    lua5.4 "$RECIPES_DIR/prt-transactions-test.lua"
else
    lua5.4 "$RECIPES_DIR/prt-demo.lua" "$initial_hash" "${1:-story}"
fi
