#!/bin/bash
# Local-chain harness. Mining policy belongs here, outside the bridge and players.
# With PRT_RPC_URL, it uses that chain. Otherwise it starts Anvil itself. The chain mode only runs
# Anvil, listening on every interface, for a harness outside its container.
set -euo pipefail
umask 022
# Anvil keeps only the newest states, since a full history of every block outgrows memory long before
# a demo ends. Blocks and logs stay available for the whole chain.
run_anvil() {
    anvil --host "$1" --port 8545 --accounts 10 --balance 10000 --hardfork prague --timestamp 1780000000 \
        --prune-history 256 "${@:2}"
}
if [[ ${1:-story} == chain ]]; then
    run_anvil 0.0.0.0
    exit
fi
: "${RECIPES_DIR:=/work/recipes}"
: "${PRT_DAVE_DIR:=/opt/dave}"
export RECIPES_DIR PRT_DAVE_DIR
# Lua prefers LUA_PATH_5_4, so the recipes join whichever of the two is set.
if [[ -n ${LUA_PATH_5_4:-} ]]; then
    export LUA_PATH_5_4="$RECIPES_DIR/?.lua;$LUA_PATH_5_4"
else
    export LUA_PATH="$RECIPES_DIR/?.lua;${LUA_PATH:-;}"
fi
lua5.4 "$RECIPES_DIR/prt-bridge-test.lua"
fixture="$RECIPES_DIR/cache/game-tests"
"${MAKE:-make}" -C "$(dirname "$RECIPES_DIR")" RECIPE_TEST_ENV=yes prt-demo-fixture
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
if [[ -z ${PRT_RPC_URL:-} ]]; then
    export PRT_RPC_URL=http://127.0.0.1:8545
    run_anvil 127.0.0.1 --silent > anvil.log 2>&1 &
    anvil_pid=$!
    cleanup() { kill "$anvil_pid" 2>/dev/null || true; wait "$anvil_pid" 2>/dev/null || true; }
    trap cleanup EXIT
fi
for _ in {1..100}; do
    if cast block-number --rpc-url "$PRT_RPC_URL" > /dev/null 2>&1; then break; fi
    [[ -z ${anvil_pid:-} ]] || kill -0 "$anvil_pid"
    sleep 0.1
done
cast block-number --rpc-url "$PRT_RPC_URL" > /dev/null
if [[ ${1:-story} == transactions ]]; then
    lua5.4 "$RECIPES_DIR/prt-transactions-test.lua"
elif [[ ${1:-story} == proofs ]]; then
    lua5.4 "$RECIPES_DIR/prt-proof-test.lua" "$initial_hash"
else
    lua5.4 "$RECIPES_DIR/prt-demo.lua" "$initial_hash" "${1:-story}"
fi
