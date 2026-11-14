#!/bin/bash
# R1-A5-1: a guardian foreclosure after a tournament settled stops the referee (Dave DaveConsensus +
# cartesi-rollups-contracts Application, released pinned build) from accepting the settled state's outputs.
# Runs check.lua against a private anvil (random port) in a temporary directory. See README.md.
# Exit 0: outputs accepted after foreclosure (A5 holds); 1: refused (defect); 2: setup error.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${HARNESS_WORK:?run through bugs/run.sh}"

export PRT_VARIANT=released
. "$HARNESS/chain/env.sh" || exit 2
[ -d "$PRT_DAVE_DIR/prt/contracts/out" ] && [ -d "$PRT_DAVE_DIR/cartesi-rollups/contracts/out" ] || {
    echo "SETUP: released Dave build missing ($PRT_DAVE_DIR; bugs/harness/chain/build-dave.sh released)" >&2
    exit 2
}
command -v anvil > /dev/null && command -v cast > /dev/null || { echo "SETUP: anvil/cast not in PATH" >&2; exit 2; }
[ -f "$HERE/guest.bin" ] || { echo "SETUP: guest.bin missing (./build-guest.sh)" >&2; exit 2; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/r1-a5-1.XXXXXX") || exit 2
ANVIL_PID=""
cleanup() {
    [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2> /dev/null && wait "$ANVIL_PID" 2> /dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

# private anvil on a free port (never 8545/8546/8547), with the parameters of bugs/harness/chain/start-chain.sh
RPC=""
for _ in $(seq 1 20); do
    PORT=$((20000 + RANDOM % 10000))
    cast block-number --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && continue
    anvil --host 127.0.0.1 --port "$PORT" --accounts 10 --balance 10000 --hardfork prague \
        --timestamp 1780000000 --prune-history 256 > "$TMP/anvil.log" 2>&1 &
    ANVIL_PID=$!
    for _ in $(seq 1 100); do
        cast block-number --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && break
        kill -0 "$ANVIL_PID" 2> /dev/null || break
        sleep 0.1
    done
    if cast block-number --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1; then
        RPC="http://127.0.0.1:$PORT"
        break
    fi
    kill "$ANVIL_PID" 2> /dev/null
    ANVIL_PID=""
done
[ -n "$RPC" ] || { echo "SETUP: could not start a private anvil" >&2; exit 2; }
export PRT_RPC_URL=$RPC

# recipe wallets (test mnemonic), as bugs/harness/chain/deploy.sh creates them
mkdir -p "$TMP/wallets" && chmod 700 "$TMP/wallets"
printf '%s\n' 'test test test test test test test test test test test junk' > "$TMP/wallets/mnemonic"
printf '%s\n' 'local-prt-demo' > "$TMP/wallets/password"
for index in 0 1 2; do
    CAST_UNSAFE_PASSWORD=local-prt-demo cast wallet import "player-$index" --keystore-dir "$TMP/wallets" \
        --mnemonic "$TMP/wallets/mnemonic" --mnemonic-index "$index" > /dev/null || exit 2
done

cd "$TMP" || exit 2
lua5.4 "$HERE/check.lua" "$HERE/guest.bin"
status=$?
case "$status" in
0 | 1 | 2) exit "$status" ;;
*) exit 2 ;;
esac
