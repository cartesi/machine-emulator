#!/bin/bash
# R5-INVBRIDGE-1: runs check.lua against a private anvil (random port, never 8545/8546/8547). See README.md.
# Exit 0: a value-bearing job whose value exceeds the balance is reported as blocked (fixed).
# Exit 1: submit raises "transaction preflight RPC failure" instead (bug present). Exit 2: setup error.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
command -v anvil > /dev/null && command -v cast > /dev/null || { echo "SETUP: anvil/cast not in PATH" >&2; exit 2; }
TMP="$(mktemp -d)"
ANVIL_PID=""
cleanup() {
    [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2> /dev/null && wait "$ANVIL_PID" 2> /dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

RPC=""
for _ in $(seq 1 20); do
    PORT=$((20000 + RANDOM % 10000))
    case "$PORT" in 8545 | 8546 | 8547) continue ;; esac
    cast block-number --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && continue
    anvil --host 127.0.0.1 --port "$PORT" --accounts 1 --balance 10000 --hardfork prague \
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
    wait "$ANVIL_PID" 2> /dev/null
    ANVIL_PID=""
done
[ -n "$RPC" ] || { echo "SETUP: could not start a private anvil" >&2; exit 2; }

cd "$TMP" || exit 2
lua5.4 "$HERE/check.lua" "$RPC" "$TMP"
