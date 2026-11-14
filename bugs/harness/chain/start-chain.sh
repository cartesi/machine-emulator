#!/bin/bash
# Start a local chain (anvil) with the parameters of doc/recipes/prt-demo.sh (run_anvil): 10 accounts of 10000 ETH
# from the test mnemonic, prague, timestamp 1780000000, --prune-history 256. Port CHAIN_PORT (default 8547, so it never clashes with the anvil that doc/recipes/prt-demo.sh starts on 8545).
# Writes work/chain/{anvil.pid,anvil.log,rpc-url}. Idempotent. stop-chain.sh stops it.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
export DIE_STATUS=2
C="$WORK/chain"
mkdir -p "$C"
PORT=${CHAIN_PORT:-8547}
RPC=http://127.0.0.1:$PORT
"$HARNESS/solidity-step/install-tools.sh" > /dev/null
if cast block-number --rpc-url "$RPC" > /dev/null 2>&1; then
    log "chain already up at $RPC"
else
    nohup anvil --host 127.0.0.1 --port "$PORT" --accounts 10 --balance 10000 --hardfork prague \
        --timestamp 1780000000 --prune-history 256 > "$C/anvil.log" 2>&1 &
    echo $! > "$C/anvil.pid"
    for _ in $(seq 1 100); do cast block-number --rpc-url "$RPC" > /dev/null 2>&1 && break; sleep 0.1; done
    cast block-number --rpc-url "$RPC" > /dev/null || die "anvil did not start (log: $C/anvil.log)"
    log "chain up at $RPC"
fi
echo "$RPC" > "$C/rpc-url"
