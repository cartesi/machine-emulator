#!/bin/bash
# Start a dedicated anvil for the step EVM harness (port EVM_STEP_PORT, default 8546) and deploy StepVerifier
# (src/StepVerifier.sol over the regenerated step, work/solidity-step/step). Writes work/evm/{rpc-url,address,
# anvil.pid,anvil.log}. Idempotent: an anvil that already answers with the deployed code is reused.
# anvil runs with --code-size-limit and a large gas limit because StepVerifier inlines all step libraries
# (HARNESS SETTING, not a property of any deployment).
set -euo pipefail
. "$(dirname "$0")/../../lib/common.sh"
. "$REPO/bugs/env.sh"
export DIE_STATUS=2
E="$WORK/evm"
mkdir -p "$E"
PORT=${EVM_STEP_PORT:-8546}
RPC=http://127.0.0.1:$PORT
"$HARNESS/solidity-step/install-tools.sh" > /dev/null
[ -d "$WORK/solidity-step/step/src" ] || die "no regenerated step (run solidity-step/regenerate.sh)"

if [ -f "$E/address" ] && cast code --rpc-url "$RPC" "$(cat "$E/address")" 2> /dev/null | grep -q '^0x[0-9a-f]\{10\}'; then
    log "StepVerifier already deployed at $(cat "$E/address") on $RPC"
    exit 0
fi
if ! cast block-number --rpc-url "$RPC" > /dev/null 2>&1; then
    nohup anvil --port "$PORT" --hardfork prague --code-size-limit 4000000 \
        --disable-block-gas-limit --silent > "$E/anvil.log" 2>&1 &
    echo $! > "$E/anvil.pid"
    for _ in $(seq 1 100); do cast block-number --rpc-url "$RPC" > /dev/null 2>&1 && break; sleep 0.1; done
fi
cast block-number --rpc-url "$RPC" > /dev/null || die "anvil did not start"
(cd "$HARNESS/solidity-step/evm" && forge build > "$E/build.log" 2>&1) || { tail "$E/build.log" >&2; die "forge build failed"; }
# anvil account 0 (well-known test key)
KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
addr=$(cd "$HARNESS/solidity-step/evm" && forge create --rpc-url "$RPC" --private-key "$KEY" --broadcast \
    src/StepVerifier.sol:StepVerifier 2>&1 | tee "$E/deploy.log" | awk '/Deployed to:/{print $3}')
[ -n "$addr" ] || { cat "$E/deploy.log" >&2; die "deploy failed"; }
echo "$RPC" > "$E/rpc-url"
echo "$addr" > "$E/address"
log "StepVerifier deployed at $addr on $RPC"
