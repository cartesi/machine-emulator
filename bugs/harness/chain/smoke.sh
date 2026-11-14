#!/bin/bash
# Smoke checks of the local chain with the pinned Dave contracts:
#   smoke.sh released   deploy the released-constant build, check its CartesiStateTransition against the emulator
#   smoke.sh patched    same for the recipe build, then the PRT demo in smoke mode (honest player + sentinel), which
#                       settles an epoch of the rolling calculator on the chain (prt-demo.lua's assertions)
#   smoke.sh patched-stf  only the deploy + STF check of the patched build
# Exit 0 on success.
set -uo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
V=${1:-released}
mkdir -p "$WORK/chain"
case "$V" in
released | patched | patched-stf)
    var=${V%-stf}
    "$HARNESS/chain/deploy.sh" "$var" > "$WORK/chain/deploy-$var.log" 2>&1 || { tail "$WORK/chain/deploy-$var.log"; exit 2; }
    lua5.4 "$HARNESS/chain/smoke-stf.lua" "$WORK/chain/deploy-$var/deployment.json" || exit 1
    ;;
*) DIE_STATUS=2 die "usage: smoke.sh released|patched|patched-stf" ;;
esac
if [ "$V" = patched ]; then
    "$HARNESS/chain/stop-chain.sh"
    "$HARNESS/chain/prt-demo.sh" smoke > "$WORK/chain/prt-demo-smoke.log" 2>&1
    rc=$?
    tail -5 "$WORK/chain/prt-demo-smoke.log"
    exit $rc
fi
