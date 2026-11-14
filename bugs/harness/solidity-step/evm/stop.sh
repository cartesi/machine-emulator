#!/bin/bash
# Stop the step EVM harness anvil started by start.sh.
. "$(dirname "$0")/../../lib/common.sh"
[ -f "$WORK/evm/anvil.pid" ] && kill "$(cat "$WORK/evm/anvil.pid")" 2> /dev/null
rm -f "$WORK/evm/anvil.pid" "$WORK/evm/address"
exit 0
