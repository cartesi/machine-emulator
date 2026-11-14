#!/bin/bash
# Stop the anvil started by start-chain.sh.
. "$(dirname "$0")/../lib/common.sh"
[ -f "$WORK/chain/anvil.pid" ] && kill "$(cat "$WORK/chain/anvil.pid")" 2> /dev/null
rm -f "$WORK/chain/anvil.pid"
exit 0
