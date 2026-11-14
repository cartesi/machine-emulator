#!/bin/bash
# Run the doc/recipes PRT demo end to end on the host against the PATCHED Dave build (work/dave/patched), the way
# `make -C doc test-prt-bridge` does it, except that anvil runs on the host instead of in the PRT image:
#   prt-demo.sh [smoke|story|transactions|proofs]   (default smoke: the honest player and a sentinel only)
# prt-demo.sh starts its own anvil (doc/recipes/prt-demo.sh run_anvil) unless PRT_RPC_URL is set. Extra
# environment of the recipe (PRT_INPUT_CONFIRMATIONS, PRT_DISPUTE_CONFIRMATIONS, PRT_TEST_RESTART, ...) passes
# through. Artifacts: work/prt-runs/run.XXXXXX (players/<label>/log.txt, deployment.json, checkpoints/).
# Exit status: the recipe's (0 = the demo settled as the recipe asserts).
set -uo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
export PRT_VARIANT=patched
. "$HARNESS/chain/env.sh"
[ -d "$PRT_DAVE_DIR/prt/contracts/out" ] || DIE_STATUS=2 die "Dave patched not built (chain/build-dave.sh patched)"
command -v xgenext2fs > /dev/null || "$HARNESS/emulator/build-xgenext2fs.sh" || exit 2
mkdir -p "$PRT_OUTPUT_DIR"
export LUA_PATH_5_4="$RECIPES_DIR/?.lua;$LUA_PATH_5_4"
# doc/recipes/prt-demo.sh starts anvil on 8545 and silently uses whatever already answers there
if [ -z "${PRT_RPC_URL:-}" ] && cast block-number --rpc-url http://127.0.0.1:8545 > /dev/null 2>&1; then
    DIE_STATUS=2 die "something already answers on 127.0.0.1:8545 (stale anvil?); stop it first"
fi
# reflink filesystem for the players' machine clones (see chain/reflink-fs.sh); without it runs need far more disk
[ "$PRT_OUTPUT_DIR" != "$WORK/prt-runs" ] || "$HARNESS/chain/reflink-fs.sh" || log "WARNING: no reflink filesystem at $PRT_OUTPUT_DIR (every machine clone is a full copy)"
# prt-demo.sh starts `run_anvil ... &` and, at exit, kills the background subshell, not anvil itself, so on the
# host its anvil outlives the demo; stop it here (only the recipe's own anvil command line matches).
stop_recipe_anvil() { pkill -f '^anvil --host 127.0.0.1 --port 8545 --accounts 10 --balance 10000 .* --silent$' 2> /dev/null || true; }
trap stop_recipe_anvil EXIT
bash "$RECIPES_DIR/prt-demo.sh" "${1:-smoke}"
