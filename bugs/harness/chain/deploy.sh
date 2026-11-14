#!/bin/bash
# Deploy one Dave build on the chain of start-chain.sh, with doc/recipes/prt-deploy.lua (Tournament,
# CartesiStateTransition, CanonicalTournamentParametersProvider, MultiLevelTournamentFactory, InputBox,
# ApplicationFactory, DaveAppFactory, and a Dave application for the given template hash).
#   deploy.sh <patched|released> [template-hash]
# The template hash defaults to the doc/recipes rolling calculator fixture's (configs/valid-template-calc).
# Creates a run directory work/chain/deploy-<variant>/ with the recipe wallets (test mnemonic, as prt-demo.sh)
# and writes deployment.json there. Exit 0 on success.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
export DIE_STATUS=2
V=${1:?usage: deploy.sh <patched|released> [template-hash]}
export PRT_VARIANT=$V
. "$HARNESS/chain/env.sh"
[ -d "$PRT_DAVE_DIR/prt/contracts/out" ] || die "Dave $V not built (chain/build-dave.sh $V)"
HASH=${2:-$(cat "$WORK/configs/valid-template-calc/initial-hash" 2> /dev/null || true)}
[ -n "$HASH" ] || die "no template hash (run configs/make-configs.sh or pass one)"
"$HARNESS/chain/start-chain.sh"
export PRT_RPC_URL=$(cat "$WORK/chain/rpc-url")
D="$WORK/chain/deploy-$V"
rm -rf "$D"
mkdir -p "$D/wallets"
cd "$D"
chmod 700 wallets
printf '%s\n' 'test test test test test test test test test test test junk' > wallets/mnemonic
printf '%s\n' 'local-prt-demo' > wallets/password
export CAST_UNSAFE_PASSWORD=local-prt-demo
for index in 0 1 2; do
    cast wallet import "player-$index" --keystore-dir wallets --mnemonic wallets/mnemonic --mnemonic-index "$index" > /dev/null
done
unset CAST_UNSAFE_PASSWORD
lua5.4 "$HARNESS/chain/deploy.lua" "$HASH" > deployment.json
cat deployment.json
