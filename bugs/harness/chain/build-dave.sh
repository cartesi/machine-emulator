#!/bin/bash
# Build the pinned Dave contracts on the host, the way doc/Dockerfile.prt does (stage `contracts`), twice:
#   work/dave/patched   Dave v3.0.0-alpha.7 + doc/recipes/prt-contracts.patch (recipe geometry), for the PRT recipes
#   work/dave/released  Dave v3.0.0-alpha.7 as released (released constants), for tests of the contracts
# In both, machine/step/src is replaced by the src/ of the regenerated machine-solidity-step
# (work/solidity-step/step, see solidity-step/regenerate.sh), as Dockerfile.prt does with PRT_MACHINE_STEP_DIR.
# Dependencies come from soldeer (soldeer.lock: OpenZeppelin 5.5.0, forge-std 1.9.6, cartesi-rollups-contracts
# 3.0.0-alpha.10 with its own recursive deps), forge v1.5.1, solc 0.8.30.
# Usage: build-dave.sh [patched] [released] [--force]. Exit 0 when the requested builds succeed.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
export DIE_STATUS=2

FORCE=no
VARIANTS=()
for a in "$@"; do
    case "$a" in
    --force) FORCE=yes ;;
    patched | released) VARIANTS+=("$a") ;;
    *) die "unknown argument $a" ;;
    esac
done
[ ${#VARIANTS[@]} -gt 0 ] || VARIANTS=(patched released)

"$HARNESS/solidity-step/install-tools.sh" > /dev/null
STEP="$WORK/solidity-step/step"
[ -d "$STEP/src" ] || die "no regenerated step at $STEP (run solidity-step/regenerate.sh)"
D="$WORK/dave"
mkdir -p "$D"
clone_at_tag "$DAVE_REPO" "$DAVE_TAG" "$DAVE_COMMIT" "$D/src"
if [ ! -d "$D/src/machine/step/src" ]; then
    (cd "$D/src" && git submodule update --init machine/step > /dev/null 2>&1) || die "machine/step submodule"
fi

for v in "${VARIANTS[@]}"; do
    W="$D/$v"
    if [ "$FORCE" = no ] && [ -f "$W/.built" ] && [ "$(cat "$W/.built")" = "$(readlink -f "$STEP")" ]; then
        log "dave $v already built"
        continue
    fi
    rm -rf "$W"
    cp -a "$D/src" "$W"
    rm -rf "$W/machine/step/src"
    cp -R "$STEP/src" "$W/machine/step/src"
    (cd "$W" && just prt-contracts::install-deps && just rollups-contracts::install-deps) > "$D/$v-deps.log" 2>&1 ||
        die "dave $v: install-deps failed (log: $D/$v-deps.log)"
    if [ "$v" = patched ]; then
        (cd "$W" && git apply --check "$REPO/doc/recipes/prt-contracts.patch" &&
            git apply "$REPO/doc/recipes/prt-contracts.patch") || die "prt-contracts.patch does not apply"
    fi
    (cd "$W" && just build-smart-contracts) > "$D/$v-build.log" 2>&1 || {
        tail -20 "$D/$v-build.log" >&2
        die "dave $v: build failed (log: $D/$v-build.log)"
    }
    readlink -f "$STEP" > "$W/.built"
    log "dave $v built: $W/prt/contracts/out, $W/cartesi-rollups/contracts/out"
done
