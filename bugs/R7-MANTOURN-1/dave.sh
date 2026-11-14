#!/bin/bash
# Runs SealLeafZeroProof.t.sol against the released Dave v3.0.0-alpha.7 prt/contracts build of the shared
# harness (bugs/harness/work/dave/released, with the regenerated step), in a throw-away copy so the shared
# build is never touched. Prints forge's per-test PASS/FAIL lines. Exit 2 on setup errors.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
D="${HARNESS_WORK:?source bugs/env.sh}/dave/released"
[ -f "$D/.built" ] && [ -d "$D/prt/contracts/out" ] && [ -d "$D/machine/step/src" ] || {
    echo "dave.sh: released Dave build missing (bugs/harness/chain/build-dave.sh released)" >&2
    exit 2
}
command -v forge > /dev/null || { echo "dave.sh: forge not on PATH" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/r7-mantourn-1.XXXXXX")" || exit 2
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/prt" "$T/machine"
# Same relative layout as the build (foundry.toml remaps step/ to ../../machine/step/); the copied cache
# keeps the compile incremental (only the new test and its imports are compiled, a few seconds).
cp -a "$D/prt/contracts" "$T/prt/" && cp -a "$D/machine/step" "$T/machine/" || exit 2
cp "$HERE/SealLeafZeroProof.t.sol" "$T/prt/contracts/test/fixtures/" || exit 2
cd "$T/prt/contracts" || exit 2
forge test --offline --match-contract SealLeafZeroProofAuditTest 2>&1
exit 0
