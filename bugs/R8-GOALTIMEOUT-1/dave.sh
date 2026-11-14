#!/bin/bash
# Runs FinalityLagTimeout.t.sol against the released Dave v3.0.0-alpha.7 prt/contracts build of the shared
# harness (bugs/harness/work/dave/released), in a throw-away copy so the shared build is never touched. The test
# deploys the released contracts from the build's own compiled artifacts (vm.deployCode), so only the test file
# itself is compiled. Prints forge's output (-vv: console logs and per-test PASS/FAIL). Exit 2 on setup errors.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
D="${HARNESS_WORK:?source bugs/env.sh}/dave/released"
[ -f "$D/.built" ] && [ -d "$D/prt/contracts/out" ] && [ -d "$D/machine/step/src" ] || {
    echo "dave.sh: released Dave build missing (bugs/harness/chain/build-dave.sh released)" >&2
    exit 2
}
command -v forge > /dev/null || { echo "dave.sh: forge not on PATH" >&2; exit 2; }
T="$(mktemp -d "${TMPDIR:-/tmp}/r8-goaltimeout-1.XXXXXX")" || exit 2
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/prt" "$T/machine"
# Same relative layout as the build (foundry.toml remaps step/ to ../../machine/step/); the copied cache keeps
# the compile incremental.
cp -a "$D/prt/contracts" "$T/prt/" && cp -a "$D/machine/step" "$T/machine/" || exit 2
cp "$HERE/FinalityLagTimeout.t.sol" "$T/prt/contracts/test/fixtures/" || exit 2
cd "$T/prt/contracts" || exit 2
# The copy may read its own compiled artifacts (vm.deployCode of out/*.json).
sed -i 's|^fs_permissions = \[{ access = "read-write", path = "deployments" }\]$|fs_permissions = [{ access = "read-write", path = "deployments" }, { access = "read", path = "out" }]|' \
    foundry.toml || exit 2
grep -q 'path = "out"' foundry.toml || { echo "dave.sh: cannot grant read access to out/" >&2; exit 2; }
forge test --offline -vv --match-contract FinalityLagTimeoutAuditTest 2>&1
exit 0
