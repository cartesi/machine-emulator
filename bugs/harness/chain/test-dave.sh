#!/bin/bash
# Run Dave's own contract test suites on one build (default: released constants), as its justfile defines them:
#   just prt-contracts::test-disputes   (forge test --no-match-contract ".*FfiTest")
#   just rollups-contracts::test        (forge test --no-match-contract ".*FfiTest")
# Logs and a summary in work/dave/test-<variant>-*.log / test-<variant>.txt. Exit 0 iff both pass.
# Extra arguments are passed to forge through FORGE_ARGS-free direct use: cd work/dave/<variant>/prt/contracts &&
# forge test --match-test ... works too (PATH from bugs/env.sh).
set -uo pipefail
. "$(dirname "$0")/../lib/common.sh"
. "$REPO/bugs/env.sh"
V=${1:-released}
W="$WORK/dave/$V"
[ -f "$W/.built" ] || DIE_STATUS=2 die "Dave $V not built (chain/build-dave.sh $V)"
status=0
: > "$WORK/dave/test-$V.txt"
for t in prt-contracts::test-disputes rollups-contracts::test; do
    (cd "$W" && ulimit -Sn 4096 2> /dev/null; just "$t") > "$WORK/dave/test-$V-${t%%::*}.log" 2>&1
    rc=$?
    echo "$t: exit $rc; $(grep -E 'Ran [0-9]+ test suites?' "$WORK/dave/test-$V-${t%%::*}.log" | tail -1)" |
        tee -a "$WORK/dave/test-$V.txt"
    [ $rc = 0 ] || status=1
done
grep -h -E '^\[FAIL' "$WORK/dave/test-$V"-*.log | sort -u > "$WORK/dave/test-$V-failures.txt" || true
exit $status
