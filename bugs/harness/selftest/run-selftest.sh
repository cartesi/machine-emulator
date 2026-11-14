#!/bin/bash
# Checks the bugs/run.sh exit-status convention with tiny tests. Exits 0 when all match.
set -u
H="$(cd "$(dirname "$0")/.." && pwd)"
BUGS="$(cd "$H/.." && pwd)"
fail=0
for pair in pass:0 fail:1 err:2 luaerr:2 sherr:2 nonexistent:2; do
    name=${pair%%:*} want=${pair##*:}
    "$BUGS/run.sh" "harness/selftest/$name" > /dev/null 2>&1
    got=$?
    if [ "$got" = "$want" ]; then echo "ok   $name -> $got"; else echo "FAIL $name -> $got (want $want)"; fail=1; fi
done
# sanitizer mode: the module must come from the ASan+UBSan build (skipped if not built)
if [ -f "$H/work/sanitizer/src/cartesi.so" ]; then
    for pair in 1:0 0:1; do
        san=${pair%%:*} want=${pair##*:}
        HARNESS_SANITIZE=$san "$BUGS/run.sh" harness/selftest/sanpath > /dev/null 2>&1
        got=$?
        if [ "$got" = "$want" ]; then echo "ok   sanpath HARNESS_SANITIZE=$san -> $got"; else echo "FAIL sanpath HARNESS_SANITIZE=$san -> $got (want $want)"; fail=1; fi
    done
fi
exit $fail
