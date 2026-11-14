#!/bin/bash
# bugs/R3-VARDIRTY-1: a host allocation failure inside hash_tree::update, after the new page hashes were stored,
# leaves their ancestors stale for good. Builds the fault injector (fail-new.cpp) into a temp dir and runs
# check.lua under LD_PRELOAD.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/r3-vardirty-1.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT

g++ -O2 -shared -fPIC -o "$TMP/fail-new.so" "$HERE/fail-new.cpp" || {
    echo "HARNESS ERROR: cannot build fail-new.so" >&2
    exit 2
}

# With concurrency.update_hash_tree = 1 (check.lua), update_dense_trees reserves a batch of
# min(1 << 10, 16384) = 1024 entries of 16 bytes: 16384 bytes, the only request of that size in the update.
FAIL_NEW_EXACT=16384 FAIL_NEW_ARM_FILE="$TMP/arm" FAIL_NEW_COUNT_FILE="$TMP/injected" \
    LD_PRELOAD="$TMP/fail-new.so" lua5.4 "$HERE/check.lua" "$TMP"
status=$?
case $status in
0 | 1) exit $status ;;
*) exit 2 ;;
esac
