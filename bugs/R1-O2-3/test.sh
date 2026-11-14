#!/bin/bash
# bugs/R1-O2-3: a host allocation failure inside collect_mcycle_root_hashes leaves the hash tree stale.
# Builds the fault injector (fail-new.cpp) into a temp dir and runs check.lua under LD_PRELOAD.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/r1-o2-3.XXXXXX")" || exit 2
trap 'rm -rf "$TMP"' EXIT

g++ -O2 -shared -fPIC -o "$TMP/fail-new.so" "$HERE/fail-new.cpp" || {
    echo "HARNESS ERROR: cannot build fail-new.so" >&2
    exit 2
}

export LUA_PATH_5_4="$HERE/?.lua;${LUA_PATH_5_4:-;}"
FAIL_NEW_MIN_SIZE=100000 FAIL_NEW_ARM_FILE="$TMP/arm" FAIL_NEW_COUNT_FILE="$TMP/injected" \
    LD_PRELOAD="$TMP/fail-new.so" lua5.4 "$HERE/check.lua" "$TMP"
status=$?
case $status in
0 | 1) exit $status ;;
*) exit 2 ;;
esac
