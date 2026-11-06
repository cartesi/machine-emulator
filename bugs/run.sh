#!/bin/bash
# Runs one audit test: bugs/run.sh <ID>.
# Each test asserts the correct behavior, so it exits 0 when the bug is absent and nonzero while it is present.
# A test is bugs/<ID>/test.sh when present, else bugs/<ID>/test.lua. It runs from inside bugs/<ID>.
set -uo pipefail
id=${1:?usage: bugs/run.sh <ID>}
. "$(dirname "${BASH_SOURCE[0]}")/env.sh"
dir="$BUGS_DIR/$id"
[ -d "$dir" ] || { echo "no such test: $dir" >&2; exit 2; }
cd "$dir"
if [ -f test.sh ]; then
    bash ./test.sh
else
    lua5.4 ./test.lua
fi
status=$?
if [ $status -eq 0 ]; then echo "PASS $id (bug absent)"; else echo "FAIL $id (bug present, status $status)"; fi
exit $status
