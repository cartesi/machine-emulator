#!/bin/bash
# Run the proof-of-concept test of one candidate:  bugs/run.sh <ID> [extra args passed to the test]
#
# Runs bugs/<ID>/test.lua (with lua5.4 and the environment of bugs/env.sh) or bugs/<ID>/test.sh (with bash,
# same environment), from inside bugs/<ID>/, and exits with the test's status:
#   0  the bug is fixed (the behavior the threat model requires holds)
#   1  the bug is present
#   2  harness error (missing test, emulator not built, a missing artifact, a crash of the
#      interpreter before the test decided, a timeout, or any status other than 0 and 1)
# Tests must exit 1 only after they have observed the buggy behavior, and should exit 2 themselves on setup
# failures (Lua: os.exit(2); bash: exit 2). Uncaught Lua errors make lua5.4 exit 1, so the runner can't tell
# them apart: tests should wrap their setup in pcall and exit 2 on error (see bugs/harness/lib/harness.lua,
# harness.main()).
#
# Environment: RUN_TIMEOUT (seconds, default 3600) bounds the test; on expiry the status is 2.
set -uo pipefail

ID="${1:-}"
if [ -z "$ID" ]; then
    echo "usage: bugs/run.sh <ID> [args...]" >&2
    exit 2
fi
shift

BUGS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIR="$BUGS_DIR/$ID"
if [ ! -d "$DIR" ]; then
    echo "run.sh: no directory $DIR" >&2
    exit 2
fi

# shellcheck source=bugs/env.sh
. "$BUGS_DIR/env.sh" || {
    echo "run.sh: cannot source env.sh" >&2
    exit 2
}

if [ ! -f "$REPO/src/cartesi.so" ] || [ ! -x "$REPO/src/cartesi-jsonrpc-machine" ]; then
    echo "run.sh: the emulator is not built in-tree (run 'make' at the repository root or bugs/harness/setup.sh)" >&2
    exit 2
fi
if [ "${HARNESS_SANITIZE:-0}" = 1 ] && [ ! -f "$HARNESS_WORK/sanitizer/src/cartesi.so" ]; then
    echo "run.sh: HARNESS_SANITIZE=1 but the sanitizer build is missing (bugs/harness/sanitizer/build.sh)" >&2
    exit 2
fi

if [ -f "$DIR/test.lua" ]; then
    cmd=(lua5.4 "$DIR/test.lua" "$@")
    # the sanitizer build needs libasan loaded first in the (uninstrumented) interpreter
    [ "${HARNESS_SANITIZE:-0}" = 1 ] && cmd=(env LD_PRELOAD="$SANITIZER_PRELOAD" "${cmd[@]}")
elif [ -f "$DIR/test.sh" ]; then
    cmd=(bash "$DIR/test.sh" "$@")
else
    echo "run.sh: neither $DIR/test.lua nor $DIR/test.sh exists" >&2
    exit 2
fi

cd "$DIR" || exit 2
timeout --kill-after=30 "${RUN_TIMEOUT:-3600}" "${cmd[@]}"
status=$?
case "$status" in
0)
    echo "run.sh: $ID: exit 0 (fixed / not reproduced)" >&2
    exit 0
    ;;
1)
    echo "run.sh: $ID: exit 1 (bug present)" >&2
    exit 1
    ;;
124 | 137)
    echo "run.sh: $ID: timeout after ${RUN_TIMEOUT:-3600}s, harness error" >&2
    exit 2
    ;;
*)
    echo "run.sh: $ID: exit $status, mapped to 2 (harness error)" >&2
    exit 2
    ;;
esac
