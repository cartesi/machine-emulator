#!/bin/bash
# R7-MANCLIROLL-1: a host I/O error inside a commit of `cartesi-machine --revert-mode=stored` makes the CLI's own
# error-path revert delete the synced (O2-guaranteed) <directory>, and on a failed rename every copy of the
# committed state.
# Exit 0: a committed state survives the fault in both cases; 1: it does not (bug present); 2: setup error.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${REPO:?source bugs/env.sh (bugs/run.sh does)}"

TEMPLATE="$HARNESS_WORK/configs/baremetal-template"
[ -d "$TEMPLATE/machine" ] || { echo "setup: missing $TEMPLATE (bugs/harness/configs/make-configs.sh)" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/r7-manclroll-1.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

gcc -shared -fPIC -O2 -o "$WORK/ioshim.so" "$HERE/ioshim.c" -ldl || { echo "setup: cannot build shim" >&2; exit 2; }

# The manual's stored-mode command (doc/README.md "Rolling Cartesi Machines directly from storage") on the
# bare-metal echo template (emit-output guest: emits each input as an output and a report, then accepts).
# The CLI writes input-0-outputs-merkle-root.bin when input 0 is accepted, right before that input's commit, so
# FAIL_AFTER_FILE places the fault inside the commit of input 0, after `machine` and `machine.revert.tmp` were
# synced with the state after input 0.
run_cli() { # <run-dir> <log> [env assignments for the shim...]
    local dir="$1" log="$2"
    shift 2
    mkdir -p "$dir" || return 2
    printf 'first input' >"$dir/input-0.bin"
    printf 'second input' >"$dir/input-1.bin"
    (
        cd "$dir" &&
            env "$@" $CARTESI_MACHINE \
                --revert-mode=stored \
                --load="machine,clone:$TEMPLATE/machine,sharing:all" \
                --cmio-advance-state=input_file_index_begin:0,input_file_index_end:2 \
                >"$log" 2>&1
    )
}

# Control: without a fault the run completes and accepts both inputs.
echo "== control: no fault"
run_cli "$WORK/control" "$WORK/control.log"
status=$?
if [ "$status" -ne 0 ] || [ ! -f "$WORK/control/input-1-outputs-merkle-root.bin" ]; then
    tail -20 "$WORK/control.log" >&2
    echo "setup: the control run failed (exit $status)" >&2
    exit 2
fi
echo "  control run completed (exit 0), both inputs accepted"

result=0
run_case() { # <name> <description> [shim env...]
    local name="$1" desc="$2"
    shift 2
    echo "== case $name: $desc"
    run_cli "$WORK/$name" "$WORK/$name.log" LD_PRELOAD="$WORK/ioshim.so" \
        FAIL_AFTER_FILE="input-0-outputs-merkle-root.bin" "$@"
    local status=$?
    if ! grep -q "ioshim: failing" "$WORK/$name.log"; then
        tail -20 "$WORK/$name.log" >&2
        echo "setup: the shim did not inject the fault in case $name (exit $status)" >&2
        exit 2
    fi
    echo "  cartesi-machine exit status $status; its output:"
    grep -E "ioshim|rror|lua5.4:|Storing input-0-outputs|Before input" "$WORK/$name.log" | sed 's/^/    /' | head -8
    lua5.4 "$HERE/check.lua" "$TEMPLATE" "$WORK/$name" "$WORK/$name/input-0.bin" "$WORK/$name/input-1.bin"
    local c=$?
    case "$c" in
    0) echo "  case $name: OK" ;;
    1)
        echo "  case $name: BUG"
        result=1
        ;;
    *) exit 2 ;;
    esac
}

# Case A: renaming machine.revert.tmp to machine.revert fails with EIO (e.g. ENOSPC/EIO from the filesystem).
run_case rename "renameat2(machine.revert.tmp -> machine.revert) fails with EIO in the commit of input 0" \
    FAIL_FUNC=renameat2 FAIL_SUFFIX="machine.revert.tmp"

# Case B: removing the old machine.revert fails with EIO at its 2nd file (the 2nd unlink under machine.revert/
# once input 0 is accepted; on audit/prt2 that is inside the commit of input 0).
run_case unlink "the 2nd unlink() under machine.revert/ after input 0 is accepted fails with EIO" \
    FAIL_FUNC=unlink FAIL_MATCH="machine.revert/" FAIL_NTH=2

exit "$result"
