#!/bin/bash
# R5-INVSTORE-2: a stop of `cartesi-machine --revert-mode=stored` while a commit removes the old
# <directory>.revert leaves a partial <directory>.revert, and the documented recovery rule resumes from it.
# Exit 0: the documented rule recovers a committed state; 1: it does not (bug present); 2: setup error.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${REPO:?source bugs/env.sh (bugs/run.sh does)}"

TEMPLATE="$HARNESS_WORK/configs/baremetal-template"
[ -d "$TEMPLATE/machine" ] || { echo "setup: missing $TEMPLATE (bugs/harness/configs/make-configs.sh)" >&2; exit 2; }

WORK="$(mktemp -d "${TMPDIR:-/tmp}/r5-invstore-2.XXXXXX")" || exit 2
trap 'rm -rf "$WORK"' EXIT

gcc -shared -fPIC -O2 -o "$WORK/killshim.so" "$HERE/killshim.c" -ldl || { echo "setup: cannot build shim" >&2; exit 2; }

RUN="$WORK/run"
mkdir -p "$RUN" || exit 2
# two advance-state inputs for the bare-metal echo template (any payload longer than 3 bytes is accepted)
printf 'first input' >"$RUN/input-0.bin"
printf 'second input' >"$RUN/input-1.bin"

# The manual's command (doc/README.md "Rolling Cartesi Machines directly from storage"), on the bare-metal
# template. The CLI commits at creation, at the epoch's initial fixed point and after each accepted input; it
# writes input-0-outputs-merkle-root.bin when input 0 is accepted, right before that input's commit. The shim
# then counts removals of paths containing "machine.revert" (the backup, or a renamed-away copy of it such as
# machine.revert.old in a fixed version), ignoring machine.revert.tmp/ (the clone's own copy fallback unlinks
# files it just created there), and kills the CLI right before the 3rd one: today inside
# remove_stored(machine.revert) of the commit of input 0, after machine and machine.revert.tmp were synced.
echo "running cartesi-machine --revert-mode=stored over 2 inputs, SIGKILL at the 3rd backup removal after input 0"
(
    cd "$RUN" &&
        LD_PRELOAD="$WORK/killshim.so" KILL_MATCH="machine.revert" KILL_EXCLUDE="machine.revert.tmp/" \
            KILL_AFTER_FILE="input-0-outputs-merkle-root.bin" KILL_NTH=3 \
            $CARTESI_MACHINE \
            --revert-mode=stored \
            --load="machine,clone:$TEMPLATE/machine,sharing:all" \
            --cmio-advance-state=input_file_index_begin:0,input_file_index_end:2 \
            >"$WORK/cli.log" 2>&1
) 2>/dev/null # (the shell's own "Killed" notice)
status=$?
grep -E "killshim|Error|error|Storing input-0-outputs|Before input" "$WORK/cli.log" | head -8
if [ "$status" -ne 137 ]; then
    tail -20 "$WORK/cli.log" >&2
    echo "setup: cartesi-machine was not killed by the shim (exit $status); the test cannot place the stop" >&2
    exit 2
fi
if [ -d "$RUN/machine.revert" ]; then
    echo "machine.revert holds $(find "$RUN/machine.revert" -type f | wc -l) files," \
        "machine holds $(find "$RUN/machine" -type f | wc -l)"
fi

lua5.4 "$HERE/recover.lua" "$HARNESS_WORK/configs/baremetal-template" "$RUN" "$RUN/input-0.bin" "$RUN/input-1.bin"
exit $?
