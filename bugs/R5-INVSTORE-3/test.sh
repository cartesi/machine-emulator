#!/bin/bash
# bugs/R5-INVSTORE-3: `cartesi-machine --store=<dir>` never syncs the directory it writes, so the template that the
# manual builds with --store is never "synced after the last change to its contents" (THREAT_MODEL O2).
#
# Part A (deterministic, decides the verdict): trace the documented template command and require that, before it
# exits successfully, every stored file, the directory and its parent are fsync()ed (what machine:sync_stored and
# the CLI's own `--load=...,sync` key do). Positive control: the same parser on a trace of `--load=...,sync`.
# Part B (power-loss simulation, needs root and loop devices): run the command on an ext4 loop filesystem whose
# backing file is on tmpfs, copy the backing file right after the command exits (what a power loss leaves), mount
# the copy, and require that the directory loads with the hash --final-hash printed. Control: a second directory
# written the same way and then synced with machine:sync_stored (the documented API) survives the same copy.
#
# Exit 0: the stored template is durable when --store returns. Exit 1: it is not. Exit 2: harness/setup error.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${CARTESI_MACHINE:?source bugs/env.sh}" "${HARNESS_WORK:?source bugs/env.sh}"
GUEST="$HARNESS_WORK/baremetal/accept.bin"
[ -f "$GUEST" ] || { echo "HARNESS ERROR: missing $GUEST (bugs/harness/baremetal/build.sh)" >&2; exit 2; }
command -v strace >/dev/null || { echo "HARNESS ERROR: strace not installed" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/r5-invstore-3.XXXXXX")" || exit 2
MOUNTS=()
LOOPS=()
cleanup() {
    local i
    # loop filesystems first, then their loop devices, then the tmpfs that holds the backing files
    for ((i = ${#MOUNTS[@]} - 1; i >= 1; i--)); do umount "${MOUNTS[$i]}" 2>/dev/null; done
    for l in "${LOOPS[@]}"; do losetup -d "$l" 2>/dev/null; done
    if [ ${#MOUNTS[@]} -gt 0 ]; then
        for _ in 1 2 3 4 5; do umount "${MOUNTS[0]}" 2>/dev/null && break; sleep 1; done
    fi
    mountpoint -q "$TMP/tm" 2>/dev/null || rm -rf "${TMP:?}"
}
trap cleanup EXIT

# The template command of the manual (Persistent Cartesi Machines): run, print the final hash, store
store_cmd() { # <dir>
    $CARTESI_MACHINE --ram-image="$GUEST" --ram-length=64Mi --no-root-flash-drive --max-mcycle=0 \
        --final-hash --store="$1"
}

echo "== Part A: syscalls of 'cartesi-machine ... --final-hash --store=<dir>'"
mkdir -p "$TMP/a" || exit 2
strace -f -y -qq -o "$TMP/store.trace" -e trace=openat,open,creat,fsync,fdatasync,syncfs,sync \
    $CARTESI_MACHINE --ram-image="$GUEST" --ram-length=64Mi --no-root-flash-drive --max-mcycle=0 \
    --final-hash --store="$TMP/a/tmpl" >"$TMP/a.out" 2>&1 || { cat "$TMP/a.out"; echo "HARNESS ERROR: --store failed" >&2; exit 2; }
echo "  control: syscalls of 'cartesi-machine --load=<dir>,clone:<tmpl>,sharing:all,sync' (the CLI's sync key)"
strace -f -y -qq -o "$TMP/ctl.trace" -e trace=openat,open,creat,fsync,fdatasync,syncfs,sync \
    $CARTESI_MACHINE --load="$TMP/a/ctl,clone:$TMP/a/tmpl,sharing:all,sync" --revert-mode=none --max-mcycle=0 \
    >"$TMP/ctl.out" 2>&1 || { cat "$TMP/ctl.out"; echo "HARNESS ERROR: --load ...,sync failed" >&2; exit 2; }
lua5.4 "$HERE/check-trace.lua" "$TMP/ctl.trace" "$TMP/a/ctl"
case $? in
0) echo "  control OK: the parser sees the sync key make its directory durable" ;;
*) echo "HARNESS ERROR: control failed, the trace parser cannot recognize a synced directory" >&2; exit 2 ;;
esac
echo "  subject: --store"
lua5.4 "$HERE/check-trace.lua" "$TMP/store.trace" "$TMP/a/tmpl"
A=$?
[ $A -le 1 ] || exit 2
if [ $A -eq 0 ]; then echo "  Part A: OK, --store syncs what it writes"; else
    echo "  Part A: VIOLATION, --store exits with its directory never synced"; fi

echo "== Part B: power loss right after --store returns (ext4 loop filesystem on tmpfs)"
B=skip
if [ "$(id -u)" = 0 ] && command -v losetup >/dev/null && command -v mkfs.ext4 >/dev/null &&
    mkdir -p "$TMP/tm" "$TMP/mnt" "$TMP/snap" && mount -t tmpfs -o size=600m tmpfs "$TMP/tm" 2>/dev/null; then
    MOUNTS+=("$TMP/tm")
    if truncate -s 256M "$TMP/tm/disk.img" && mkfs.ext4 -q -F "$TMP/tm/disk.img" &&
        L=$(losetup -f --show "$TMP/tm/disk.img") && LOOPS+=("$L") && mount "$L" "$TMP/mnt"; then
        MOUNTS+=("$TMP/mnt")
        mkdir "$TMP/mnt/ops" && sync -f "$TMP/mnt" || exit 2
        # subject: the template command of the manual
        H=$(store_cmd "$TMP/mnt/ops/tmpl" 2>&1 | sed -n 's/^[0-9]*: \(0x[0-9a-f]*\)$/\1/p' | tail -1)
        # control: the same command followed by machine:sync_stored, the documented way to make it durable
        HC=$(store_cmd "$TMP/mnt/ops/ctl" 2>&1 | sed -n 's/^[0-9]*: \(0x[0-9a-f]*\)$/\1/p' | tail -1)
        D="$TMP/mnt/ops/ctl" lua5.4 -e 'require("cartesi").machine:sync_stored(assert(os.getenv("D")))' || exit 2
        # what a power loss now leaves on the disk
        cp --sparse=always "$TMP/tm/disk.img" "$TMP/tm/snap.img" || exit 2
        L2=$(losetup -f --show "$TMP/tm/snap.img") && LOOPS+=("$L2") && mount "$L2" "$TMP/snap" || exit 2
        MOUNTS+=("$TMP/snap")
        [ -n "$H" ] && [ -n "$HC" ] || { echo "HARNESS ERROR: no --final-hash output" >&2; exit 2; }
        echo "  control (stored, then machine:sync_stored), expected $HC:"
        lua5.4 "$HERE/reload.lua" "$TMP/snap/ops/ctl" "$HC" ||
            { echo "HARNESS ERROR: the synced control did not survive the simulated power loss" >&2; exit 2; }
        echo "  subject (stored with --store only), expected $H:"
        if [ -d "$TMP/snap/ops/tmpl" ]; then
            echo "    directory present after the power loss: $(ls -A "$TMP/snap/ops/tmpl" | wc -l) files," \
                "$(du -sk "$TMP/snap/ops/tmpl" | cut -f1) KiB on disk (before: $(du -sk "$TMP/mnt/ops/tmpl" | cut -f1) KiB)"
        else
            echo "    directory absent after the power loss"
        fi
        if lua5.4 "$HERE/reload.lua" "$TMP/snap/ops/tmpl" "$H"; then B=0; else B=1; fi
    else
        echo "  SKIP: cannot create the loop filesystem"
    fi
else
    echo "  SKIP: needs root, tmpfs, losetup and mkfs.ext4"
fi
case $B in
0) echo "  Part B: OK, the --store directory survived the simulated power loss" ;;
1) echo "  Part B: VIOLATION, the template that --store reported as stored is lost by a power loss" ;;
esac

if [ $A -eq 1 ] || [ "$B" = 1 ]; then
    echo "BUG: 'cartesi-machine --store' returns before its directory is durable, so the template it makes is never"
    echo "     a directory that O2 guarantees ('synced after the last change to its contents'); THREAT_MODEL section 5:"
    echo "     'The tools and reference implementations that ship with it must follow them'."
    exit 1
fi
echo "OK: --store leaves a durable (O2-guaranteed) directory"
exit 0
