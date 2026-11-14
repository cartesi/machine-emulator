#!/bin/bash
# R5-INVSTORE-1: sync_stored reports success after an earlier sync of the same directory failed (writeback error,
# the kernel marked the pages clean); after a remount the directory, which then meets O2's definition, reloads with a
# root hash different from the machine's.
#
# Required (THREAT_MODEL section 4, O2, R9; cm.h cm_sync_stored "On success, all previous changes to the stored
# machine files are durable on disk"): after the first sync_stored fails on a full disk and the space is freed,
# either the second sync_stored (or the later load) fails, or the reloaded directory has the root hash of the
# machine that was destroyed before the sync.  exit 0 = holds, 1 = violated, 2 = setup error.
#
# Needs root, tmpfs, a free loop device and mkfs.xfs (reflink=1; the manual requires a filesystem with reflinks for stored
# machines). Everything lives in a temporary directory that is removed at exit.
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${HARNESS_CONFIGS:?run through bugs/run.sh}"
SRC="$HARNESS_CONFIGS/baremetal-template/machine"
[ -d "$SRC" ] || { echo "setup: missing $SRC" >&2; exit 2; }
[ "$(id -u)" = 0 ] || { echo "setup: needs root (tmpfs + loop mount)" >&2; exit 2; }
for t in mkfs.xfs losetup fstrim mount umount; do
    command -v "$t" >/dev/null || { echo "setup: missing $t" >&2; exit 2; }
done

T="$(mktemp -d /tmp/r5-invstore-1.XXXXXX)" || exit 2
LOOP=""
cleanup() {
    umount "$T/mnt" 2>/dev/null
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    umount "$T/tmpfs" 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT
mkdir -p "$T/tmpfs" "$T/mnt"
HASH="$T/expected-root"
DIR="$T/mnt/machine"
phase() { lua5.4 "$HERE/phase.lua" "$@"; }

# A 320 MiB XFS filesystem on a loop device backed by a fully allocated file in a 330 MiB tmpfs
mount -t tmpfs -o size=330m tmpfs "$T/tmpfs" || exit 2
dd if=/dev/zero of="$T/tmpfs/disk.img" bs=1M count=320 status=none || exit 2
mkfs.xfs -q -f -K -m reflink=1 "$T/tmpfs/disk.img" || exit 2
LOOP=$(losetup --find --show "$T/tmpfs/disk.img") || exit 2
mount "$LOOP" "$T/mnt" || exit 2

# The operator's own stored directory, cloned and synced (guaranteed by O2)
phase clone "$SRC" "$DIR" || { echo "setup: clone failed" >&2; exit 2; }
# Control in the same run: a second clone changed the same way and synced while space is available
phase clone "$SRC" "$T/mnt/control" || { echo "setup: clone failed" >&2; exit 2; }
echo "control:"
phase dirty "$T/mnt/control" "$T/control-root" "sync_stored (space available):" || { echo "setup: control sync failed" >&2; exit 2; }
sync
echo "test:"
# Free blocks of the filesystem become holes in the backing file, and the tmpfs is filled: the storage under the
# filesystem is full (as a full thin-provisioned disk), so writeback of newly allocated blocks fails.
fstrim "$T/mnt" || { echo "setup: fstrim failed" >&2; exit 2; }
dd if=/dev/zero of="$T/tmpfs/filler" bs=64k status=none 2>/dev/null

# Load with sharing, change 2048 pages, record the root, destroy, sync_stored: must fail (host fault).
# The same process then frees space and syncs the same directory again (no stop in between).
phase dirty "$DIR" "$HASH" "first sync_stored (storage full):" "$T/tmpfs/filler"
st=$?
case $st in
0) ;;
3) echo "PASS: the second sync_stored does not claim durability after the earlier failure"; exit 0 ;;
4) echo "setup: the first sync_stored did not fail; the host fault was not produced" >&2; exit 2 ;;
*) exit 2 ;;
esac

# The directory now meets O2's definition (machine destroyed without a crash, synced after the last change).
# Drop the page cache of the filesystem (reboot analog) and reload it.
umount "$T/mnt" || exit 2
mount "$LOOP" "$T/mnt" || { echo "setup: cannot mount the filesystem again" >&2; exit 2; }
echo "control (synced without a fault):"
phase check "$T/mnt/control" "$T/control-root" || {
    echo "setup: the control directory does not reload with its root hash; the setup itself is wrong" >&2
    exit 2
}
echo "test (sync failed, then succeeded):"
phase check "$DIR" "$HASH"
st=$?
case $st in
0) echo "PASS: the reloaded directory has the root hash of the destroyed machine"; exit 0 ;;
1) echo "FAIL: sync_stored reported success, the directory meets O2, and it reloads as a different state (R9, section 4)"
   exit 1 ;;
4) echo "PASS: the directory is refused loudly on reload (the control directory loads)"; exit 0 ;;
*) echo "check: harness error (status $st)" >&2; exit 2 ;;
esac
