#!/bin/bash
# Mount a reflink-capable filesystem at bugs/harness/work/prt-runs (PRT_OUTPUT_DIR of the recipes).
# The PRT players clone stored machines for every epoch entry; doc/Makefile assumes a host filesystem with
# reflinks. On ext4 every clone is a full copy (~2.8 GB per player for the smoke demo, the story's 9 players do
# not fit in the container's disk). This creates a SPARSE file work/prt-fs.img (apparent size PRT_FS_SIZE,
# default 60G; only written blocks use disk), formats it XFS with reflink=1 and loop-mounts it.
# Idempotent; needs root and loop devices. Exit 0 if work/prt-runs is on a reflink filesystem afterwards.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
M="$WORK/prt-runs"
IMG="$WORK/prt-fs.img"
mkdir -p "$M"
if findmnt -no FSTYPE "$M" 2> /dev/null | grep -q xfs; then exit 0; fi
[ "$(id -u)" = 0 ] || die "needs root to loop-mount $IMG"
command -v mkfs.xfs > /dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends xfsprogs > /dev/null
if [ ! -f "$IMG" ]; then
    truncate -s "${PRT_FS_SIZE:-60G}" "$IMG"
    mkfs.xfs -q -m reflink=1 "$IMG"
fi
[ -z "$(ls -A "$M")" ] || die "$M is not empty; move its contents away before mounting"
mount -o loop "$IMG" "$M"
findmnt -no FSTYPE "$M" | grep -q xfs
log "reflink filesystem mounted at $M ($IMG)"
