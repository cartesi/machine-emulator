#!/bin/bash
# Fetch and checksum-verify the guest images pinned in dependencies.lock, into bugs/harness/work/images:
#   linux.bin                       cartesi/linux $LINUX_TAG kernel image   (LINUX_SHA256)
#   rootfs.ext2 (rootfs-tools.ext2) machine-guest-tools rootfs              (MACHINE_GUEST_TOOLS_ROOTFS_SHA256)
#   machine-guest-tools_riscv64.deb / .tar.gz                               (..._DEB_SHA256 / ..._TARBALL_SHA256)
# and make sure doc/recipes/rootfs-docs.ext2 (git lfs object used by doc/recipes) is present and matches
# the recipe inputs (`make -C doc check-rootfs-docs`). Idempotent: verified files are not fetched again.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"

IMG="$WORK/images"
DL="$WORK/downloads"
mkdir -p "$IMG" "$DL"

fetch() { # fetch <url> <sha256> <dest>
    local url=$1 sha=$2 dest=$3
    if [ -f "$dest" ] && verify_sha256 "$dest" "$sha" 2> /dev/null; then
        log "ok (cached) $(basename "$dest")"
        return 0
    fi
    log "fetching $url"
    curl -sSfL --retry 3 -o "$dest.part" "$url"
    verify_sha256 "$dest.part" "$sha" || {
        rm -f "$dest.part"
        return 1
    }
    mv "$dest.part" "$dest"
    log "ok $(basename "$dest") sha256=$sha"
}

LINUX_URL=$(lock_var LINUX_URL)
LINUX_SHA256=$(lock_var LINUX_SHA256)
ROOTFS_URL=$(lock_var MACHINE_GUEST_TOOLS_ROOTFS_URL)
ROOTFS_SHA256=$(lock_var MACHINE_GUEST_TOOLS_ROOTFS_SHA256)
MGT_TAG=$(lock_var MACHINE_GUEST_TOOLS_TAG)
MGT_DEB_SHA256=$(lock_var MACHINE_GUEST_TOOLS_DEB_SHA256)
MGT_TARBALL_SHA256=$(lock_var MACHINE_GUEST_TOOLS_TARBALL_SHA256)
MGT_BASE=https://github.com/cartesi/machine-guest-tools/releases/download/$MGT_TAG

fetch "$LINUX_URL" "$LINUX_SHA256" "$IMG/linux.bin"
fetch "$ROOTFS_URL" "$ROOTFS_SHA256" "$IMG/rootfs.ext2"
fetch "$MGT_BASE/machine-guest-tools_riscv64.deb" "$MGT_DEB_SHA256" "$DL/machine-guest-tools_riscv64.deb"
fetch "$MGT_BASE/machine-guest-tools_riscv64.tar.gz" "$MGT_TARBALL_SHA256" "$DL/machine-guest-tools_riscv64.tar.gz"

# doc/recipes rootfs (git lfs)
ROOTFS_DOCS="$REPO/doc/recipes/rootfs-docs.ext2"
if [ ! -s "$ROOTFS_DOCS" ] || git -C "$REPO" lfs pointer --check --file "$ROOTFS_DOCS" > /dev/null 2>&1; then
    log "git lfs pull doc/recipes/rootfs-docs.ext2"
    git -C "$REPO" lfs pull --include doc/recipes/rootfs-docs.ext2
fi
if make -s -C "$REPO/doc" check-rootfs-docs > /dev/null 2>&1; then
    log "ok rootfs-docs.ext2 matches the recipe inputs"
else
    die "doc/recipes/rootfs-docs.ext2 missing or stale (make -C doc check-rootfs-docs)"
fi
ln -sf "$ROOTFS_DOCS" "$IMG/rootfs-docs.ext2"
# check-rootfs-docs writes generated files in doc/recipes (gitignored by doc/.gitignore? leave them, they are
# the documented local convenience files)
ls -la "$IMG"
