#!/bin/bash
# Build xgenext2fs (cartesi/genext2fs v1.5.6, the version doc/Dockerfile installs) into bugs/harness/work/bin.
# doc/recipes (game-test-fixtures.sh, prt-demo.sh) use it to make ext2 drives. Needs automake, libarchive-dev.
set -euo pipefail
. "$(dirname "$0")/../lib/common.sh"
[ -x "$WORK/bin/xgenext2fs" ] && { log "xgenext2fs exists"; exit 0; }
src="$WORK/src/genext2fs"
clone_at_tag https://github.com/cartesi/genext2fs.git v1.5.6 466d4aef70ba54b0ec79f2b1ebdd253d82bed06b "$src"
mkdir -p "$WORK/bin"
(cd "$src" && ./autogen.sh && ./configure --enable-libarchive --prefix="$WORK/genext2fs-install" &&
    make -j"$(nproc)" && make install) > "$WORK/xgenext2fs-build.log" 2>&1 || {
    tail -20 "$WORK/xgenext2fs-build.log" >&2
    die "xgenext2fs build failed"
}
ln -sf "$WORK/genext2fs-install/bin/xgenext2fs" "$WORK/bin/xgenext2fs"
log "xgenext2fs ok"
