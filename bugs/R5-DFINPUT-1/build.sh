#!/bin/bash
# R5-DFINPUT-1: build the guest ballot app against the LIVE pinned libcmt sources
# (so a fix to abi.c is exercised) with the pinned cross compiler at -O2, and pack
# it into an ext2 flash drive. Usage: build.sh <build-dir>
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
build="${1:?usage: build.sh <build-dir>}"
: "${MACHINE_GUEST_TOOLS_DIR:?set by bugs/env.sh}"
LC="$MACHINE_GUEST_TOOLS_DIR/sys-utils/libcmt"
CC=riscv64-linux-gnu-gcc
command -v "$CC" >/dev/null
rm -rf "$build"
mkdir -p "$build/root"
"$CC" -O2 -static -I"$LC/include" "$here/app.c" \
    "$LC/src/abi.c" "$LC/src/buf.c" "$LC/src/rollup.c" "$LC/src/io.c" \
    "$LC/src/merkle.c" "$LC/src/keccak.c" "$LC/src/util.c" \
    -o "$build/root/app.rv64"
mke2fs -q -F -b 1024 -d "$build/root" -t ext2 "$build/poc.ext2" 2048 >/dev/null 2>&1
