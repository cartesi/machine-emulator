#!/bin/bash
# Builds the bare-metal guest into the directory given as the first argument (default: here).
# It links libcmt's own keccak and merkle sources from the pinned machine-guest-tools checkout,
# with a freestanding stand-in for the few libc functions they call (libc/).
set -eu
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$here}"
cmt="${MACHINE_GUEST_TOOLS_DIR:-/home/user/ext/machine-guest-tools}/sys-utils/libcmt"
riscv64-unknown-elf-gcc -march=rv64imac -mabi=lp64 -mcmodel=medany -O2 -ffreestanding -fno-builtin \
    -nostdlib -nostartfiles -static -ffunction-sections -fdata-sections -Wl,--gc-sections,--no-warn-rwx-segments \
    -I "$here/libc" -I "$cmt/include" -T "$here/link.ld" -o "$out/guest.elf" \
    "$here/start.S" "$here/guest.c" "$here/libc/libc.c" "$cmt/src/merkle.c" "$cmt/src/keccak.c" -lgcc
riscv64-unknown-elf-objcopy -O binary "$out/guest.elf" "$out/guest.bin"
