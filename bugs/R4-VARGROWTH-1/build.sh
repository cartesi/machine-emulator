#!/bin/bash
# Builds the bare-metal guest into the directory given as the first argument (default: here).
set -eu
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-$here}"
riscv64-unknown-elf-gcc -march=rv64ima -mabi=lp64 -nostdlib -nostartfiles -static \
    -T "$here/link.ld" -o "$out/guest.elf" "$here/guest.S"
riscv64-unknown-elf-objcopy -O binary "$out/guest.elf" "$out/guest.bin"
