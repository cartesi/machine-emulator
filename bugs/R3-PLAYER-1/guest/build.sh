#!/bin/bash
# Builds the bare-metal rolling guest into the directory given as $1 (guest.bin, a flat RAM image at 0x80000000).
# The guest yields manually with the accepted reason, then for each delivered input spins input[1..2] times and
# yields accepted again (or rejected when input[0] == 'R'). It never emits outputs, so the outputs Merkle root the
# template leaves in the transmit buffer (the empty tree's root) stays correct: a correctly designed application.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out=${1:?usage: build.sh OUT_DIR}
riscv64-unknown-elf-gcc -march=rv64i -mabi=lp64 -nostdlib -nostartfiles -static -T "$here/link.ld" \
    -o "$out/guest.elf" "$here/guest.S"
riscv64-unknown-elf-objcopy -O binary "$out/guest.elf" "$out/guest.bin"
