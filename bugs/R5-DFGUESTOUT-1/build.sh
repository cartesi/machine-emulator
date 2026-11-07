#!/bin/bash
# Builds guest-<len>.bin (template yield DATA = <len>) into directory $1 for each <len> in $2...
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-.}"
shift || true
for len in "${@:-0}"; do
    riscv64-unknown-elf-gcc -march=rv64i -mabi=lp64 -nostdlib -nostartfiles -static -DFIRST_LEN="$len" \
        -T "$here/link.ld" -o "$out/guest-$len.elf" "$here/guest.S"
    riscv64-unknown-elf-objcopy -O binary "$out/guest-$len.elf" "$out/guest-$len.bin"
done
