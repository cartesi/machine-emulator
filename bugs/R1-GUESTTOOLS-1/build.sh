#!/bin/bash
# Builds the bare-metal guest yield.bin into the directory given as $1 (default: current directory).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-.}"
riscv64-unknown-elf-gcc -march=rv64ima_zicsr -mabi=lp64 -nostdlib -nostartfiles -static \
    -T "$here/link.ld" -o "$out/yield.elf" "$here/yield.S"
riscv64-unknown-elf-objcopy -O binary "$out/yield.elf" "$out/yield.bin"
