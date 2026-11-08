#!/bin/bash
# Builds the uarch program halt.bin into the directory given as $1 (default: current directory).
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:-.}"
riscv64-unknown-elf-gcc -march=rv64i -mabi=lp64 -nostdlib -nostartfiles -static -Wl,-Ttext=0 \
    -o "$out/halt.elf" "$here/halt.S"
riscv64-unknown-elf-objcopy -O binary "$out/halt.elf" "$out/halt.bin"
