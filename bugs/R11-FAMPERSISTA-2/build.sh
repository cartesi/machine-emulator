#!/bin/bash
# Builds guest.bin from guest.S (bare metal, linked at the RAM start 0x80000000).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
riscv64-unknown-elf-gcc -march=rv64gc -mabi=lp64 -nostdlib -nostartfiles -Ttext=0x80000000 -o guest.elf guest.S
riscv64-unknown-elf-objcopy -O binary guest.elf guest.bin
rm -f guest.elf
