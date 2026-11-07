#!/bin/bash
# Rebuilds guest.bin (a small checked-in fixture) from guest.S with the bare-metal cross compiler.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
riscv64-unknown-elf-gcc -march=rv64ima_zicsr -mabi=lp64 -nostdlib -nostartfiles -Wl,-Ttext=0x80000000 -o guest.elf guest.S
riscv64-unknown-elf-objcopy -O binary guest.elf guest.bin
rm -f guest.elf
