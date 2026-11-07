# Source of the guest in common.lua (M.CODE). It is hand-encoded there, so no build is needed.
# riscv64-unknown-elf-gcc -march=rv64i -mabi=lp64 -nostdlib -Ttext=0x80000000 guest.S -o guest.elf
# riscv64-unknown-elf-objdump -d guest.elf   # 00005317 00128293 00533023 ff9ff06f
.section .text
.global _start
_start:
    auipc t1, 5
1:  addi t0, t0, 1
    sd t0, 0(t1)
    j 1b
