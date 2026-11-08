# Uarch program for R14-INVLOGS-1. Like the uarch interpreter, it completes one main-processor step: it increments
# mcycle (shadow register at physical address 0x100) and then halts. It executes exactly 2^20-1 instructions and
# halts on the last one: 8 setup instructions, 524283 iterations of a 2-instruction loop, then the halting ECALL.
# 8 + 2*524283 + 1 = 1048575 = UARCH_CYCLE_MAX. It uses only PC-relative branches, so it runs at any load address.
.text
.globl _start
_start:
  nop
  li t1, 0x100          # physical address of the mcycle shadow register
  ld t2, 0(t1)
  addi t2, t2, 1
  sd t2, 0(t1)          # mcycle += 1
  lui t0, 0x80          # t0 = 0x80000 = 524288
  addiw t0, t0, -5      # t0 = 524283 loop iterations
  li a7, 1              # uarch ECALL function 1 = halt
loop:
  addi t0, t0, -1
  bnez t0, loop
  ecall                 # halts the uarch: the 1048575th instruction
