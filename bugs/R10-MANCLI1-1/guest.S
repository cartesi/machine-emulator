# Bare-metal M-mode rollup guest for R10-MANCLI1-1.
# DATA page (0x80005000) is written by the test before the template is built:
#   +0x00: an 8-byte counter the guest updates on every advance-state input (its "application state")
#   +0x20: 32 bytes copied to the transmit buffer (the root of the empty outputs tree)
# 1. copy DATA[0x20..0x40) to the transmit buffer and yield manual rx-accepted with DATA=32 (the template)
# 2. on every resume (an input was delivered): counter += 1 (one dword written to the DATA page), then
#    yield manual rx-accepted again. No outputs are emitted, so the outputs root stays valid.
    .section .text.init
    .globl _start
_start:
    li t0, 0x80005000
    li t1, 0x60800000
    ld a0, 0x20(t0)
    sd a0, 0(t1)
    ld a0, 0x28(t0)
    sd a0, 8(t1)
    ld a0, 0x30(t0)
    sd a0, 16(t1)
    ld a0, 0x38(t0)
    sd a0, 24(t1)
    li t2, 0x40008000
    li a1, 0x0201000100000020   # dev=yield cmd=manual reason=rx-accepted data=32
1:
    sd a1, 0(t2)
    ld a0, 0(t0)
    addi a0, a0, 1
    sd a0, 0(t0)
    j 1b
