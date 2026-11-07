# Bare-metal M-mode guest for R1-GUESTTOOLS-1.
# PARAM (0x80001000) holds, written by the test before the template is built:
#   +0x00: 32 bytes copied to the transmit buffer (the root of the empty outputs tree)
#   +0x20: the tohost word of the yield taken after the first input is delivered
#   +0x28: the tohost word of every later yield
# 1. copy PARAM[0..32) to the transmit buffer and yield manual rx-accepted with DATA=32 (the template)
# 2. after the input is delivered, write PARAM+0x20 to tohost (the oversized-DATA yield)
# 3. then write PARAM+0x28 to tohost forever (one yield per resume)
    .section .text.init
    .globl _start
_start:
    li t0, 0x80001000
    li t1, 0x60800000
    ld a0, 0(t0)
    sd a0, 0(t1)
    ld a0, 8(t0)
    sd a0, 8(t1)
    ld a0, 16(t0)
    sd a0, 16(t1)
    ld a0, 24(t0)
    sd a0, 24(t1)
    li t2, 0x40008000
    li a1, 0x0201000100000020   # dev=yield cmd=manual reason=rx-accepted data=32
    sd a1, 0(t2)
    ld a1, 0x20(t0)
    sd a1, 0(t2)
1:
    ld a1, 0x28(t0)
    sd a1, 0(t2)
    j 1b
