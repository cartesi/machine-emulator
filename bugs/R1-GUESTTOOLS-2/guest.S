# Bare-metal M-mode guest for R1-GUESTTOOLS-2.
# PARAM (0x80001000) holds, written by the test before the template is built:
#   +0x00: 32 bytes copied to the transmit buffer before the first yield (the root of the empty outputs tree)
#   +0x20: 32 bytes copied to the transmit buffer before every later yield
#   +0x40: the tohost word of every later yield (a manual yield with the accepted reason, and some DATA)
# 1. copy PARAM[0x00..0x20) to the transmit buffer and yield manual rx-accepted with DATA=32 (the valid template)
# 2. after each delivered input, copy PARAM[0x20..0x40) to the transmit buffer and write PARAM+0x40 to tohost
    .section .text.init
    .globl _start
_start:
    li t0, 0x80001000
    li t1, 0x60800000          # AR_CMIO_TX_BUFFER_START
    li t2, 0x40008000          # AR_HTIF_START (tohost)
    ld a0, 0(t0)
    sd a0, 0(t1)
    ld a0, 8(t0)
    sd a0, 8(t1)
    ld a0, 16(t0)
    sd a0, 16(t1)
    ld a0, 24(t0)
    sd a0, 24(t1)
    li a1, 0x0201000100000020  # dev=yield cmd=manual reason=rx-accepted data=32
    sd a1, 0(t2)
1:
    ld a0, 0x20(t0)
    sd a0, 0(t1)
    ld a0, 0x28(t0)
    sd a0, 8(t1)
    ld a0, 0x30(t0)
    sd a0, 16(t1)
    ld a0, 0x38(t0)
    sd a0, 24(t1)
    ld a1, 0x40(t0)
    sd a1, 0(t2)
    j 1b
