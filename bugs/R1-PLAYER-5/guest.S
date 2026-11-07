# Bare-metal rolling application for R1-PLAYER-5 (a correctly designed application).
# It yields manually with RX_ACCEPTED (data length 32: the outputs Merkle root the host placed in the
# transmit buffer, which this guest never touches). After each delivered input it burns a fixed
# number of instructions, a stand-in for an input that drives the application to its per-input
# mcycle bound, and then accepts again. Every input therefore costs the honest operator the same,
# bounded, number of mcycles.
    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000            # HTIF tohost
    li   s1, (2 << 56) | (1 << 48) | (1 << 32) | 32   # dev=yield, cmd=manual, reason=accepted, len=32
    la   t0, burn
    ld   s2, 0(t0)                  # loop iterations per input (two instructions each)
loop:
    sd   s1, 0(s0)                  # yield manual accepted
    mv   t1, s2
1:  addi t1, t1, -1
    bnez t1, 1b
    j    loop
    .align 3
burn:
    .dword 50000
