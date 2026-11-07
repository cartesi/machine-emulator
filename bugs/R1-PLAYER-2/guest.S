# Bare-metal rolling application for R1-PLAYER-2.
# It yields manually with RX_ACCEPTED (data length 32: the outputs Merkle root the host placed in the
# transmit buffer, which this guest never touches), and after each delivered input it burns a fixed
# number of instructions (a stand-in for the application's per-input mcycle usage), then yields again.
    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000            # HTIF tohost
    li   s1, (2 << 56) | (1 << 48) | (1 << 32) | 32   # dev=yield, cmd=manual, reason=accepted, len=32
    la   t0, burn
    ld   s2, 0(t0)                  # instructions to burn per input (two per iteration)
loop:
    sd   s1, 0(s0)                  # yield manual accepted
    mv   t1, s2
1:  addi t1, t1, -1
    bnez t1, 1b
    j    loop
    .align 3
burn:
    .dword 500
