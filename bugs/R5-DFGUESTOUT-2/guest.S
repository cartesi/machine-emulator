# Bare-metal guest for R5-DFGUESTOUT-2 (loaded at 0x80000000).
# 1. Yields manually with RX_ACCEPTED (the template; the host placed the empty outputs root in the tx buffer).
# 2. Reads N from bytes 0..7 of the delivered input and a tohost word W from bytes 8..15
#    (rx buffer at 0x60000000). The test uses W = automatic tx-output or automatic tx-report, DATA = 0x200000.
# 3. Stores W to tohost N times, never rewriting the tx buffer: one automatic yield of the whole 2 MiB
#    tx buffer per iteration, about 4 mcycles each.
# 4. Yields manually with RX_REJECTED, so every output is discarded anyway.
    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000            # HTIF tohost
    li   s1, 0x60000000            # rx buffer
    li   t0, 0x0201000100000000    # dev=yield, cmd=manual, reason=rx-accepted, len=0
    sd   t0, 0(s0)
    ld   s2, 0(s1)                 # N
    ld   t1, 8(s1)                 # W
1:  beqz s2, 2f
    sd   t1, 0(s0)
    addi s2, s2, -1
    j    1b
2:  li   t0, 0x0201000200000000    # dev=yield, cmd=manual, reason=rx-rejected, len=0
    sd   t0, 0(s0)
3:  j    3b
