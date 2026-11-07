# Bare-metal guest for R1-ROBUST-1 (loaded at 0x80000000).
# 1. Yields manually with RX_ACCEPTED (the template; the host placed the empty outputs root in the tx buffer).
# 2. Reads N from the first 8 bytes of the delivered input (rx buffer at 0x60000000).
# 3. Issues N automatic TX_OUTPUT yields of length 2 MiB (the whole tx buffer), never rewriting the buffer:
#    one store to tohost per output, about 4 mcycles each.
# 4. Yields manually with RX_REJECTED, so every output is discarded anyway.
    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000            # HTIF tohost
    li   s1, 0x60000000            # rx buffer
    li   t0, 0x0201000100000000    # dev=yield, cmd=manual, reason=rx-accepted, len=0
    sd   t0, 0(s0)
    ld   s2, 0(s1)                 # N
    li   t1, 0x0200000200200000    # dev=yield, cmd=automatic, reason=tx-output, len=0x200000
1:  beqz s2, 2f
    sd   t1, 0(s0)
    addi s2, s2, -1
    j    1b
2:  li   t0, 0x0201000200000000    # dev=yield, cmd=manual, reason=rx-rejected, len=0
    sd   t0, 0(s0)
3:  j    3b
