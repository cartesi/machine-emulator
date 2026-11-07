# Bare-metal guest for R5-DFGUESTOUT-1 (loaded at 0x80000000), following the manual's low-level
# rollup loop (doc/README.md, "Rollup"): "Initialize reason = RX_ACCEPTED, length = 0; Repeat: Yield
# manual with reason as REASON and length as DATA".
# 1. The template yield: manual, rx-accepted, DATA = FIRST_LEN (0 as in the manual's loop; 32 for
#    the control). The host placed the empty outputs root in the tx buffer before running.
# 2. Every later input is accepted with no outputs: the tx buffer still holds the same (empty)
#    outputs root, and the yield carries DATA = 32 (hash size), as the manual's loop does.
#ifndef FIRST_LEN
#define FIRST_LEN 0
#endif
    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000            # HTIF tohost
    li   t0, (0x0201000100000000 | FIRST_LEN)  # dev=yield, cmd=manual, reason=rx-accepted, len=FIRST_LEN
    sd   t0, 0(s0)
    li   t0, 0x0201000100000020    # dev=yield, cmd=manual, reason=rx-accepted, len=32
1:  sd   t0, 0(s0)
    j    1b
