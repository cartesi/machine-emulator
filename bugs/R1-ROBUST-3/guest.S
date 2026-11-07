# Bare-metal guest for R1-ROBUST-3.
# Template: yields manually with rx-accepted. For the delivered input, reads two words from the rx
# buffer: N and MODE. It then runs a 4-instruction loop N times. With MODE = 0 each iteration stores
# an automatic progress yield (length 0) to HTIF tohost; with MODE = 1 it stores the same word to RAM
# instead, so both modes spend the same number of mcycles. Finally it rejects the input.
    .section .text
    .globl _start
_start:
    li s0, 0x40008000          # HTIF tohost
    li s1, 0x60000000          # rx buffer
    li t0, 0x0201000100000000  # manual yield, rx-accepted
    sd t0, 0(s0)
    ld s2, 0(s1)               # N
    ld s3, 8(s1)               # MODE
    beqz s3, 0f
    li s0, 0x80080000          # MODE != 0: store into RAM instead of tohost
0:  li t1, 0x0200000100000000  # automatic yield, progress, length 0
1:  beqz s2, 2f
    sd t1, 0(s0)
    addi s2, s2, -1
    j 1b
2:  li s0, 0x40008000
    li t0, 0x0201000200000000  # manual yield, rx-rejected
    sd t0, 0(s0)
3:  j 3b
