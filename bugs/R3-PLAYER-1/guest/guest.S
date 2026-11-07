    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000
    li   s3, 0x60000000
    li   s1, (2 << 56) | (1 << 48) | (1 << 32) | 32
    li   s4, (2 << 56) | (1 << 48) | (2 << 32) | 0
yield_acc:
    sd   s1, 0(s0)
handle:
    lbu  t0, 0(s3)
    lbu  t1, 1(s3)
    lbu  t2, 2(s3)
    slli t2, t2, 8
    or   t1, t1, t2
    beqz t1, 2f
1:  addi t1, t1, -1
    bnez t1, 1b
2:  li   t3, 'R'
    beq  t0, t3, reject
    j    yield_acc
reject:
    sd   s4, 0(s0)
    j    handle
