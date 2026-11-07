    .section .text.init
    .globl _start
_start:
    li   s0, 0x40008000            # HTIF tohost
    li   s1, 0x60000000            # rx buffer
    li   s3, 0x80001000            # first data page
    li   s4, 0x80400000            # end of 4 MiB RAM
    li   t0, 0x0201000100000020    # manual yield, rx-accepted, len 32
1:  sd   t0, 0(s0)
    ld   t2, 0(s1)                 # input word
    mv   t3, s3
2:  sd   t2, 0(t3)                 # dirty one word per page
    li   t4, 4096
    add  t3, t3, t4
    bltu t3, s4, 2b
    j    1b
