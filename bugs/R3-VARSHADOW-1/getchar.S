    .text
    .globl _start
_start:
    li t0, 0x40008000        # HTIF tohost
    li t1, 0x0100000000000000 # dev=1 (console), cmd=0 (getchar), data=0
    sd t1, 0(t0)
    ld a0, 8(t0)             # fromhost
    li t1, 0x0000000000000001 # halt: dev=0 cmd=0 data=1
    sd t1, 0(t0)
1:  j 1b
