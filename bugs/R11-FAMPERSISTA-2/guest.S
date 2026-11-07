# Bare-metal guest for R11-FAMPERSISTA-2.
# Stores a word to the 4 KiB flash drive at 0x80000000000000 (through the interpreter's write TLB),
# spins until the host sets the RAM flag at 0x80001000, then executes sfence.vma (which flushes the
# TLB slots, marking their pages dirty in whatever range pma_index names at that time) and spins.
.section .text
.global _start
_start:
    li t0, 0x80000000000000
    li t1, 0x1122334455667788
    sd t1, 0(t0)
    li t2, 0x80001000
1:  ld t3, 0(t2)
    beqz t3, 1b
    sfence.vma
2:  j 2b
