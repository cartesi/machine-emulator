/* Entry point of bare-metal guests. The machine starts here (pc = AR_RAM_START) in M-mode.
 * Sets sp to the top of the stack area defined by link.ld, clears .bss, calls main(), then halts with
 * main's return value as the exit code. */
    .section .text.init
    .global _start
_start:
    la sp, __stack_top
    la t0, __bss_start
    la t1, __bss_end
1:  bgeu t0, t1, 2f
    sd zero, 0(t0)
    addi t0, t0, 8
    j 1b
2:  call main
    /* halt: tohost = dev 0, cmd 0, data = (code << 1) | 1 */
    slli a0, a0, 1
    ori a0, a0, 1
    li t0, 0x40008000
3:  sd zero, 8(t0)
    sd a0, 0(t0)
    j 3b
