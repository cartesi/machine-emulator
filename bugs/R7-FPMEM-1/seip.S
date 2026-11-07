# R7-FPMEM-1 bare-metal guest (M-mode entry at 0x80000000).
# Part 1 (M-mode): set mip.SEIP in software, store 1 to PLIC claim/complete, read mip again.
# Part 2 (S-mode): M-mode sets mip.SEIP, delegates SEI to S (mideleg), enables mie.SEIE, enters S-mode with
#   sstatus.SIE=0. S-mode stores 1 to PLIC claim/complete, then sets sstatus.SIE=1. The software-injected
#   supervisor external interrupt must then be taken (stvec handler records scause).
# Results (8 bytes each) at RESULT: [0] mip after csrs, [1] mip after claim/complete write (M-mode),
#   [2] scause seen by S trap handler (0 = no interrupt taken), [3] mcause of the final M trap (ecall).
# Control: if the host writes a nonzero word at SKIP, part 2 skips the S-mode store (validates the harness).
    .equ RESULT, 0x80001000
    .equ SKIP, 0x80001100
    .equ PLIC_CLAIM_COMPLETE, 0x40300004
    .equ HTIF_TOHOST, 0x40008000
    .section .text.init
    .globl _start
_start:
    la t0, mtrap
    csrw mtvec, t0
    li s2, RESULT
    # ---- Part 1: M-mode ----
    li t0, 0x200            # SEIP
    csrs mip, t0
    csrr s0, mip
    li t1, PLIC_CLAIM_COMPLETE
    li t2, 1
    sw t2, 0(t1)
    csrr s1, mip
    sd s0, 0(s2)
    sd s1, 8(s2)
    sd zero, 16(s2)
    # ---- Part 2: S-mode ----
    li t0, 0x200
    csrc mip, t0            # start from a clean software SEIP
    csrs mip, t0            # inject supervisor external interrupt
    csrw mideleg, t0        # delegate SEI to S-mode
    csrs mie, t0            # SEIE
    la t0, strap
    csrw stvec, t0
    li t0, 0x1802           # clear MPP and SIE
    csrc mstatus, t0
    li t0, 0x800            # MPP = S
    csrs mstatus, t0
    la t0, smode
    csrw mepc, t0
    mret
smode:
    li t1, SKIP
    lw t1, 0(t1)
    bnez t1, 2f
    li t1, PLIC_CLAIM_COMPLETE
    li t2, 1
    sw t2, 0(t1)            # S-mode store to claim/complete
2:
    csrsi sstatus, 2        # SIE = 1: the pending SEI must be taken now
    nop
    nop
    ecall                   # no interrupt taken: go to M-mode and halt
strap:
    csrr t0, scause
    sd t0, 16(s2)
    ecall
mtrap:
    csrr t0, mcause
    sd t0, 24(s2)
    li t0, HTIF_TOHOST
    li t1, 1                # halt, exit code 0
    sd t1, 0(t0)
1:  j 1b
