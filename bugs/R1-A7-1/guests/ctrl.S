// R1-A7-1 guest "ctrl": control: integer adds in U-mode (cheapest instructions, close to Dave's measured average density)
// Loaded at 0x80000000 in M-mode. Enables the FPU, then mret's to the loop in the privilege
// level given by MPP below, with satp = 0 (bare translation). The loop body is repeated so that
// almost every mcycle executes the instruction under test.
    .option arch, +d
    .section .text.init
    .global _start
_start:
    li t0, (3<<13)              // mstatus.FS = dirty (FPU on)
    csrs mstatus, t0
    li t1, 0x4009214afcd1234f
    fmv.d.x f1, t1
    li t1, 0x3ff3333333333333
    fmv.d.x f2, t1
    li t1, 0x0000000000012345
    fmv.d.x f3, t1
    li t0, (3<<11)              // mstatus.MPP = 0
    csrc mstatus, t0
    li t0, (0<<11)
    csrs mstatus, t0
    la t0, loop
    csrw mepc, t0
    mret
    .align 4
loop:
    .rept 32
    addi t3, t3, 1
    addi t4, t4, 1
    .endr
    j loop
