// R1-A7-1 guest "sfence": sfence.vma in S-mode (guest kernel code; THREAT_MODEL section 4: any instruction stream at any privilege level)
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
    li t0, (3<<11)              // mstatus.MPP = 1
    csrc mstatus, t0
    li t0, (1<<11)
    csrs mstatus, t0
    la t0, loop
    csrw mepc, t0
    mret
    .align 4
loop:
    .rept 32
    sfence.vma x0, x0
    sfence.vma x0, x0
    .endr
    j loop
