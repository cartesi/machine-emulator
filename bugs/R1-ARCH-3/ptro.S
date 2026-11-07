// R1-ARCH-3 guest. M-mode driver runs a list of cases. Each case sets satp, flushes translations, drops to S-mode
// at a given entry point with a1 = data address, and records (mcause, mtval) of the first trap back into M-mode at
// RESULT + 16*case. The S-mode stubs end with ecall, so mcause 9 means the S-mode code ran to completion.
#define HTIF_TOHOST 0x40008000
#define RESULT      0x80008000
#define RAM_PT      0x80006000              // control page table, in RAM
#define RO_PT       0x100000000             // page table in a read-only flash drive (image built by test.lua)
#define CLINT       0x2000000               // device range, not memory
#define HOLE        0x200000000             // no range at all
#define SV39(root)  ((8 << 60) | ((root) >> 12))
#define NCASES      6

.section .text.init
.global _start
_start:
    la t0, mtrap
    csrw mtvec, t0
    // control page table in RAM: entry[2] = identity gigapage at 0x80000000, V|R|X, A=0
    li t0, RAM_PT + 2*8
    li t1, (0x80000 << 10) | 0x0b
    sd t1, 0(t0)
    li s0, 0
next:
    li t0, NCASES
    beq s0, t0, done
    la t0, cases
    slli t1, s0, 4
    slli t2, s0, 3
    add t1, t1, t2                          // t1 = 24 * case
    add t0, t0, t1
    ld t2, 0(t0)                            // satp
    ld t3, 8(t0)                            // S-mode entry
    ld a1, 16(t0)                           // data address
    csrw satp, t2
    sfence.vma
    csrw mepc, t3
    li t0, (3 << 11)
    csrc mstatus, t0
    li t0, (1 << 11)
    csrs mstatus, t0                        // MPP = S
    mret

mtrap:
    csrr t0, mcause
    csrr t1, mtval
    li t2, RESULT
    slli t3, s0, 4
    add t2, t2, t3
    sd t0, 0(t2)
    sd t1, 8(t2)
    csrw satp, zero
    addi s0, s0, 1
    j next

done:
    li a0, 1                                // exit code 0: (0 << 1) | 1
    li t6, HTIF_TOHOST
    sd a0, 0(t6)
1:  j 1b

.align 3
s_ecall:
    ecall
.align 3
s_load:
    ld t0, 0(a1)
    ecall
.align 3
s_store:
    sd t0, 0(a1)
    ecall

.align 3
cases:
    // 0: fetch through RO table entry[5] (vaddr 0x140000000 -> 0x80000000, V|R|X, A=0)
    .dword SV39(RO_PT), s_ecall + 0xC0000000, 0
    // 1: load through RO table entry[3] (vaddr 0xC0000000 -> 0x80000000, V|R|W|X, A=0); code via entry[2] (A=1)
    .dword SV39(RO_PT), s_load, 0xC0005000
    // 2: store through RO table entry[4] (vaddr 0x100000000 -> 0x80000000, V|R|W, A=1, D=0); code via entry[2]
    .dword SV39(RO_PT), s_store, 0x100005000
    // 3: fetch with the root page table in the CLINT device range
    .dword SV39(CLINT), s_ecall, 0
    // 4: fetch with the root page table in an unmapped hole
    .dword SV39(HOLE), s_ecall, 0
    // 5: control: fetch through the RAM table entry[2] (A=0); must succeed and set A
    .dword SV39(RAM_PT), s_ecall, 0
