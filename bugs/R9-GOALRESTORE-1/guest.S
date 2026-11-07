# Bare-metal M-mode guest. The host places one Sv39 gigapage PTE (V|R|W|X, A=0, D=0) mapping VA 0x80000000 to
# PA 0x80000000 at 0x80010010 (root page table at 0x80010000, VPN[2]=2).
# The guest enables Sv39, sets mstatus.MPRV=1 with MPP=S so M-mode loads are translated, performs one load
# (the page walk sets the A bit, writing the PTE in RAM), then spins forever.
.section .text
.global _start
_start:
    li t0, 0x80010          # satp.PPN = 0x80010 (root table at 0x80010000)
    li t1, 8
    slli t1, t1, 60         # satp.MODE = Sv39
    or t0, t0, t1
    csrw satp, t0
    sfence.vma
    li t0, (1<<17)|(1<<11)  # mstatus.MPRV | mstatus.MPP=S
    csrs mstatus, t0
    li t2, 0x80002000
    ld t3, 0(t2)            # translated load: page walk sets PTE.A
1:  j 1b
