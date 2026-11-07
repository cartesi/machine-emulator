// Bare-metal RV64 guest for R4-VARSPEC-1 (reserved A/D/U bits in a non-leaf PTE).
// Inputs written by the host before the run:
//   PARAM+0 (0x80004000): bits OR-ed into the non-leaf root PTE (0, A=0x40, D=0x80 or U=0x10).
//   PARAM+8 (0x80004008): access kind: 0 = instruction fetch (S-mode executes ecall through the page table),
//                         1 = load and 2 = store (M-mode with mstatus.MPRV=1, MPP=S, so the access is translated).
// Page tables (Sv39): root at 0x80010000, root[2] -> L1 at 0x80011000 (non-leaf, V | PARAM bits),
// L1[0] = V|R|W|X|A|D 2 MiB leaf identity-mapping VA 0x80000000 to PA 0x80000000.
// Every trap goes to M-mode, whose handler halts with exit code = mcause:
//   9  = ecall from S (fetch succeeded),  11 = ecall from M (load/store succeeded),
//   12/13/15 = instruction/load/store page fault (what the privileged spec requires when a reserved bit is set).
#define HTIF_TOHOST 0x40008000
#define PARAM 0x80004000
#define ROOT  0x80010000
#define L1    0x80011000
.section .text.init
.global _start
_start:
  la t0, mtrap; csrw mtvec, t0
  li t0, PARAM; ld s0, 0(t0); ld s1, 8(t0)
  // L1[0]: 2 MiB leaf, PPN = 0x80000, flags V|R|W|X|A|D = 0xcf
  li t1, L1; li t2, (0x80000 << 10) | 0xcf; sd t2, 0(t1)
  // root[2]: non-leaf pointer to L1 (PPN = 0x80011), flags V | PARAM bits
  li t1, ROOT; li t2, (0x80011 << 10) | 0x1; or t2, t2, s0; sd t2, 16(t1)
  // satp = Sv39 (mode 8) | PPN(ROOT)
  li t0, (8 << 60) | (ROOT >> 12); csrw satp, t0
  sfence.vma
  beqz s1, fetch
  // MPP = S, MPRV = 1: M-mode loads/stores are translated with S privilege
  li t0, (3 << 11); csrc mstatus, t0; li t0, (1 << 11) | (1 << 17); csrs mstatus, t0
  li t1, PARAM
  li t0, 1; beq s1, t0, load
store:
  sd zero, 16(t1)
  ecall
load:
  ld t2, 0(t1)
  ecall
fetch:
  la t0, smode; csrw mepc, t0
  li t0, (3 << 11); csrc mstatus, t0; li t0, (1 << 11); csrs mstatus, t0  // MPP = S
  mret
.align 4
mtrap:
  csrr a0, mcause
  slli a0, a0, 1; ori a0, a0, 1; li t6, HTIF_TOHOST; sd a0, 0(t6)
1: j 1b
.align 4
smode:
  ecall
