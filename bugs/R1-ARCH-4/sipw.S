// Bare-metal RV64 guest for R1-ARCH-4 (sip write mask).
// M-mode delegates SSI, STI and SEI in mideleg (as OpenSBI does), leaves interrupts globally disabled
// (mstatus.SIE = 0, sie = 0, so no interrupt is ever taken), and selects a case from PARAM (0x80001000):
//   case 0: S-mode does csrs sip,(STIP|SEIP); a0 = ((sip & (STIP|SEIP)) != 0). Spec: bits read-only -> 0.
//   case 1: M-mode sets mip.STIP|SEIP, S-mode does csrc sip,(STIP|SEIP);
//           a0 = ((sip & (STIP|SEIP)) != (STIP|SEIP)). Spec: bits read-only -> 0.
//   case 2: control: S-mode does csrs sip,SSIP; a0 = ((sip & SSIP) == 0). Spec: SSIP writable -> 0.
// S-mode then ECALLs (not delegated) and the M handler halts with exit code a0.
#define HTIF_TOHOST 0x40008000
#define HALT_REG(r) slli r, r, 1; ori r, r, 1; li t6, HTIF_TOHOST; sd r, 0(t6); 1: j 1b
#define PARAM 0x80001000
#define SSIP (1<<1)
#define STIP (1<<5)
#define SEIP (1<<9)
.section .text.init
.global _start
_start:
  li t0, SSIP|STIP|SEIP; csrw mideleg, t0
  la t0, mtrap; csrw mtvec, t0
  li t0, PARAM; ld s0, 0(t0)
  li t0, 1; bne s0, t0, 2f
  li t0, STIP|SEIP; csrs mip, t0        // case 1: firmware raises STI and SEI for S
2:
  la t0, smode; csrw mepc, t0
  li t0, (3<<11); csrc mstatus, t0; li t0, (1<<11); csrs mstatus, t0  // MPP=S, MPIE=0, SPIE/SIE=0
  mret
.align 4
mtrap:
  HALT_REG(a0)
smode:
  beqz s0, case0
  li t0, 1; beq s0, t0, case1
case2:
  li t0, SSIP; csrs sip, t0
  csrr t1, sip; and t1, t1, t0; seqz a0, t1
  ecall
case0:
  li t0, STIP|SEIP; csrs sip, t0
  csrr t1, sip; and t1, t1, t0; snez a0, t1
  ecall
case1:
  li t0, STIP|SEIP; csrc sip, t0
  csrr t1, sip; and t1, t1, t0; xor t1, t1, t0; snez a0, t1
  ecall
