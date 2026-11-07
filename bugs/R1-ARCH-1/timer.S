// Bare-metal RV64 M-mode guest for R1-ARCH-1.
// Reads a 64-bit deadline from PARAM (0x80001000, written by the host before running),
// stores it to CLINT mtimecmp, enables MTIE and MIE, busy-loops ~3 RTC ticks, then halts with exit 0.
// If a machine timer interrupt is taken, the handler records mcause and mcycle at RESULT and halts with exit 1.
#define HTIF_TOHOST 0x40008000
#define HALT_REG(r) slli r, r, 1; ori r, r, 1; li t6, HTIF_TOHOST; sd r, 0(t6); 1: j 1b
#define PARAM  0x80001000
#define RESULT 0x80001008
.section .text.init
.global _start
_start:
  la t0, trap
  csrw mtvec, t0
  li t0, PARAM
  ld t1, 0(t0)
  li t0, 0x02004000          // CLINT mtimecmp
  sd t1, 0(t0)
  li t0, (1 << 7)            // mie.MTIE
  csrs mie, t0
  csrsi mstatus, 8           // mstatus.MIE
  li t2, 12000               // ~24000 mcycles, i.e. past ticks 8192, 16384
loop:
  addi t2, t2, -1
  bnez t2, loop
  li a0, 0
  HALT_REG(a0)
.align 4
trap:
  li t0, RESULT
  csrr t1, mcause
  sd t1, 0(t0)
  csrr t1, mcycle
  sd t1, 8(t0)
  li a0, 1
  HALT_REG(a0)
