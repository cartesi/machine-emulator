// Bare-metal RV64 M-mode guest for R4-VARSPEC-2.
// The host writes a store target address at PARAM (0x80001000) before running:
//   case 0: a RAM scratch word  -> the sw is an ordinary store, execution falls through into `measure`
//   case 1: CLINT msip (0x02000000) -> the sw raises mip.MSIP, and the machine software interrupt is taken
//           before the next instruction, jumping to mtvec == `measure` (the very same address).
// Either way exactly three instructions retire between the two minstret reads (csrr, csrr, sw).
// `measure` reads minstret/mcycle again, clears msip, records dinstret, dmcycle and mcause at RESULT, and halts.
#define HTIF_TOHOST 0x40008000
#define PARAM  0x80001000
#define RESULT 0x80001010
.section .text.init
.option norvc
.global _start
_start:
  la t0, measure
  csrw mtvec, t0             // direct mode
  csrw mcause, zero
  li t0, (1 << 3)            // mie.MSIE
  csrs mie, t0
  csrsi mstatus, 8           // mstatus.MIE
  li t0, PARAM
  ld t2, 0(t0)               // store target
  li t1, 1
  csrr s0, minstret          // instruction 1
  csrr s1, mcycle            // instruction 2
  sw t1, 0(t2)               // instruction 3 (raises MSI in case 1)
.align 2
measure:
  csrr s2, minstret
  csrr s3, mcycle
  csrr s4, mcause
  li t0, 0x02000000
  sw zero, 0(t0)             // clear msip
  sub s2, s2, s0             // dinstret
  sub s3, s3, s1             // dmcycle
  li t0, RESULT
  sd s2, 0(t0)
  sd s3, 8(t0)
  sd s4, 16(t0)
  li t0, HTIF_TOHOST
  li t1, 1                   // halt, exit code 0
  sd t1, 0(t0)
1: j 1b
