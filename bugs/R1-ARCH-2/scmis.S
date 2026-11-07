// Bare-metal RV64 M-mode guest for R1-ARCH-2.
// Runs four cases, none with a live LR reservation. For each case it records, in a 24-byte slot at RESULT + 24*i:
//   +0 mcause of the trap taken by the instruction (0 if none), +8 mtval (0 if none), +16 final value of rd (t0).
// rd is preset to 0xdead, so a trapping instruction leaves 0xdead there.
//   case 0: sc.w t0, t1, (0x80002001)   misaligned word SC      -> must trap with mcause 6, mtval = address
//   case 1: sc.d t0, t1, (0x80002004)   misaligned doubleword SC -> must trap with mcause 6, mtval = address
//   case 2: sc.w t0, t1, (0x80002000)   aligned SC, no reservation -> no trap, rd = 1 (control)
//   case 3: sw   t1,     (0x80002001)   misaligned plain store   -> traps with mcause 6 (control)
// The trap handler records mcause/mtval into the current slot (s1), skips the faulting instruction and returns.
// The program then halts with exit 0.
#define HTIF_TOHOST 0x40008000
#define RESULT 0x80003000
#define DATA   0x80002000
#define BEGIN_CASE(i) li s1, RESULT + 24*(i); sd zero, 0(s1); sd zero, 8(s1); li t0, 0xdead; li t1, 5
#define END_CASE sd t0, 16(s1)
.section .text.init
.global _start
_start:
  la t0, trap
  csrw mtvec, t0
  li a1, DATA

  BEGIN_CASE(0)
  addi a2, a1, 1
  sc.w t0, t1, (a2)
  END_CASE

  BEGIN_CASE(1)
  addi a2, a1, 4
  sc.d t0, t1, (a2)
  END_CASE

  BEGIN_CASE(2)
  sc.w t0, t1, (a1)
  END_CASE

  BEGIN_CASE(3)
  addi a2, a1, 1
  sw t1, 0(a2)
  END_CASE

  li a0, 0
  slli a0, a0, 1
  ori a0, a0, 1
  li t6, HTIF_TOHOST
  sd a0, 0(t6)
1: j 1b

.align 4
trap:
  csrr t5, mcause
  sd t5, 0(s1)
  csrr t5, mtval
  sd t5, 8(s1)
  csrr t5, mepc
  addi t5, t5, 4
  csrw mepc, t5
  mret
