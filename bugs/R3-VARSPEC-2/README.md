# R3-VARSPEC-2: an M-mode write to `mcycle` raises illegal-instruction, and the manual does not document it

## What is asserted

`write_csr_mcycle` in `src/interpret.cpp` returns `execute_status::failure`. So every CSR instruction that writes
`mcycle` (CSR `0xB00`) raises an illegal-instruction exception, even in M-mode. The RISC-V privileged specification
defines `mcycle` as an MRW register, which M-mode may write. The behavior is deliberate: `mcycle` is the dispute clock,
and THREAT_MODEL.md R8 says the guest "can never change the cycle counter". But `doc/README.md` never says that
`mcycle` is read-only or that writing it traps. "The main processor" section describes `mcycle` only as a standard
register "advanced at every CPU cycle".

`test.lua` builds a bare machine (1 MiB RAM, starts in M-mode at `0x80000000`, `mtvec` = `0x80000100`, `x6` =
`0x12345`). It runs one instruction there, both natively (`machine:run`) and on the uarch path (`run_uarch` +
`reset_uarch`). The two paths must reach the same root hash, or the test exits 2. The instructions are:

- writes: `csrrw x0,mcycle,x6`, `csrrs x0,mcycle,x6`, `csrrc x0,mcycle,x6`, `csrrwi x0,mcycle,5`;
- controls, which must retire or the test exits 2: `csrrw x0,minstret,x6` (the writable sibling counter) and
  `csrrs x7,mcycle,x0` (a plain read).

The test then looks for a sentence in the prose of `doc/README.md` (fenced code blocks left out) that names `mcycle`
and says it is read-only, not writable, or that writing it traps, raises an exception, or is ignored.

- Exit 1 if a write to `mcycle` traps (or is ignored) and the manual documents nothing. This is the R7 violation.
- Exit 1 also if a write takes effect. That would break R8.
- Exit 0 only when the manual documents the deviation and the guest cannot change `mcycle`.

R8 requires the current behavior, so the expected fix is to document it in the manual. To check the test against such
a fix without editing the tracked manual, set `MANUAL_OVERRIDE=<path to a copy of README.md>`. With a copy that adds
"Unlike the RISC-V specification, which makes it an MRW register, the guest cannot write `mcycle`: a CSR instruction
that writes it raises an illegal-instruction exception." after the `mcycle` paragraph of "The main processor", the
test exits 0.

## Requirement

THREAT_MODEL.md R7 (area "Traps and interrupts"): "The emulator implements the RISC-V specification and the devices
as the manual documents them, departing only where the manual documents a deviation."
Section 8, Medium: "An undocumented deterministic deviation, consistent across all paths, in behavior that no correct
guest relies on for isolation or data integrity (R7)."
R8: "It can never change the cycle counter".

## How to run

```sh
bugs/run.sh R3-VARSPEC-2
```

Needs only the in-tree emulator build. It takes about one second.

## Expected output on audit/prt2

```
csrrw x0,mcycle,x6                 native+uarch: pc=0x80000100 mcause=2 mtval=0xb0031073 mcycle 0->1  TRAPPED (illegal instruction)
csrrs x0,mcycle,x6                 native+uarch: pc=0x80000100 mcause=2 mtval=0xb0032073 mcycle 0->1  TRAPPED (illegal instruction)
csrrc x0,mcycle,x6                 native+uarch: pc=0x80000100 mcause=2 mtval=0xb0033073 mcycle 0->1  TRAPPED (illegal instruction)
csrrwi x0,mcycle,5                 native+uarch: pc=0x80000100 mcause=2 mtval=0xb002d073 mcycle 0->1  TRAPPED (illegal instruction)
csrrw x0,minstret,x6 (control)     native+uarch: pc=0x80000004 mcause=0 mtval=0x0 mcycle 0->1  retired
csrrs x7,mcycle,x0 (control)       native+uarch: pc=0x80000004 mcause=0 mtval=0x0 mcycle 0->1  retired
manual: no sentence naming `mcycle` says it is read-only, not writable, or that writes trap
writes to mcycle: 4 trapped, 0 retired without effect, 0 changed mcycle
VIOLATED: R7 (Traps and interrupts): a guest write to mcycle in M-mode departs from the RISC-V privileged spec (mcycle is MRW) and the manual must document that deviation
run.sh: R3-VARSPEC-2: exit 1 (bug present)
```
