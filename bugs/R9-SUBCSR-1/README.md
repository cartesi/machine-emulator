# R9-SUBCSR-1: PMP CSRs raise illegal instruction in M-mode. Does not reproduce as a deviation.

## Claim

`read_csr` and `write_csr` in `src/interpret.cpp` have no case for `pmpcfg0`-`pmpcfg15` (0x3A0-0x3AF) or
`pmpaddr0`-`pmpaddr63` (0x3B0-0x3EF). So an M-mode CSR instruction on them raises an illegal-instruction exception
(mcause 2, mtval = the instruction). The claim says this is an undocumented R7 deviation, because the PMP CSRs
should read as WARL read-only zero.

## Result: the trap is what the specification allows

The observation is correct, but it is not a deviation. The privileged specification lets an implementation have
zero PMP CSRs, and it requires an access to a non-existent CSR to trap as an illegal instruction. The text below was
checked against the tagged sources of `riscv/riscv-isa-manual`.

- **v1.10**, the version the manual links to (`src/machine.tex`, "Physical Memory Protection CSRs"):
  > Up to 16 PMP entries are supported. If any PMP entries are implemented, then all PMP CSRs must be implemented,
  > but all PMP CSR fields are WARL and may be hardwired to zero. PMP CSRs are only accessible to M-mode.

  The requirement applies only if some PMP entry is implemented. `src/priv-csrs.tex` adds:
  > Attempts to access a non-existent CSR raise an illegal instruction exception.

  The same text is in v1.11 (Ratified-IMFDQC-and-Priv-v1.11).
- **v1.12** (`Priv-v1.12`, `src/machine.tex`):
  > Implementations may implement zero, 16, or 64 PMP CSRs; the lowest-numbered PMP CSRs must be implemented first.
  > All PMP CSR fields are WARL and may be read-only zero.

  The non-existent-CSR sentence is the same as in v1.10.
- **20240411 and the 2026-11-09 release**: "Implementations may implement zero, 16, or 64 PMP entries". Also:
  "Instructions that access a non-existent CSR are reserved."

The brief's quote "All PMP CSR fields are WARL and may be read-only zero" applies to PMP CSRs that are implemented.
v1.12 says plainly that zero PMP CSRs may be implemented. The riscv-tests environment (`riscv-test-env`,
`p/riscv_test.h`, `INIT_PMP`) points `mtvec` past its `csrw pmpaddr0`/`csrw pmpcfg0` because those CSRs may not
exist. QEMU also raises illegal instruction for PMP CSRs when PMP is disabled.

The emulator implements zero PMP entries and therefore no PMP CSRs. Trapping is the specified behavior, so no
deviation needs to be documented. This differs from the hpmcounter case (R1-R7-3) in where the permission comes
from, but the outcome is the same: an access to a non-existent CSR may trap.

## What `test.lua` asserts

The test builds one bare machine (1 MiB RAM, M-mode) for each of the 80 PMP CSR addresses. Each runs
`li a1,-1; csrrw a0,<csr>,a1; csrr a2,<csr>; j .`, with `mtvec` pointing at `j .`. The test checks:

1. On RV64, the odd `pmpcfg` CSRs are illegal and must trap. (v1.10: "pmpcfg1 and pmpcfg3 are illegal". v1.12:
   "For RV64, the odd-numbered configuration registers, pmpcfg1, pmpcfg3, ..., pmpcfg15, are illegal.")
2. The even `pmpcfg` CSRs and `pmpaddr0`-`63` either:
   - are all absent, and each access raises a precise illegal-instruction exception (pc = mtvec, mepc = the
     `csrrw`, mcause = 2, mtval = the instruction bits, `a0` not written, still in M-mode); or
   - exist, with the lowest-numbered ones (`pmpcfg0`, `pmpaddr0`) implemented first.

   Any other outcome fails the test.
3. R2: on the `pmpcfg0` program, the interpreter (`run`) and the uarch (`run_uarch` + `reset_uarch`) have the same
   root hash after each of the first 4 mcycles.

The test exits 1 if the PMP CSRs behaved in a way the specification forbids, such as an imprecise trap or a partial
set of CSRs. It also exits 1 if the interpreter and the uarch disagreed. It exits 2 on a setup error.

## How to run

```sh
bugs/run.sh R9-SUBCSR-1
```

## Expected output on audit/prt2 (2865afc)

```
pmpcfg(even)+pmpaddr: 72 trap with a precise illegal-instruction exception, 0 exist
OK: RV64: odd pmpcfg CSRs are illegal and must trap
OK: PMP CSRs: zero implemented (all non-existent, illegal instruction) or the lowest-numbered implemented first
observed: the machine implements zero PMP CSRs (every access is a precise illegal-instruction trap), which the privileged specification permits
OK: R2: interpreter and uarch agree after mcycle 1
...
OK: R2: interpreter and uarch agree after mcycle 4
run.sh: R9-SUBCSR-1: exit 0 (fixed / not reproduced)
```

Exit status 0: the candidate does not reproduce as a violation. The trap is real, but the privileged specification
permits it, so R7 has nothing to document. It runs in about 2 seconds.
