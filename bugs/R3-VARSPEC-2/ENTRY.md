## R3-VARSPEC-2

**Title.** An M-mode write to `mcycle` raises an illegal-instruction exception, a departure from the RISC-V privileged specification that the manual does not document

**Severity.** Medium

### Problem

The RISC-V privileged specification defines `mcycle` (CSR `0xB00`) as an MRW register, so M-mode may write it.
The emulator does not allow this. `write_csr_mcycle` always returns `execute_status::failure`, so every CSR
instruction that writes `mcycle` raises an illegal-instruction exception at every privilege level, M-mode included:
`csrrw`, `csrrs` and `csrrc` with a nonzero `rs1`, and `csrrwi`, `csrrsi` and `csrrci` with a nonzero immediate.
The exception has `mcause` 2 and `mtval` set to the instruction.

The behavior is deliberate. The code comment says that `mcycle` measures the progress of the machine.
THREAT_MODEL.md R8 also requires it: the guest "can never change the cycle counter". So the behavior itself is right.
The defect is that the manual says nothing about it. R7 permits a departure from the RISC-V specification only
"where the manual documents a deviation". `doc/README.md` never says that `mcycle` is read-only, that writing it
traps, or that writes are ignored. "Limiting execution" calls it a CSR "that starts at 0 and is incremented after
every instruction cycle". "The main processor" says only that "its value is advanced at every CPU cycle".

A guest author who follows the manual and the specification would expect an M-mode `csrw mcycle` to retire. On the
emulator, the guest's M-mode trap handler is entered instead. The behavior is deterministic, and the native and uarch
paths agree on it, so the security goal is not affected. The defect is a rule violation in the manual's description
of the transition function.

### Component, role and area

The component is the interpreter's CSR file, which the uarch program shares through the same source, together with
the manual's description of the main processor. AUDIT.md lists "Interpreter, state-access layers, devices, uarch
program, ..." with the role "Honest operator". The area is the counter CSRs (Zicsr/Zicntr writability of `mcycle`).

### Location

- `src/interpret.cpp`: `write_csr_mcycle` (around line 2406) returns `execute_status::failure`. The `write_csr`
  dispatch (around line 2562) calls it for `csr::mcycle`. The sibling `write_csr_minstret` (around line 2397)
  accepts writes.
- `doc/README.md`: "The main processor" (the paragraph after the processor-shadow table, around line 7358) and
  "Limiting execution" (around line 920). Neither documents the deviation. The "System architecture" introduction
  promises that the section describes "the modifications made to support verification".

### Evidence and test

`bugs/R3-VARSPEC-2/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R3-VARSPEC-2`. It needs only the
in-tree emulator build and takes about one second.

The test builds a bare machine with 1 MiB of RAM that starts in M-mode at `0x80000000`, with `mtvec = 0x80000100`
and `x6 = 0x12345`. It runs one instruction twice: natively with `machine:run`, and on the uarch path with
`run_uarch` and `reset_uarch`. The two paths must reach the same root hash and pc, or the test exits 2. The
instructions are the writes `csrrw x0,mcycle,x6`, `csrrs x0,mcycle,x6`, `csrrc x0,mcycle,x6` and
`csrrwi x0,mcycle,5`, and two controls that must retire, `csrrw x0,minstret,x6` and `csrrs x7,mcycle,x0`.

The test then searches the prose of `doc/README.md`, with fenced code blocks removed, for a sentence that names
`mcycle` and says it is read-only, cannot be written, or that writing it traps, raises an exception or is ignored. It
exits 1 if a write traps or is ignored and no such sentence exists (R7), or if a write changes `mcycle` (R8). It exits
0 only when the manual documents the deviation and the guest cannot change `mcycle`.

Output on audit/prt2 (commit 14a26ae). The reviewer re-ran it twice and it exited 1 both times:

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

The reviewer also checked the test against the expected fix. `MANUAL_OVERRIDE` pointed at a copy of the manual with
one added sentence after the `mcycle` paragraph of "The main processor": "Unlike the RISC-V specification, which makes
it an MRW register, the guest cannot write `mcycle`: a CSR instruction that writes it raises an illegal-instruction
exception." With that copy the test exits 0. The tracked manual was not edited. Opus 5.5 found, proved and reviewed
the issue. No fallback model was used.

### Trigger and reachability

Any guest code running in M-mode can trigger it by executing a CSR write to `mcycle`. Section 4 says that an input
may take control of the firmware and "run any instruction stream at any privilege level", so the state is reachable
from any valid template. In U-mode and S-mode the same instruction also traps, but there the result does not depart
from the specification in the same way, because `mcycle` is an M-mode register.

### Rating

1. Out of scope: none applies. The defect needs no machine API call by an untrusted party, no deployment violation,
   no snapshot the emulator did not write, no O1 or O2 violation and no host fault. It is not a case of "Guest
   software that an input can subvert, as long as R7 and R8 hold", because the defect is the emulator's own
   departure from R7.
2. Role: the interpreter and the uarch program. AUDIT.md: "Interpreter, state-access layers, devices, uarch program,
   ... | Honest operator". This clause covers the component directly. Section 3: "The transition function ... play[s]
   this role in every deployment."
3. High and Medium cases: section 8 Medium, "An undocumented deterministic deviation, consistent across all paths, in
   behavior that no correct guest relies on for isolation or data integrity (R7)." This case fits:
   - The manual is silent, so the deviation is undocumented.
   - It is deterministic, and the test checks that native and uarch reach the same root hash.
   - Writing `mcycle` is not something a correct guest relies on for isolation or data integrity. R8 requires that the
     guest "can never change the cycle counter", so the threat model itself rules out any guest that depends on the
     write taking effect.

   The rating stops here: Medium.
4. Critical: not reached under the preferred reading. The rule violated is R7: "The emulator implements the RISC-V
   specification and the devices as the manual documents them, departing only where the manual documents a
   deviation."

Two readings give different classes:

- **Critical (literal R7).** The symptom is an unexpected trap, so the deviation could be placed in the R7 area
  "Traps and interrupts", where "any deviation lets an input subvert a correct guest, even a deviation that is
  consistent across all paths". Then the Medium case would not fit, and step 4 would rate it Critical. The preferred
  reading rejects this, for two reasons. First, the departure is in counter-CSR writability, and the trap is only how
  it shows. If every unexpected trap belonged to "Traps and interrupts", the Medium case could never apply to an
  instruction. Second, R8 requires the guest-visible behavior, so no correct guest can be subverted by it.
- **Low.** One could read R8 (in the threat model, not the manual), or the manual's general phrases ("the
  modifications made to support verification", "advanced at every CPU cycle"), as documenting the deviation. R7 asks
  for "the manual" to document it, and those phrases never say that a write traps, so this reading is weaker.

The deciding facts are whether counter writability belongs to the R7 area "Traps and interrupts", and whether
implicit wording in the manual counts as documenting a deviation.

### Possible solution and risks

Keep the behavior and document it in "The main processor" of `doc/README.md`. For example: "Unlike the RISC-V
specification, which makes it an MRW register, the guest cannot write `mcycle`: a CSR instruction that writes it raises
an illegal-instruction exception." The same section could list the other counter CSRs whose behavior departs from the specification, so that
guest authors have a single list. This is a documentation-only change. It
does not change the transition function, the uarch program, the step contracts or any hash, so it needs no new
protocol version (R13).

Changing the code instead is not an option. Making the write take effect would break R8. Silently ignoring it would
change the transition function (R13) and would still be a deviation that needs documenting.

### Risk of not fixing it

The security goal is not affected. All paths agree, and the guest cannot move the dispute clock. The risk is to
guest authors: M-mode firmware written to the specification, for example code that resets or preloads the cycle
counter, takes an unexpected illegal-instruction trap. The resulting misbehavior is deterministic and affects only
that guest's own correctness. Until the manual is fixed, the only mitigation is this entry or the code comment in
`write_csr_mcycle`.
