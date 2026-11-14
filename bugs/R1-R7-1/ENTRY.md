## R1-R7-1

**Title.** The LR/SC reservation is keyed by virtual address and survives `satp` writes and `sfence.vma`, so after a remap an SC succeeds on a physical word in another 4 KiB page that the LR never reserved.

**Severity.** Critical (R7, "Atomics and fences" and "Address translation", read as written). Medium under a narrower reading. See Rating.

### Problem

`execute_LR` stores the **virtual** address of the access in `ilrsc`. `execute_SC` succeeds whenever
`ilrsc == vaddr`. Only three places write `ilrsc`: LR, SC (which always clears it) and `set_prv` (traps, `sret`,
`mret`). A `satp` write (`write_csr_satp`) and `sfence.vma` (`execute_SFENCE_VMA`) leave it unchanged. Take a hart
that runs `lr.d` at VA V (physical P1), then remaps V to P2 in another physical page without a trap or xRET (a
`csrw satp` or a store to the leaf PTE, then `sfence.vma`), then runs `sc.d` at V. The SC succeeds (rd = 0) and
writes P2.

The RISC-V specification forbids this:

- Privileged spec, Sv32 section, inherited by Sv39: "For implementations with both page-based virtual memory and the A
  standard extension, the LR/SC reservation set must lie completely within a single base physical page (i.e., a
  naturally aligned 4 KiB physical-memory region)."
- Unprivileged A/Zalrsc: "The SC must fail if the address is not within the reservation set of the most recent LR in
  program order". When an SC fails, it "does not write to memory, and it writes a nonzero value to rd".

P2 lies in a different physical page from P1, so it cannot be in the reservation set, and the SC must fail.

The manual (doc/README.md, "The main processor") says the main processor implements `RV64IMAFDCZicsr_Zifencei` with
Sv39. It describes `ilrsc` only as the register that "holds the reservation address for the LR/SC atomic memory
operations". It documents no deviation here. The behavior is deterministic and the same on every path: native
interpretation and the uarch reach the same root hash, and the regenerated step replays the uarch. So nothing breaks
in the dispute. The defect is an architectural deviation in an area that R7 lists ("Atomics and fences"; "Address
translation and memory permissions"). There, R7 says "any deviation lets an input subvert a correct guest, even a
deviation that is consistent across all paths". A guest that relies on the specified LR/SC semantics can complete a
read-modify-write on a word it never load-reserved.

### Component, role and area

The interpreter (main-processor A extension and Sv39 address translation). The uarch program compiles the same
`interpret.cpp`, and the regenerated machine-solidity-step implements the uarch, so all of them show the same
behavior. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". The
regenerated step is "Referee verifier". It shows the deviation only because it faithfully implements the same state
transition function, not because its verification is unsound.

### Location

`src/interpret.cpp`:

- `execute_LR` (around line 1292): `a.write_ilrsc(vaddr)`.
- `execute_SC` (around line 1313): `if (a.read_ilrsc() == vaddr) { ...write_virtual_memory... }`.
- `set_prv` (around line 380): the only other place that clears `ilrsc`.
- `write_csr_satp` (around line 2233) and `execute_SFENCE_VMA` (around line 3574) do not touch `ilrsc`.

### Evidence and test

`bugs/R1-R7-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-R7-1`, which takes under a second.

The test builds a bare machine with 1 MiB of RAM, two Sv39 roots, and code at VA 0x5000. It runs in S-mode with
`mie = 0` and `mstatus.MIE = 0`. It checks that every program reaches its final `j .` at pc 0x5010, still in S-mode,
so no trap happened. P1 = 0x80020000 and P2 = 0x80021000 both start at 0x1111, and the SC stores 0x9999. Each case
runs twice: natively (`run`) and through the uarch (`run_uarch` plus `reset_uarch` per mcycle). The two runs must
reach equal root hashes, or the test exits 2. The cases are these.

- **Baseline.** `lr.d; nop; nop; sc.d` with no remap. It must succeed, or the test exits 2. The reviewer added this
  case.
- **Control, per variant.** The same program as the remap case, but the "remap" keeps VA 0x1000 on P1. The result
  must be consistent (success writes P1, failure writes nothing, P2 is untouched), or the test exits 2. The reviewer
  relaxed this check. The prover's version required success, but the spec allows that SC to fail, and the
  invalidate-on-remap fix makes it fail.
- **Remap, variant `satp`.** `lr.d x6,(x5); csrw satp,x7; sfence.vma; sc.d x9,x8,(x5)`. The new root maps VA 0x1000
  to P2.
- **Remap, variant `pte`.** The `csrw` is replaced by `sd x10,0(x11)`, which overwrites the leaf PTE of VA 0x1000
  through a mapping of the leaf table.

In both remap variants the test asserts that `x9 != 0`, that P1 is 0x1111 and that P2 is 0x1111. On audit/prt2 it
exits 1, deterministically: three runs by the prover and three by the reviewer gave the same result. It prints:

```
baseline (native)            pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
baseline (uarch)             pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp control (native)        pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp control (uarch)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp remap   (native)        pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
satp remap   (uarch)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
VIOLATED: satp: R7 (Atomics; Address translation): after LR at VA 0x1000 (P1) and a remap of VA 0x1000 to P2 in another 4 KiB physical page, the SC lies outside every legal reservation set and must fail (rd != 0) without writing memory
pte control (native)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
pte control (uarch)          pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
pte remap   (native)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
pte remap   (uarch)          pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
VIOLATED: pte: R7 (Atomics; Address translation): after LR at VA 0x1000 (P1) and a remap of VA 0x1000 to P2 in another 4 KiB physical page, the SC lies outside every legal reservation set and must fail (rd != 0) without writing memory
run.sh: R1-R7-1: exit 1 (bug present)
```

The test exits 0 under either fix below: keying the reservation by physical address, or invalidating it on `satp`
writes and `sfence.vma`. All agents ran on the primary model, with no fallback.

### Trigger and reachability

The guest triggers it. It needs code that runs, in S-mode (or in M-mode with `mstatus.MPRV`), an LR, a change of
translation for the reserved virtual address, and an SC to the same virtual address, with no trap and no xRET in
between. Every trap, `sret` and `mret` calls `set_prv` and clears the reservation.

The state is reachable. Section 4 says "Any input may take control of the firmware, the kernel, ... It may then run
any instruction stream at any privilege level", and section 2 says "Any assignment of guest-writable memory and
registers is presumed reachable". Page tables, `satp` (written through instruction semantics) and the code all lie
in guest-writable RAM and registers. The test sets them through the machine API only for brevity. A valid template
running an S-mode kernel can execute the same instruction sequence.

A user-mode program cannot trigger the remap without a trap. The exception is a U-mode store to a page table that
the kernel maps writable to it, which a correct kernel does not do.

### Rating

1. Out of scope: no. The trigger is guest instructions, not a machine API call. "The effect of a deliberate state
   change made through the machine API" does not apply: the test uses the API only to set up guest-writable state,
   which a guest can produce itself. "Guest software that an input can subvert, as long as R7 and R8 hold" does not
   apply either, because R7 itself does not hold. No snapshot, reload, host fault or deployment obligation is
   involved.
2. Role: the interpreter, plus the uarch program built from it. AUDIT.md: "Interpreter, ... uarch program, ... |
   Honest operator". Section 3: "The transition function, its log producers, ... play this role in every
   deployment." That clause covers this component. The regenerated step ("Referee verifier") shares the semantics
   but stays sound with respect to the state transition function as implemented, so the role does not raise the
   rating beyond what R7 gives.
3. High and Medium cases: no High case fits. The paths do not diverge (they agree), and the state is reachable. The
   candidate Medium case is "An undocumented deterministic deviation, consistent across all paths, in behavior that
   no correct guest relies on for isolation or data integrity (R7)". The deviation is undocumented, deterministic and
   consistent across paths. But R7 says "A correct guest relies on the architecture for isolation and data integrity
   in the areas listed below. In these areas, any deviation lets an input subvert a correct guest, even a deviation
   that is consistent across all paths", and lists "Address translation and memory permissions" and "Atomics and
   fences". LR/SC reservation semantics under address translation fall in both areas. So under the text as written,
   the Medium case, which covers behavior "no correct guest relies on", does not fit.
4. Critical: this violates R7 at a reachable state. R7 says "The emulator implements the RISC-V specification ...
   departing only where the manual documents a deviation", and the manual documents none for LR/SC. Section 8 says
   "violating any rule or obligation at a reachable state ... is critical". Under the reading in steps 3 and 4,
   **Critical**.

**Second reading: Medium.** The Medium case can instead be read as a question of fact about this particular
behavior. On that reading it fits, and the rating is **Medium**, if no correct guest actually relies on an SC failing
after a remap made between its own LR and SC with no trap. The facts for this reading:

- Every trap and xRET already clears the reservation. So a user-mode victim is never exposed through a kernel remap,
  and preemption also clears it.
- Only S-mode or M-mode code that remaps between its own LR and SC sees the deviation.
- The Zalrsc text recommends that software invalidate reservations with a scratch SC "if necessary when changing
  virtual to physical address mappings". Linux follows that advice on exception return.

That reading would settle on Medium if one could show that no supported guest software (kernel, OpenSBI or bare-metal
runtime) remaps inside an LR/SC window. The categorical wording of R7 ("any deviation ... even a deviation that is
consistent across all paths"), which answers exactly the Medium case's argument, supports the first reading better.
Both readings rate it Medium or above.

### Possible solution and risks

There are two options.

- **Clear `ilrsc` on every `satp` write and every `sfence.vma`** (in `write_csr_satp` and `execute_SFENCE_VMA`). This
  is the smaller change. The spec allows an SC to fail at any time outside the constrained LR/SC loop, and SYSTEM
  instructions and stores end that loop, so this fix never breaks forward progress. It does not cover a remap by a
  plain store to a PTE that is still cached in the TLB with no `sfence.vma`. That case is fine: the stale translation
  is architectural, the SC then still goes to P1, and that is allowed.
- **Store the physical address of the LR access in `ilrsc`, and compare it with the translated physical address in
  SC.** This follows the spec directly. It needs a translation before the comparison, and it changes the state
  accesses that SC logs.

Either fix changes the state transition function, and so the uarch program, its pristine hash, the regenerated step
and the logged accesses (R13). It needs a new protocol version and a new `marchid`. It must not be mixed with
deployed versions (A6).

### Risk of not fixing it

The dispute game itself is not exposed: every path computes the same (non-compliant) successor, so claims, proofs
and verification still agree. The exposure is a correct guest that relies on the specified atomics under address
translation. It can see an SC succeed on a word that was never load-reserved, and silently corrupt that word's
read-modify-write. Only code running in S-mode or M-mode that changes the mapping between its own LR and SC can
trigger it. Guest software can mitigate it by issuing an SC to a scratch word after every remap, as the spec
recommends.
