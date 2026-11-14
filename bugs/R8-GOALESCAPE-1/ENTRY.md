## R8-GOALESCAPE-1

**Title.** An AMO translates its address twice, once for its load and once for its store. So one AMO can load from one physical page and store to another, and an AMO on its own PTE clears the dirty bit that its store needs.

**Severity.** Critical (R7, "Atomics and fences" and "Address translation and memory permissions", read as written, as for R1-R7-1). Medium under the narrower reading of the Medium case. See Rating.

### Problem

`execute_AMO` in `src/interpret.cpp` runs an AMO as two independent accesses. It first calls
`read_virtual_memory<T, STATE_ACCESS, true>(vaddr)`, which looks up the read TLB set and, on a miss, runs a read-type
`translate_virtual_address` walk. It then calls `write_virtual_memory<T>(vaddr, result)`, which looks up the write TLB
set and, on a miss, runs its own store-type walk. Each walk sets the leaf PTE's A bit (and D for the store walk) after
its own permission check (`src/translate-virtual-address.hpp`, the `pte_update_mode::update` branch).

The RISC-V specification defines an AMO as a single access. The A extension says an AMO atomically loads from the
address in rs1 and stores the result "back to the original address". The RVWMO model says an aligned AMO gives rise to
a single memory operation that is both a load and a store. The privileged spec translates each access once, and an AMO
is translated as a store/AMO access. The specification allows stale translations (no `sfence.vma`), but each access
uses one translation, old or new. The manual (doc/README.md, "The main processor") says the processor implements
`RV64IMAFDCZicsr_Zifencei` with Sv39, and it documents no deviation for AMOs or for A/D updates.

The double translation produces two deviations that the test observes.

- **(A) An AMO that is not atomic on any location.** A guest maps V to P1 and loads from V, which fills the read TLB
  with V->P1. It then changes the PTE to point at P2, without `sfence.vma`, and stores to V+8, which refills the
  write TLB with V->P2. Then `amoadd.d rd, 1, (V)` loads 100 from P1 and stores 101 to P2. P1 is left unchanged, and
  P2's 200 is overwritten although the AMO never read it. A single translation gives one of two results: P1 = 101 with
  rd = 100, or P2 = 201 with rd = 200.
- **(C) A lost dirty bit.** A guest runs an AMO on the PTE word that maps its own page, with that PTE's A = 0, D = 0
  and W = 1. The read walk sets only A, and the AMO loads the half-updated PTE (`...47`). The write walk then sets
  A and D (`...c7`), and the AMO's store writes `...47` back, so D ends clear although the page was just written. With
  one store/AMO translation, A and D are set before the access. The AMO then reads and writes back `...c7`. The spec
  says D updates are exact and observed in program order by the local hart, and that the AMO's load and store are
  atomic, so D must end set.

The hunter also reported a spurious A bit on an AMO that raises a store page fault, and a D bit set by a failed SC.
The test does not assert either. The spec allows A to be set speculatively, so the first is not a deviation. The
second turns on how a failed SC is translated, so it was left out.

Every path computes the same result: native interpretation and the uarch (which compiles the same `interpret.cpp`)
reach equal root hashes, and the regenerated step replays the uarch. No claim, proof or verification diverges. The
threat runs through R7. A correct guest relies on an AMO being one atomic read-modify-write of one location, and on
the dirty bit recording every write. Here an AMO silently overwrites a word it never read, and a write can be missing
from dirty tracking. R7 says that in these areas "any deviation lets an input subvert a correct guest, even a
deviation that is consistent across all paths".

### Component, role and area

The interpreter (A extension and Sv39 address translation), and the uarch program built from the same source. The
AUDIT.md table says "Interpreter, state-access layers, devices, uarch program, ... | Honest operator". The regenerated
machine-solidity-step ("Referee verifier") shares the semantics only because it implements the same state transition
function. Its verification stays sound.

### Location

- `src/interpret.cpp`, `execute_AMO` (about lines 1358-1379): `read_virtual_memory<T, STATE_ACCESS, true>` (line 1364),
  then `write_virtual_memory<T>` (line 1369), on the same `vaddr`.
- `src/interpret.cpp`, `read_virtual_memory` (about line 1051, `TLB_READ`) and `write_virtual_memory` (about line 1171,
  `TLB_WRITE`): separate TLB sets, and a separate slow-path walk for each.
- `src/translate-virtual-address.hpp`, `translate_virtual_address` (line 113): the A/D update (lines 239-243) is done
  per walk, after that walk's own permission check.

### Evidence and test

`bugs/R8-GOALESCAPE-1/` contains three files.

- `amo.c` is a bare-metal guest. It sets up Sv39 with identity gigapages and one leaf table, then drops to S-mode and
  runs scenario A, scenario C, and a control AMO on a page whose translation never changes. It writes the results to
  a fixed physical array at 0x80920000 and halts through HTIF.
- `test.lua` builds `amo.c` with `bugs/harness/baremetal/build.sh` into a temporary directory and boots it as a
  64 MiB bare-metal machine. It runs the machine to halt and reads the results.
  - It exits 2 (setup error) if the store to V+8 did not refill the write TLB to P2, or if the control AMO is not
    atomic (old 300, new 301).
  - It asserts (A): the AMO is atomic on P1 (old 100, P1 101, P2 200) or on P2 (old 200, P2 201, P1 100).
  - It asserts (C): the self-mapping PTE has D (0x80) set after the AMO.
  - It also runs the same machine with `run_uarch` and `reset_uarch` per mcycle and prints whether the final root
    hashes are equal. This is informational.
- `README.md` explains the scenarios.

Run it with `bugs/run.sh R8-GOALESCAPE-1`, which takes a few seconds. On audit/prt2 it exits 1 deterministically:
three runs by the prover and three by the reviewer gave the same output. It prints:

```
native/uarch final root hashes equal: true
scenario A: amo old=100  P1=100 (pre 100)  P2=101 (pre 200)
scenario C: self-mapping PTE after AMO = 0x20200847  (D bit 0x80 = 0)
control  : consistent-translation AMO old=300  PC=301 (pre 300) -> atomic
VIOLATED: R7 (Atomics and fences; Address translation): an AMO is one atomic access on a single address -- it must load and store the same physical location
VIOLATED: R7 (Address translation and memory permissions): an AMO that stores to the page its own PTE maps must leave that PTE's dirty bit set
run.sh: R8-GOALESCAPE-1: exit 1 (bug present)
```

Both assertions accept every behavior that the specification allows. (A) accepts either the old or the new
translation, and (C) only requires the final D bit that a single store/AMO translation gives. So a fix that translates
each AMO once, as a store/AMO access, makes the test exit 0. The reviewer did not change the test. The fix was argued
from the code, not built. All agents ran on the primary model, with no fallback.

### Trigger and reachability

The guest triggers it. Code running in S-mode, or in M-mode with `mstatus.MPRV`, does one of two things under Sv39.

- It changes a PTE without `sfence.vma` while the read and write TLB sets hold different translations for the page,
  then runs an AMO (A).
- It runs an AMO on a PTE that maps its own page while that PTE's D bit is clear (C).

The state is reachable. Section 4 says "Any input may take control of the firmware, the kernel, ... It may then run
any instruction stream at any privilege level". Section 2 says "Any assignment of guest-writable memory and registers
is presumed reachable". The page tables, `satp` and the code are guest-writable. The guest fills both TLB sets through
instruction semantics, as R8 allows. The test reaches both states in about 4,700 mcycles from a freshly created
machine, with no machine-API write of state.

### Rating

1. Out of scope: no. The trigger is guest instructions in a reproducible machine. "The effect of a deliberate state
   change made through the machine API" does not apply, because the test uses the API only to create and run the
   machine. "Guest software that an input can subvert, as long as R7 and R8 hold" does not apply, because R7 itself
   does not hold. No snapshot, reload, host fault, unreproducible mode or deployment obligation is involved.
2. Role: the interpreter and the uarch program. AUDIT.md says "Interpreter, ... uarch program, ... | Honest operator".
   Section 3 says "The transition function, its log producers, ... play this role in every deployment". That clause
   covers this component.
3. High and Medium cases: no High case fits, because the paths agree and the state is reachable. The candidate Medium
   case is "An undocumented deterministic deviation, consistent across all paths, in behavior that no correct guest
   relies on for isolation or data integrity (R7)". The deviation is undocumented, deterministic and consistent across
   paths. But R7 says "A correct guest relies on the architecture for isolation and data integrity in the areas listed
   below. In these areas, any deviation lets an input subvert a correct guest, even a deviation that is consistent
   across all paths". It lists "Address translation and memory permissions" and "Atomics and fences". AMO atomicity
   and the A/D update of an AMO's translation fall in both areas. So, as written, the Medium case does not fit.
4. Critical: R7 is violated at a reachable state. R7 says "The emulator implements the RISC-V specification ...
   departing only where the manual documents a deviation", and the manual documents none here. Section 8 says
   "violating any rule or obligation at a reachable state ... is critical". **Critical** under this reading.

**Second reading: Medium.** The Medium case can be read as a question of fact about this behavior: does any correct
guest actually rely on it? The facts for that reading are these.

- (A) needs a PTE that maps a page to a different physical page while the old translation is still cached, with no
  `sfence.vma` between the change and the AMO. Linux breaks or remaps a valid mapping with a clear-and-flush first.
- (C) needs a page table that maps itself. Linux never builds one, though recursive page-table schemes in other
  kernels do.

If no supported guest software (kernel, OpenSBI or bare-metal runtime) reaches either state, the rating is
**Medium**. R7's categorical wording answers exactly that argument for the listed areas, so the first reading is
better supported. The same split, with the same preference, was applied to the confirmed R1-R7-1 (LR/SC reservation
under remap). Both readings rate it Medium or above.

### Possible solution and risks

Translate an AMO once, as a store/AMO access, and use the resulting physical address for both the load and the store.
For example, add an AMO path that looks up only the write TLB set and, on a miss, runs one store-type walk (which
checks write permission, raises the store/AMO page fault, and sets A and D before the access). Then do the load and
the store through that one physical address. Device ranges must keep their current AMO handling, or reject AMOs where
the PMA does not allow them. The same review applies to the failed-SC path, which runs a store walk with `skip_write`.

The fix changes the state transition function: the interpreter, the uarch program, its pristine hash, the regenerated
step, and the accesses each AMO logs (R13). It needs a new protocol version and `marchid`, and it must not be mixed
with deployed versions (A6). The risk is mainly in the logged access order, which the Solidity step must reproduce
exactly.

### Risk of not fixing it

The dispute game itself is not exposed: every path computes the same (non-compliant) successor, so claims, proofs and
verification agree. The exposure is a correct guest that relies on the specified atomics and dirty-bit semantics under
address translation. Such a guest can see an AMO that overwrites a word it never read, or a write that its dirty
tracking misses, and then lose data. Only S-mode or M-mode (MPRV) code can produce the triggering states. Guest
software can avoid them by executing `sfence.vma` after every PTE change before any AMO to the page, and by not
running AMOs on self-mapped page-table entries.
