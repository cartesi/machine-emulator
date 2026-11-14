## R9-SUBTLB-1

**Title.** SRET from S-mode to S-mode clears `mstatus.MPRV` without flushing the read/write TLB, so S-mode with SUM=0
keeps accessing U pages through translations filled at effective privilege MPP=U.

**Severity.** Critical (preferred: per-register reading of the valid-template register condition) / Medium (if a
template in S-mode with MPRV=1 is not a valid template).

### Problem

`execute_SRET` follows the privileged specification and clears `mstatus.MPRV` when SPP < M ("An MRET or SRET
instruction that changes the privilege mode to a mode less privileged than M also sets MPRV=0"). It flushes the TLB
only through `set_prv`, which it calls only when the privilege changes (`prv != spp`). When the hart is in S-mode with
MPRV=1 and MPP=U, and SRET returns to S (SPP=S), the effective privilege of loads and stores changes from U to S, but
the read and write TLB sets keep entries that were filled and permission-checked at effective privilege U. A later
S-mode load or store with SUM=0 to a U page then hits the stale entry and completes, where the specification requires
a page fault ("When SUM=0, S-mode memory accesses to pages that are accessible by U-mode will fault"). The emulator
handles the analogous cases elsewhere: `execute_MRET` flushes the read/write TLB when it returns to M with MPRV still
set, `raise_exception` does the same for a trap taken in M with MPRV set, and the `mstatus` CSR write flushes on MPRV,
MPP, SUM and MXR changes. SRET is the one path that changes the effective data privilege without a flush.

The deviation is deterministic and consistent across paths (native run and uarch run agree), so it does not produce
a hash disagreement. It is a deviation of the state transition function itself from the RISC-V specification, in
"Address translation and memory permissions", an area where R7 says "any deviation lets an input subvert a correct
guest, even a deviation that is consistent across all paths". A guest that relies on SUM=0 to keep S-mode code from
touching U memory after returning from such an SRET is not protected.

### Component, role and area

The interpreter (`execute_SRET`), shared by native execution, the uarch program (which runs the same interpreter),
the log producers, and the referee verifier regenerated from it. Role: Honest operator (AUDIT.md: "Interpreter,
state-access layers, devices, uarch program, ..."). Area: address translation and memory permissions (TLB
maintenance on a change of the effective data privilege). Machine creation (accepting `iprv=S` with MPRV=1) is the
other component involved; it has the same role.

### Location

- `src/interpret.cpp`, `execute_SRET` (lines ~2802-2828): clears MPRV, calls `set_prv` only when `prv != spp`, no TLB
  flush otherwise.
- For comparison: `execute_MRET` (~2832-2866, `else if (mstatus & MSTATUS_MPRV_MASK)` flush branch),
  `raise_exception` (~496-504), the `mstatus` write (~2331-2337).
- `src/translate-virtual-address.hpp` (~118-122): data accesses use MPP when MPRV=1, in any privilege mode.

### Evidence and test

`bugs/R9-SUBTLB-1/` contains:

- `test.lua` (run by `bugs/run.sh R9-SUBTLB-1`): creates a machine from a configuration with `iprv=1` (S), `mstatus`
  MPRV=1, MPP=U, SPP=S, SUM=0, Sv39 `satp`, `medeleg` delegating page faults to an S handler, and a hand-encoded guest
  (no toolchain). The guest loads from a U page at VA 0xC0002000 (succeeds at effective privilege U and fills the
  read TLB), executes `sret` (sepc = next instruction, stays in S, MPRV becomes 0), then loads the same VA again. The
  test requires the second load to raise a load page fault (scause 13, sepc = the load, stval = the VA). A control
  variant with `sfence.vma` before the second load faults as required, which shows a page walk refuses the access and
  the stale TLB entry is what lets it through. The bug variant is also run through `run_uarch` + `reset_uarch` per
  mcycle and compared (informational). The test also exits 0 under the alternative fixes "creation refuses iprv != M
  with MPRV=1" and "MPRV ignored outside M-mode".
- `reach-from-template.lua` (informational, not run by `run.sh`): the same guest first loads the U page, then yields
  manually with the accepted reason through HTIF while still in S-mode with MPRV=1. The machine is stored, reloaded,
  an advance-state input is delivered with `send_cmio_response` (revert root hash = the root hash), and the guest
  runs `sret` and the second load. It prints `stage=3 trap=0 scause=0 t2=0x1122334455667788 MPRV=0 iprv=1`: the stale
  entry survives store/load and the delivery, and the second load completes.
- `README.md`: description of the test.

`bugs/run.sh R9-SUBTLB-1` on audit/prt2 (three runs by the reviewer, identical, exit 1, about 0.1 s):

```
native, no flush:            stage=3 trap=0 scause=0 sepc=0x0 stval=0x0 t0(1st ld)=0x1122334455667788 t2(2nd ld)=0x1122334455667788 MPRV=0 iprv=1
native, sfence.vma (control): stage=2 trap=1 scause=13 sepc=0x80000014 stval=0xc0002000 t0(1st ld)=0x1122334455667788 t2(2nd ld)=0x0 MPRV=0 iprv=1
uarch, no flush:             stage=3 trap=0 scause=0 sepc=0x0 stval=0x0 t0(1st ld)=0x1122334455667788 t2(2nd ld)=0x1122334455667788 MPRV=0 iprv=1
uarch and native agree on the bug variant
the second load completed in S-mode with SUM=0 on a U page (stale read-TLB entry filled at effective privilege U before SRET cleared MPRV); with sfence.vma it faults
VIOLATED: R7 (address translation and memory permissions): after SRET clears MPRV, an S-mode load with SUM=0 from a U page must raise a load page fault (scause 13, stval = VA)
run.sh: R9-SUBTLB-1: exit 1 (bug present)
```

Reviewed on Opus 5.5; the reviewer used no fallback model.

### Trigger and reachability

Guest instructions cannot produce S-mode with MPRV=1 from an M-mode start: only M-mode writes `mstatus`, MRET and
SRET to a mode below M clear MPRV, and traps never lower the privilege. The state is produced by the template's
configuration: machine creation accepts `iprv=1` together with `mstatus.MPRV=1`, each a value the specification
defines (the privileged specification defines MPRV=1 as "translated and protected ... as though the current privilege
mode were set to MPP" without restricting it to M-mode, and in v1.10, which the manual links, MRET/SRET do not clear
MPRV, so S-mode with MPRV=1 is an ordinary state there). From such a template, which can wait at a manual yield with
the accepted reason with the stale entry already in its TLB (`reach-from-template.lua`), the delivery of any input
leads to the deviation. No input content is needed; the guest's own code triggers it.

### Rating

1. Out of scope: no exclusion applies. The trigger is a machine created from a configuration and then run and fed
   inputs, not "a snapshot that the emulator did not write", not "an untrusted party [calling] the machine API", and
   not "The effect of a deliberate state change made through the machine API" (the state change is the guest's SRET).
   "Guest software that an input can subvert, as long as R7 and R8 hold" does not apply, because R7 is what fails.
2. Role: the interpreter and the uarch program are Honest operator (AUDIT.md row 1); section 3: "The transition
   function, its log producers, ... play this role in every deployment." The regenerated referee verifier implements
   the same transition function, so no verifier-only defect is involved.
3. High and Medium cases: no High case fits (no divergence between paths, no crash, no verifier misbehaviour). The
   Medium case "An undocumented deterministic deviation, consistent across all paths, in behavior that no correct guest
   relies on for isolation or data integrity (R7)" fits only if no correct guest can be in this state; the behaviour
   (permission checks under "Address translation and memory permissions") is one R7 lists as relied on.
4. Critical: R7, "The emulator implements the RISC-V specification ... departing only where the manual documents a
   deviation. ... In these areas, any deviation lets an input subvert a correct guest, even a deviation that is
   consistent across all paths. ... Address translation and memory permissions." The manual documents no TLB or MPRV
   deviation. The state is reachable if a template in S-mode with MPRV=1 is a valid template: section 2, "Its
   registers hold only values that the RISC-V specification and the manual allow for them."

Two readings. (a) Per-register reading (preferred): `iprv=1` and `mstatus` with MPRV=1, MPP=U, SPP=S are each values
the specification allows, so a configuration-made template that yields in that state is valid, the state is reachable
(shown by `reach-from-template.lua`), the Medium case does not fit (correct guests rely on memory permissions), and
step 4 gives Critical by R7. (b) Combination reading: the specification never lets a hart reach S-mode with MPRV=1
(1.11+), so no valid template holds it, the state is unreachable, and the Medium deviation case applies, which per the
settled readings "has no reachability condition", giving Medium. What decides: whether "values that the RISC-V
specification and the manual allow for them" constrains combinations of register values reachable from reset, or
only each register's legal values.

### Possible solution and risks

In `execute_SRET`, when SRET clears MPRV that was set and MPP differs from the new privilege (`spp`), flush
`TLB_READ` and `TLB_WRITE` even when `prv == spp`, mirroring the `execute_MRET` branch (the simplest form flushes
whenever MPRV was set and `prv == spp`). Alternatively, refuse at machine creation any configuration with `iprv != M`
and MPRV=1. The flush changes the state transition function (the shadow TLB is hashed state), so it needs a new
protocol version, a regenerated `machine-solidity-step` and a new uarch pristine hash (R13, A6). The creation check
could reject configurations that some tool produces today.

### Risk of not fixing it

A deployment whose template starts the guest in S-mode with MPRV=1 (only possible through a hand-written
configuration; Linux images boot in M-mode and never reach the state) runs a transition function in which S-mode code
can read and write U pages with SUM=0 after such an SRET, until the next TLB flush. An input that reaches that code
path subverts the guest's S/U isolation. All honest operators and verifiers agree on the wrong semantics, so claims
and proofs are unaffected. Mitigation outside the code: do not create templates outside M-mode with MPRV set, or
execute `sfence.vma` after such an SRET.
