## R7-MANARCH-2

**Title.** The manual presents the processor and board shadow (`0x0-0xfff`) and the shadow TLB (`0x1000-0x6fff`) as address ranges visible to the main processor, each described by a PMA entry. The emulator gives them no PMA entry, and every guest load from them raises a load access fault.

**Severity.** Medium (preferred reading). Critical under a literal reading of R7's "any deviation" in "Address translation and memory permissions". Low if the manual's wording is read loosely (see Rating).

### Problem

`doc/README.md` says in four places that the main processor can see the processor shadow and the shadow TLB:

- "The main processor": "The processor makes its entire state available, externally and read-only, by mapping every
  register to the start of the physical address space (in the <i>processor shadow</i>, a 4KiB range)."
- "The board": "Devices are mapped to the processor's physical address space. The mapping can be seen in the following
  table". The table lists `0x00000000-0x00000fff` "Processor and board shadow" and `0x00001000-0x00006fff` "Shadow TLB".
- "Address ranges": "The address ranges visible to the main processor are mapped at fixed positions in its 64-bit
  physical address space. These are the ranges listed in the board mapping table ... and discoverable at runtime via
  the PMA array". It then names only the uarch shadow and the uarch RAM as "private address ranges, which are not
  accessible to the main processor".
- "PMAs": "Each address range visible to the main processor is described by an entry in the array of Physical Memory
  Attribute records (PMAs)". The driver-id table lists `PMA_SHADOW_STATE_DID` = 2. Only the uarch shadow's driver id is
  said to be reserved "for consistency" without an entry.

The emulator registers the shadow state for the hash tree only (`register_where{.hash_tree = true, .pmas = false}`).
So the guest-readable PMA array at `0x10000` has 8 entries (RAM, DTB, tx buffer, rx buffer, HTIF, CLINT, PLIC, PMA
array), none of them covering `0x0-0x6fff`. A main-processor load from `0x290` (`marchid`), `0x2f8` (`imcyclemax`),
`0x1000` or `0x6ff8` traps with `mcause` 5 (load access fault).

The emulator's behavior is the one the threat model requires: R8 says "Guest memory accesses cannot address the
processor registers, ... the cached translation state, the revert root hash, `imcyclemax`". So the defect is most
likely in the manual. The fault is deterministic, and native interpretation and the uarch agree on it and on the root
hash, so no hash, proof or verification changes. It does not threaten the goal of section 1. It is a contradiction
between the manual and the behavior on the guest's address map and memory permissions, a security-relevant point
(the R8 containment boundary), and section 8 makes such a contradiction a defect in one of the two.

### Component, role and area

The interpreter and state layout: the set of address ranges registered in the PMA array at machine creation, and the
interpreter's physical-memory access check that consults it. AUDIT.md table: "Interpreter, state-access layers,
devices, uarch program, ... | Honest operator". The other side of the contradiction is the manual (`doc/README.md`,
"The main processor", "The board", "Address ranges", "PMAs").

### Location

- `src/machine-address-ranges.cpp`, `machine_address_ranges` constructor (about line 315):
  `push_back(make_shadow_state_address_range(c.processor), register_where{.hash_tree = true, .pmas = false});`.
- `doc/README.md`: "The main processor" (about lines 7337-7339), "The board" table (about lines 7440-7441),
  "Address ranges" (about lines 7874-7890), "PMAs" (about lines 7894-7928).

### Evidence and test

`bugs/R7-MANARCH-2/` contains `test.lua` (the test), `README.md` (what it asserts, expected output, and the
reviewer's repair) and this entry. Run `bugs/run.sh R7-MANARCH-2` (under 1 s). No toolchain is needed.

The test decodes the PMA array of a machine with 4 MiB of RAM and checks for any entry covering `0x0-0xfff` and
`0x1000-0x6fff`, whatever its attributes. For each probe address it builds a hand-encoded M-mode guest (set `mtvec`,
then `ld a1, 0(a0)`) and requires the load to return the value the host reads at that address. A control load from the
PMA array (`0x10008`) must succeed, or the test exits 2. It then reads `doc/README.md` and checks whether the manual
still presents the two ranges as visible to the main processor: they are in the board table and not named in the
"Address ranges" or "PMAs" subsections. It exits 0 if the emulator matches the manual, or if the manual no longer
presents the ranges as visible. It exits 1 if both still disagree.

On audit/prt2 it exits 1 on every run (re-run six times by the reviewer). It prints:

```
PMA array: 8 entries
  start=0x80000000 length=0x400000 attributes=0x0fd
  ... (DTB, tx, rx, HTIF, CLINT, PLIC, and start=0x10000 length=0x1000 attributes=0x0a5)
PMA entry covering processor and board shadow 0x0-0xfff: NO
PMA entry covering shadow TLB 0x1000-0x6fff: NO
guest ld 0x10008 (control: PMA array, a range with a PMA entry): value 0x400000, shadowed value 0x400000
guest ld 0x290 (processor shadow, marchid (offset 0x290)): TRAP mcause=5 mtval=0x290
guest ld 0x2f8 (processor shadow, imcyclemax (offset 0x2f8)): TRAP mcause=5 mtval=0x2f8
guest ld 0x1000 (shadow TLB, first word): TRAP mcause=5 mtval=0x1000
guest ld 0x6ff8 (shadow TLB, last word): TRAP mcause=5 mtval=0x6ff8
manual presents 0x00000000-0x00000fff as visible to the main processor: yes
manual presents 0x00001000-0x00006fff as visible to the main processor: yes
manual: 'Each address range visible to the main processor is described by an entry ...' present: yes
VIOLATED: R7: the manual says the processor shadow and shadow TLB are address ranges visible to the main processor, each described by a PMA entry; the emulator gives them no PMA entry and a guest load faults
```

The reviewer repaired the test: the manual-side check searched only the "Address ranges" subsection; it now also
searches "PMAs", so a manual fix in either subsection is recognized. The result on audit/prt2 is unchanged. With a copy
of the manual that adds one sentence to "PMAs" ("The processor shadow (`0x00000000-0x00000fff`) and the shadow TLB
(`0x00001000-0x00006fff`) are likewise not accessible to the main processor."), the test exits 0. The reviewer also
checked that native interpretation and the uarch (one `run_uarch`/`reset_uarch` per mcycle) both end the
`imcyclemax` probe with `mcause` 5 and the same root hash. Found, proved and reviewed on `claude-opus-5-5`.

Side observation, rated separately as R3-VARSPEC-1: the manual's PMA attribute bit layout differs from
`src/pmas-constants.hpp`. The test ignores attribute bits for this reason.

### Trigger and reachability

There is nothing to trigger beyond a plain load. Every machine the emulator creates, every valid template included,
has no PMA entry for `0x0-0x6fff`. Any guest code at M-mode (or any privilege level whose translation reaches these
physical addresses) that follows the manual and reads a register from the processor shadow, or looks for a
`PMA_SHADOW_STATE_DID` entry, gets a load access fault or does not find the entry. No input sequence is needed. The
guests that ship with the emulator (OpenSBI and Linux) do not read the shadow.

### Rating

1. Out of scope: no exclusion applies. The trigger is a guest load in any machine. It needs no deliberate state change
   through the machine API ("The effect of a deliberate state change made through the machine API"), no untrusted API
   caller, no foreign snapshot, no reload of an unguaranteed directory, and no deployment violation of A1 to A8.
   "Guest software that an input can subvert, as long as R7 and R8 hold" does not apply: the question is R7 itself.
2. Role: the address ranges registered in the PMA array and the interpreter's access check belong to "Interpreter,
   state-access layers, devices, uarch program, ... | Honest operator" (AUDIT.md). Section 3: the honest operator role
   covers "The transition function ... in every deployment". That clause covers this component.
3. High and Medium cases: section 8, "A contradiction between the manual and the behavior on a security-relevant
   point is a defect in one of the two. It takes the severity it would have if the manual were right." The point is
   security-relevant: it is the guest's address map and memory permissions, the boundary R8 draws. If the manual were
   right, the emulator would deviate from the documented architecture by faulting on loads the manual allows. That
   deviation is deterministic, consistent across all paths (native and uarch agree; all use the same PMA lookup), and
   undocumented. It fits "An undocumented deterministic deviation, consistent across all paths, in behavior that no
   correct guest relies on for isolation or data integrity (R7)": refusing a read of the processor registers takes no
   isolation or data integrity from a guest, and R8 forbids the alternative. The Medium header also applies,
   "violates a rule or the manual without affecting the goal". Medium.
4. Critical: under the reading that the guest's access to the address ranges is itself R7's area "Address translation
   and memory permissions", where "any deviation lets an input subvert a correct guest, even a deviation that is
   consistent across all paths", the emulator departs from "the devices as the manual documents them" at every
   reachable state, and the defect would be Critical.

Three readings. The preferred one is Medium: R7's areas are the architecture a correct guest relies on for isolation
and data integrity, and a fault on reading the processor shadow removes neither; the manual, not the code, is wrong,
since the code's behavior is what R8 requires. The alternative is Critical: the literal R7 text counts any deviation
in "memory permissions", and the manual documents these ranges as readable with PMA entries. A third, Low, reading
takes "externally" in "The main processor" as host-only (the uarch section uses the same words for the uarch shadow,
which the manual calls private) and the "Address ranges" and "PMAs" sentences as loose. That reading does not fit the
text: "Address ranges" equates the visible ranges with the board table and carves out only the uarch ranges, and
"PMAs" promises an entry for each visible range. The facts that would decide between Medium and Critical: whether a
guest can be expected to rely on reading its own registers through the shadow for isolation or data integrity, and
how "the severity it would have if the manual were right" applies when the manual's version would itself violate R8.

### Possible solution and risks

Fix the manual. In "Address ranges", list the processor and board shadow and the shadow TLB together with the uarch
shadow and uarch RAM as ranges not accessible to the main processor, or split the board table into visible and
private ranges. In "PMAs", say that these ranges have no PMA entries and that `PMA_SHADOW_STATE_DID` is reserved like
`PMA_SHADOW_UARCH_STATE_DID`. In "The main processor", say that "externally" means through the machine API (host),
not through guest loads. This changes no hash and carries no risk. Changing the code to match the manual (adding a
read-only PMA entry for the shadow state) would let the guest read `imcyclemax`, the cached translation state and the
other registers, which R8 forbids, and would change the PMA array, every root hash, the uarch program and the on-chain
step, a new protocol version (R13, A6). It should not be done.

### Risk of not fixing it

No hash, proof or verification is affected, so no deployment's settlement is at risk. A guest, firmware or tool author
who follows the manual and reads a register through the processor shadow, or searches the PMA array for a
`PMA_SHADOW_STATE_DID` entry, gets a load access fault or no entry. A guest that does so while processing an input
would trap where the manual promises a read. Mitigation outside the code: read machine-identification and other
registers through the CSRs the specification provides, and treat `0x0-0x7fff` as inaccessible to the guest.
