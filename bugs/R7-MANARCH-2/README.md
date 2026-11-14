# R7-MANARCH-2: processor shadow and shadow TLB, visible per the manual, have no PMA entry and fault on guest loads

## What is asserted

The manual (`doc/README.md`) presents the processor and board shadow (`0x00000000-0x00000fff`) and the shadow TLB
(`0x00001000-0x00006fff`) as address ranges visible to the main processor:

- "The processor makes its entire state available, externally and read-only, by mapping every register to the start
  of the physical address space (in the processor shadow, a 4KiB range)" (The main processor).
- The board mapping table lists both ranges (The board).
- "The address ranges visible to the main processor are mapped at fixed positions ... These are the ranges listed in
  the board mapping table ... and discoverable at runtime via the PMA array". Only the uarch shadow and uarch RAM are
  then listed as "private address ranges, which are not accessible to the main processor" (Address ranges).
- "Each address range visible to the main processor is described by an entry in the array of Physical Memory
  Attribute records (PMAs)" (PMAs), with `PMA_SHADOW_STATE_DID = 2` in the driver-id table.

The emulator registers the shadow state (`0x0-0x7fff`) for the hash tree only (`src/machine-address-ranges.cpp`,
`register_where{.hash_tree = true, .pmas = false}`). So the PMA array has no entry for it, and a main-processor load
from it raises a load access fault.

The test, `test.lua`, builds a tiny hand-encoded bare-metal guest (no toolchain needed) for each probe. The guest
sets `mtvec`, then does `ld a1, 0(a0)`. The test then:

1. Decodes the PMA array at `0x10000` and checks for an entry covering `0x0-0xfff` and `0x1000-0x6fff`. It accepts
   any entry, whatever its attributes.
2. Loads from `0x290` (`marchid`), `0x2f8` (`imcyclemax`), `0x1000` and `0x6ff8` (shadow TLB) and checks that each load
   returns the value the host reads at that address. A control load from the PMA array (`0x10008`) must succeed, or
   the test exits 2.
3. Checks whether the manual still presents the two ranges as visible to the main processor: they are in the board
   table and not listed in the "Address ranges" subsection.

Exit 0 if the emulator matches the manual (entries exist and the loads return the shadowed values), or if the manual no
longer presents these ranges as visible to the main processor. Either fix passes; R8 suggests the manual is the side
to fix. Exit 1 if both still disagree.

## Requirement

THREAT_MODEL R7: "The emulator implements the RISC-V specification and the devices as the manual documents them,
departing only where the manual documents a deviation." The area is "Address translation and memory permissions".
Section 8: "A contradiction between the manual and the behavior on a security-relevant point is a defect in one of
the two. It takes the severity it would have if the manual were right."

## Run

```sh
bugs/run.sh R7-MANARCH-2
```

Run time is under a second.

## Expected output on audit/prt2 (exit 1)

```
PMA array: 8 entries            (RAM, DTB, TX, RX, HTIF, CLINT, PLIC, PMA array; none starts below 0x10000)
PMA entry covering processor and board shadow 0x0-0xfff: NO
PMA entry covering shadow TLB 0x1000-0x6fff: NO
guest ld 0x10008 (control: PMA array, a range with a PMA entry): value 0x400000, shadowed value 0x400000
guest ld 0x290 (processor shadow, marchid (offset 0x290)): TRAP mcause=5 mtval=0x290
guest ld 0x2f8 (processor shadow, imcyclemax (offset 0x2f8)): TRAP mcause=5 mtval=0x2f8
guest ld 0x1000 (shadow TLB, first word): TRAP mcause=5 mtval=0x1000
guest ld 0x6ff8 (shadow TLB, last word): TRAP mcause=5 mtval=0x6ff8
manual presents 0x00000000-0x00000fff as visible to the main processor: yes
manual presents 0x00001000-0x00006fff as visible to the main processor: yes
VIOLATED: R7: ...
run.sh: R7-MANARCH-2: exit 1 (bug present)
```

## Notes for the reviewer

- The word "externally" in the main-processor sentence is ambiguous. The uarch section uses the same words for the
  uarch shadow, which the manual calls private, so on its own that sentence may mean the host only. The test
  therefore relies on the Address ranges and PMAs subsections, which do not have this ambiguity.
- Side observation, not asserted here: the PMA attribute bit layout in the manual's table (DID in bits 11-8, IW 7,
  IR 6, X 5, W 4, R 3, E 2, IO 1, M 0) differs from `src/pmas-constants.hpp` (DID in bits 11-7, IW 6, IR 5, X 4, W 3,
  R 2, IO 1, M 0, no E bit). For example, RAM shows attributes `0x0fd`, which the manual's table would decode as
  M and E both set and DID 0. For this reason the coverage check ignores attribute bits.
