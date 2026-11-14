# R1-R7-1: SC succeeds on a different physical page after a remap of the reserved virtual address

## What is asserted

`execute_LR` in `src/interpret.cpp` stores the **virtual** address in `ilrsc`. `execute_SC` succeeds when
`ilrsc == vaddr`. Only SC and `set_prv` clear `ilrsc`; a `satp` write or `sfence.vma` does not. So a reservation
outlives a remap.

`test.lua` builds a bare machine (1 MiB RAM) with two Sv39 roots. It runs this program in S-mode, with interrupts
disabled and no trap between LR and SC:

```
lr.d  x6,(x5)          # VA 0x1000 -> P1 = 0x80020000
<remap VA 0x1000 to P2 = 0x80021000, which is another 4 KiB physical page>
sfence.vma
sc.d  x9,x8,(x5)
```

The remap comes in two variants:

- `satp`: `csrw satp` to a second root.
- `pte`: `sd` that overwrites the leaf PTE through a mapping of the page table.

For each variant, the test checks that the SC fails (`x9 != 0`) and that P1 and P2 keep their values.

The test also checks a control and the uarch path:

- **Baseline** (added by the reviewer). `lr.d; nop; nop; sc.d` with no remap. Its SC must succeed in S-mode on both
  paths. If it does not, the test exits 2.
- **Control.** The same program with a "remap" that keeps VA 0x1000 on P1. Its result must be consistent: either the
  SC succeeds and writes P1, or it fails and writes nothing. P2 is never written. If not, the test exits 2. (The
  reviewer relaxed this check. The prover's version required success, but a `csrw satp`, `sfence.vma` or store
  between LR and SC puts the pair outside the constrained LR/SC loop, so the spec allows the SC to fail. Also, the
  invalidate-on-satp/sfence.vma fix below makes it fail, so the original test would have exited 2, not 0, after
  that fix.)
- **Uarch path.** Every case also runs through the uarch path (`run_uarch` and `reset_uarch` per mcycle). It must
  reach the same root hash as native interpretation. If it does not, the test exits 2.

## Requirement

THREAT_MODEL.md R7: "The emulator implements the RISC-V specification ... In these areas, any deviation lets an
input subvert a correct guest, even a deviation that is consistent across all paths. ... Address translation and
memory permissions. Atomics and fences."

The following RISC-V text applies (riscv-isa-manual, current `src/unpriv/zalrsc.adoc` and `src/priv/supervisor.adoc`):

- Privileged, Sv32 section, which Sv39 inherits: "For implementations with both page-based virtual memory and the A
  standard extension, the LR/SC reservation set must lie completely within a single base physical page (i.e., a
  naturally aligned 4 KiB physical-memory region)."
- Zalrsc: "The SC must fail if the address is not within the reservation set of the most recent LR in program
  order." It also says: "If the SC.W fails, the instruction does not write to memory, and it writes a nonzero value
  to rd."

Zalrsc says that "an implementation can register an arbitrarily large reservation set". The privileged rule above
limits that set to the 4 KiB physical page of P1. P2 lies in a different physical page, so the SC must fail.

Zalrsc also tells software to invalidate a reservation with an SC to a scratch word "if necessary when changing
virtual to physical address mappings". That is a recommendation to software. It does not allow an SC outside the
reservation set to succeed. A reviewer should weigh it when deciding whether any correct guest relies on this
behavior, which is the deciding fact noted in triage.

## How to run

```sh
bugs/run.sh R1-R7-1
```

It runs in under a second.

## Expected output on audit/prt2 (exit 1)

```
baseline (native)            pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
baseline (uarch)             pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp control (native)        pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp control (uarch)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x9999 P2=0x1111
satp remap   (native)        pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
satp remap   (uarch)         pc=0x5010 prv=1 x9(sc rd)=0 P1=0x1111 P2=0x9999
VIOLATED: satp: R7 (Atomics; Address translation): ... must fail (rd != 0) without writing memory
pte control (native) ... (same pattern)
VIOLATED: pte: ...
run.sh: R1-R7-1: exit 1 (bug present)
```

Native interpretation and the uarch agree, so the regenerated step that runs the same `interpret.cpp` agrees too.
The deviation is consistent across all paths.

The test exits 0 once the reservation no longer survives into an SC to another physical page. Two fixes would do
that:

- Keying `ilrsc` by physical address.
- Invalidating `ilrsc` on `satp` writes and `sfence.vma`. This variant covers both cases in the test.
