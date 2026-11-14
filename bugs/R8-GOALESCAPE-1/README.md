# R8-GOALESCAPE-1 — AMOs translate their address twice

## What is asserted

`src/interpret.cpp` `execute_AMO` performs an atomic memory operation as two separate accesses:

```cpp
// read half: read-TLB set, read-type page walk
read_virtual_memory<T, STATE_ACCESS, true>(a, pc, mcycle, vaddr, &valm);
...
// write half: write-TLB set, store-type page walk
write_virtual_memory<T>(a, pc, mcycle, vaddr, valr);
```

Each half consults its own TLB set and, on a miss, runs its own `translate_virtual_address`
(`src/translate-virtual-address.hpp`) walk, which updates the leaf PTE's A/D bits **after its own**
permission check. The RISC-V "A" extension defines an AMO as **one** atomic access that loads and stores
back to the **same** address, translated **once** as a store/AMO access (privileged spec 4.3.2: one
permission check, then one A/D update for the access). The double translation produces two observable
deviations, both asserted by `test.lua`:

- **(A) Split translation / non-atomic AMO.** With a stale read-TLB entry `V -> P1` and a fresh
  write-TLB entry `V -> P2` (the PTE was changed without `sfence.vma` and the write TLB was refilled by an
  earlier store), one `amoadd.d rd, 1, (V)` **loads from P1** and **stores to P2**. The AMO is not atomic
  on any single physical location: `rd` is taken from P1 (100) while P2 is overwritten with `rd+1` (101)
  **without ever being read** (its 200 is lost), and P1 is left unchanged. A spec-correct AMO uses one
  translation, so some location `L` satisfies `rd == pre(L)` and `post(L) == rd+1` with the other location
  unchanged. The test asserts that invariant.

- **(C) Lost dirty bit.** An AMO on the PTE word that maps its own page (`A=0, D=0, W=1`): the read walk
  sets only A, the AMO reads the half-updated PTE (`...47`), the write walk sets A **and** D (`...c7`), and
  then the AMO's store writes the half-updated value (`...47`) back, **clearing D** although the page was
  just written. A single store/AMO translation sets A and D before the access, so after the AMO the PTE's D
  bit must be set. The test asserts `D` is set.

A **control** AMO on a page with a consistent (never-remapped) translation runs in the same machine; the
emulator handles it atomically (`300 -> 301`), which confirms the setup is sane and shows the same
atomicity predicate returns true for correct behavior — so a fix (one translation per AMO) makes the test
exit 0. `test.lua` also prints that native interpretation and the uarch program reach identical root
hashes, i.e. the deviation is in the state transition function itself (every path agrees).

## Requirement quoted (THREAT_MODEL.md, R7 Faithful architecture)

> The emulator implements the RISC-V specification and the devices as the manual documents them, departing
> only where the manual documents a deviation. A correct guest relies on the architecture for isolation and
> data integrity in the areas listed below. In these areas, any deviation lets an input subvert a correct
> guest, even a deviation that is consistent across all paths.
> - ...
> - Address translation and memory permissions.
> - Atomics and fences.

The manual documents no deviation for AMO translation or for A/D update order, so both (A) and (C) are R7
deviations.

## How to run

```sh
bugs/run.sh R8-GOALESCAPE-1
```

`test.lua` builds `amo.c` with `bugs/harness/baremetal/build.sh` into a temp dir (pinned
`riscv64-unknown-elf-gcc` of the toolchain image), boots it as a 64 MiB bare-metal machine, runs to halt,
and reads a fixed RESULT array from RAM. Needs the in-tree emulator and the toolchain image (both present on
`audit/prt2` per `bugs/harness/README.md`).

## Expected output on audit/prt2

Exit status **1** (bug present), deterministically. The run prints:

```
native/uarch final root hashes equal: true
scenario A: amo old=100  P1=100 (pre 100)  P2=101 (pre 200)
scenario C: self-mapping PTE after AMO = 0x20200847  (D bit 0x80 = 0)
control  : consistent-translation AMO old=300  PC=301 (pre 300) -> atomic
VIOLATED: R7 (Atomics and fences; Address translation): an AMO is one atomic access on a single address ...
VIOLATED: R7 (Address translation and memory permissions): an AMO that stores to the page its own PTE maps ...
run.sh: R8-GOALESCAPE-1: exit 1 (bug present)
```

On a fixed emulator (one translation per AMO, A/D set before the access), scenario A would read `old=200,
P1=100, P2=201` (or `old=100, P1=101, P2=200`) and scenario C would leave the PTE with D set, so both
assertions pass and the test exits 0.

## Files

- `amo.c` — bare-metal guest (built at test time; not tracked as a binary).
- `test.lua` — builds the guest, runs it, asserts (A) and (C), with the control as a setup gate.
