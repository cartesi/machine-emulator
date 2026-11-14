# R1-O1-2: unhashed `hash_tree.phtc_size` of an adopted template sets the cost of adopting it

## What is asserted

The capacity of the page hash-tree cache, `hash_tree.phtc_size`, is read from the stored `config.json`. It is not
part of the hashed state, and the O1 rebuild (`clear_hash_tree = true`) keeps it. Whoever hands the operator a
template directory can raise it and ship a sparse `hash_tree.phtc` of the matching length, which costs no disk.
The test checks that adopting such a directory costs about as much as adopting the same contents with the default
value.

`test.lua`:

1. Copies the harness's stored `baremetal-template` machine (64 MiB RAM, waiting at a manual yield with the
   accepted reason, stored with the default `phtc_size` 4096; 19403 pages in all its address ranges). This is the
   control.
2. Makes copies that differ from the control only in `config.json` `hash_tree.phtc_size` (16384, then 65536). Each
   copy gets an empty sparse `hash_tree.phtc` of the matching length. The length formula is first checked against
   the file the emulator wrote for the control. The hashed contents are the same.
3. Adopts each copy as O1 requires, in its own child process (`child.lua`), by loading without sharing with
   `clear_hash_tree = true` and then calling `get_root_hash()`. Each child reports its root hash and its peak
   resident memory (`VmHWM`).
4. Requires each crafted copy to be adopted, with the same root hash and a peak memory no larger than the larger of
   2x the control's and the control's plus a page cache covering every page of the machine (12 KiB per page).
   Otherwise it exits 1. (Reviewer repair: the original limit was 2x the control alone, which a fix that clamps the
   capacity to the machine's own page count would still have failed.)

This is a ratio measured within one run, with no wall-clock threshold. CPU time is printed for information only.

## Requirement

- R12: "Each of the following operations has a worst case in host time and memory that is bounded and at most
  linear in the cycles it executes or the bytes it covers. They are ... storing, loading, cloning or syncing a
  machine."
- Section 8, Out of scope (snapshots): "Once a snapshot meets them, nothing it carries outside the hashed state may
  affect any transition (R1), crash the honest operator, or corrupt its memory."
- Section 2, Honest operator's path: "Obtaining its valid template. For a template the operator did not produce,
  this includes rebuilding its cached hash-tree data (O1)."

## How to run

```sh
bugs/run.sh R1-O1-2              # R1O12_BIG=<entries> changes the large phtc_size (default 65536)
```

The run takes about 2 s and peaks near 0.9 GB of RSS in one child. Temporary copies (about 100 MB on disk) go
under `mktemp -d` and are deleted at the end.

## Expected output on audit/prt2

```
machine covers 19403 pages (75.8 MiB)
control: phtc_size=4096   VmHWM= 139480 kB ... root=428a6bb8...
crafted: phtc_size=16384  VmHWM= 288020 kB ... root=428a6bb8...  (2.06x control memory)
crafted: phtc_size=65536  VmHWM= 880092 kB ... root=428a6bb8...  (6.31x control memory)
marginal cost: 12.0 kB of peak resident memory per phtc entry (MID->BIG)
phtc_size survives clear_hash_tree: stored 65536 entries -> loaded 65536
allowed peak: 372568 kB (max of 2.0x control, control + 19403 pages x 12 KiB)
VIOLATED: R12 ... must cost at most 372568 kB of peak memory (bounded by the machine's size); observed 880080 kB, 6.30x the control's 139732 kB
run.sh: R1-O1-2: exit 1 (bug present)
```

Exit 1, the same on two runs. The root hash does not change. Peak memory grows by about 12 kB per entry and does
not depend on the machine's size. By extrapolation, not run, `phtc_size` near 2^21 would need about 24 GB, more
than this 16 GB host.

## When fixed

The test exits 0 if adoption ignores the stored capacity, resets it under `clear_hash_tree`, or clamps it to the
number of pages the machine covers. The test also treats a load that refuses the crafted directory as a
violation (exit 1), because the hashed contents form a valid template. A fix that only adds a runtime override would
need the test to pass that override.

Not tested here: `store()` and `clone_stored()` copying the inflated value into later directories.
