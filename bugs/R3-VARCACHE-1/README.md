# R3-VARCACHE-1: replace_memory_range on a machine sharing its directory; the synced directory reloads to a spliced state

## What is asserted

`machine:replace_memory_range` swaps a range's backing store only in the live machine. It does not refuse a
machine whose ranges are mapped shared to a stored directory D, and it does not record the replacement in D.
The test:

1. clones the harness `baremetal-template` (a valid template, `emit-output.bin` at its first accepted yield) to
   a temporary D, syncs it, and loads it with `cartesi.SHARING_ALL` and `clear_hash_tree = true`;
2. replaces `.ram` with an image that differs from D's RAM file in one byte, at 48 MiB into RAM (`0x83000000`,
   which the guest never touches);
3. delivers one advance input and runs to the next manual yield, records the root hash H;
4. destroys the machine (no crash), runs `sync_stored(D)`, so D is a directory that O2 guarantees;
5. reloads D with `clear_hash_tree = true` (O1 rebuild) and requires its root hash to equal H.

A control runs the same sequence without the replacement and must round-trip (otherwise exit 2).

Exit 0 (fixed) if D reloads to H, or if `replace_memory_range` (or `sync_stored`) refuses the operation on a
machine that shares its directory. Exit 1 if D reloads to another root hash. Exit 2 on setup errors.

## Requirement

- THREAT_MODEL.md section 8, How to rate, step 1: "A wrong hash after documented operations, destroying the
  machine, and a sync is not" out of scope.
- R2: "Wherever two of the following reach the same position, they must agree on its canonical hash. ...
  Every way of copying, persisting, restoring, or sharing a machine."
- Section 8, Medium: "A machine API operation off the honest operator's path that, used as documented, leaves
  the hash tree, the cached state of the machine or a stored directory inconsistent with the machine's contents
  (R9)."
- Section 4: the emulator must never produce "a directory that O2 guarantees but that later loads as a different
  state."
- Manual (doc/README.md): "A directory used by a machine with sharing holds a valid machine only after that
  machine was destroyed without a crash and the directory was synced." `cm.h` documents only "A later
  cm_store() uses the new backing store" for the replacement.

## How to run

```sh
bugs/run.sh R3-VARCACHE-1
```

About 7 s; uses a temporary directory under `$TMPDIR` (or `/tmp`), removed at the end.

## Expected output on audit/prt2

```
control (no replacement): final 0x0ccbd06a...880b5d mcycle 8588695
control reloaded:         root  0x0ccbd06a...880b5d mcycle 8588695
template root:            0x428a6bb8...ec92ac75
after replace .ram:       0xa1cc5cd8...b7a99751
machine after input:      0x0c035851...dbed97fb mcycle 8588695, RAM byte at probe 0x5a
D reloaded (O1 rebuild):  0xe07b2ec9...2348918e mcycle 8588695, RAM byte at probe 0x00
D's reloaded root equals: none of the machine's root hashes
VIOLATED: a directory shared by a machine, destroyed without a crash and synced (O2-guaranteed) must reload to the machine's state (R2, R9, section 8 step 1)
run.sh: R3-VARCACHE-1: exit 1 (bug present)
```

D holds the post-input registers (same mcycle as the machine) with the pre-replacement RAM: a state that no
execution reaches. The O1 rebuild passes, so nothing detects it.
