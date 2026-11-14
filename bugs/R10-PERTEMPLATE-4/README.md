# R10-PERTEMPLATE-4: unknown members in an adopted template's `config.json` set the memory the operator spends loading it

## What is asserted

`config.json` of a stored machine is outside the hashed state. `machine_config::load` (`src/machine-config.cpp`)
reads it whole and parses it into a full `nlohmann::json` value, and ignores every member it does not know. Nothing
bounds its size. `machine::clone_stored` (`src/machine.cpp`) copies it byte for byte, so every clone the PRT player
makes of such a template carries the padding too, and every later load pays for it again. Only a load followed by
`store` writes a normalized file.

`test.lua`:

1. Copies the harness's stored `baremetal-template` machine (64 MiB RAM, 75.8 MiB of address ranges, waiting at a
   manual yield with the accepted reason, root in `root-hash.txt`). This is the control.
2. Makes copies that differ from the control only in `config.json`. Each copy has an extra top-level member
   `"x-padding": [0,0,...]` of 16 MiB and 64 MiB (`R10PT4_PAD_MIB`, default 64). The 64 MiB file gzips to about
   65 KB. The hashed contents are the same.
3. Adopts each copy as O1 requires, in its own child process (`child.lua adopt`). The child loads without sharing,
   with `clear_hash_tree = true`, calls `get_root_hash()` and reports its peak resident memory (`VmHWM`).
4. For information only, it also runs `clone_stored` of the padded copy (the clone keeps the padded file) and a load
   followed by `store` (which normalizes it).
5. Requires the 64 MiB copy to be adopted with the control's root hash. Its peak memory must also be no larger than
   the larger of 2x the control's and the control's plus twice the bytes of the machine's address ranges. That bound
   depends only on the machine, not on the padding. Otherwise the test exits 1.

The test compares memory within one run and uses no wall-clock threshold. CPU times are printed for information.

## Requirement

- R12: "Each of the following operations has a worst case in host time and memory that is bounded and at most
  linear in the cycles it executes or the bytes it covers. They are ... storing, loading, cloning or syncing a
  machine."
- Section 8, Out of scope (snapshots): "Once a snapshot meets them, nothing it carries outside the hashed state may
  affect any transition (R1), crash the honest operator, or corrupt its memory."
- Section 2, Honest operator's path: "Obtaining its valid template. For a template the operator did not produce,
  this includes rebuilding its cached hash-tree data (O1)."

A fix that rejects the padded template would still make the test fail, by the readings of the campaign: a valid
template that is refused loudly on the honest operator's path is a defect. Fixes that pass would parse without
building the whole document, or skip unknown members within bounded memory.

## How to run

```sh
bugs/run.sh R10-PERTEMPLATE-4          # about 20 s; the padded child peaks near 1.4 GB
R10PT4_PAD_MIB=128 bugs/run.sh R10-PERTEMPLATE-4
```

Needs the harness configuration `bugs/harness/work/configs/baremetal-template` (`bugs/harness/configs/make-configs.sh`).
Temporary copies go to a `mktemp -d` directory, which the test removes.

## Expected output on audit/prt2

Exit 1. Two runs gave the same figures:

```
machine covers 75.8 MiB in its address ranges; control config.json 3780 bytes
control:            VmHWM=  139204 kB cpu=0.12 s root=428a6bb8...ac75
padded config.json of 67112660 bytes compresses (gzip) to 66282 bytes
padded config.json   16781012 bytes: VmHWM=  383604 kB ... root=428a6bb8...ac75 (2.76x control)
padded config.json   67112660 bytes: VmHWM= 1415804 kB ... root=428a6bb8...ac75 (10.17x control)
marginal peak memory: 21.00 bytes per byte of unhashed padding (small->big)
clone_stored: VmHWM=1415760 kB; clone's config.json 67112660 bytes (source 67112660 bytes)
load+store normalizes it: stored config.json 3780 bytes
allowed peak: 294428 kB (max of 2.0x control, control + 2 x 75.8 MiB of address ranges)
VIOLATED: R12 ... observed 1415804 kB, 10.17x the control's 139204 kB
run.sh: R10-PERTEMPLATE-4: exit 1 (bug present)
```

Each byte of unknown `config.json` padding costs about 21 bytes of peak memory, both on adoption and in
`clone_stored`, which parses the source's `config.json` too. That is about 21,000 times the padding's compressed
size. The root hash does not change. With 128 MiB of padding the adoption peaked at 2.8 GB.
