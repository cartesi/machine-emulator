# R2-DFSTORED-2: clone + shared load refuses a valid template that is read-only or has a trimmed backing file

## What is asserted

`test.lua` copies the harness stored machine `baremetal-template` (rx-accepted manual yield, empty outputs root) into
a temp dir and makes two variants that change only attributes outside the hashed state:

- **A**: `chmod a-w` on every file (as a tar/OCI layer or a protected store can leave a distributed template);
- **B**: the RAM backing file truncated after its last non-zero 4 KiB page (67108864 -> 2367488 bytes; same contents).

For each variant the test first checks the precondition: loading the variant **unshared** with
`clear_hash_tree = true` (the O1 rebuild) gives the reference content hash. If not, it exits 2. It then asserts that
the adoption path of the PRT stored player (`doc/recipes/prt.lua`, `new_stored_player`) and of
`cartesi-machine --load=<dir>,clone:<src>` works:
`cartesi.machine:clone_stored(template, clone)`, then `load(clone, {clear_hash_tree=true}, SHARING_ALL)`. The load
must succeed and give the reference hash. The clone must accept an advance input and run to the next manual yield.
The template's contents must stay unchanged afterwards. That last check means a fix cannot simply drop the
shared-write safety check while the clone stays a hard link.
A control (the unmodified template) must pass the same procedure, or the test exits 2.

Required behavior (THREAT_MODEL.md):

- Section 8, out of scope, on snapshots: "Once a snapshot meets them, nothing it carries outside the hashed state may
  affect any transition (R1), crash the honest operator, or corrupt its memory."
- Section 2, "Honest operator's path": "Obtaining its valid template. For a template the operator did not produce,
  this includes rebuilding its cached hash-tree data (O1)." and "Storing and reloading the machine."
- R4: "From any reachable state, at the position where it is reached, the honest operator can always compute the
  claim, produce every requested node and proof, ..."

Cause: `os::clone_file` (`src/os-filesystem.cpp`) hard-links every file that has no write permission bit (A), and
`machine::clone_stored` (`src/machine.cpp`) clones each backing file as it is, at its length (B). The shared-write
mapping (`src/os-mapped-memory.cpp`) refuses read-only or multiply-linked files, and backing files shorter than the
range. The unshared loader accepts both variants (B through `backing_gap`).

Context for the reviewer (printed by the test, not asserted): the manual documents "Read-only backing files are
hard-linked" (doc/README.md, `clone:` and `clone_stored`). An unshared load followed by `store(dir, SHARING_ALL)`
and a shared load of that directory works for both variants.

## Run

```sh
bugs/run.sh R2-DFSTORED-2
```

Takes about 1 s and uses a temp dir under `/tmp` (about 100 MB, mostly sparse), removed at the end.

## Expected output on audit/prt2

```
control: unmodified template
  clone_stored + SHARING_ALL load + run: OK, template untouched
A: template files read-only ...
  clone_stored + SHARING_ALL load + run FAILED: ... backing file '.../clone2/0000000000000000-8000.bin' is read-only and cannot be shared for writing when initializing shadow state
VIOLATED: A: ...
B: RAM backing file trimmed after its last non-zero page (same contents, same hash)
  clone_stored + SHARING_ALL load + run FAILED: ... backing file '.../clone3/0000000080000000-4000000.bin' length (2367488) does not match desired backing length (67108864) when initializing RAM
VIOLATED: B: ...
run.sh: R2-DFSTORED-2: exit 1 (bug present)
```

Exit 1 while the defect is present. Exit 0 once a clone of either variant loads with sharing, gives the reference
hash and runs without touching the template.
