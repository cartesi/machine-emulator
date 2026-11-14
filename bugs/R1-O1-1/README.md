# R1-O1-1: clear_hash_tree cannot adopt a stored machine whose cached hash-tree files are malformed or missing

## What is asserted

The documented O1 rebuild is the runtime option `clear_hash_tree` (`cartesi-machine --load=DIR --clear-hash-tree`,
`cartesi.machine(dir, {clear_hash_tree = true})`, `cm_load` and JSON-RPC `machine.load` with that runtime option,
the PRT recipes' `new_stored_machine`). The test stores the harness `baremetal-template` machine with sharing,
records the root hash of the untouched directory loaded with `clear_hash_tree`, and then, on copies, damages only
cached hash-tree data. Every `.bin` file and `config.json` is unchanged, so the hashed contents are the same.
For each case, with `SHARING_NONE` and with `SHARING_ALL`, it requires that loading with `clear_hash_tree = true`
succeeds and that `get_root_hash()` equals the reference root.

Controls (they must pass, or the test exits 2): garbage in the root hash stored in `hash_tree.sht`, and garbage in
the first page hashes of the RAM `.dht`. The rebuild handles both, so the rebuild itself works.

Cases:

1. `hash_tree.sht`: the left index of sparse node 2 is changed (int64 at offset 128)
2. `hash_tree.sht` truncated to 64 bytes
3. `hash_tree.phtc`: unknown file tag
4. RAM `.dpt` truncated to 10 bytes
5. RAM `.dht` missing

The cause is in `src/machine.cpp` `machine::machine`. It constructs the address ranges (`m_ars`) and the hash tree
(`m_ht`) from the cached files and validates their structure: `hash_tree::hash_tree` raises "inconsistent sparse
hash tree nodes", the `page_hash_tree_cache` constructor raises "file tag mismatch", and `os::mapped_memory`
requires exact lengths and existing files. `clear_hash_tree()` runs only after all of that, so the rebuild never
gets a chance to run.

## Requirement

THREAT_MODEL.md:

- O1: "An operator who adopts a stored machine it did not produce rebuilds the cached hash-tree data from the
  contents when loading it, and only then compares the root hash with the on-chain commitment."
- Section 5: "O1 and O2 bind the emulator too. ... the emulator must make them possible to follow. A defect that
  defeats the rebuild itself ... is not excused by them."
- Section 4: "A snapshot's cached hash-tree data is not part of any valid-template condition, so a snapshot the
  operator did not write is defended only after that data is rebuilt (O1)."
- Section 8: "Once a snapshot meets them, nothing it carries outside the hashed state may affect any transition
  (R1), crash the honest operator, or corrupt its memory."

## How to run

```sh
bugs/run.sh R1-O1-1
```

It needs the shared harness stored machine `bugs/harness/work/configs/baremetal-template/machine`. It runs in
about 1 s and works in a `mktemp -d /tmp/r1-o1-1.XXXXXX` directory, which it removes when it finishes.

## Expected output on audit/prt2 (exit 1)

```
reference root hash (rebuilt from contents): 0x428a6bb8...ac75
[SHARING_NONE] control: garbage in the root hash of hash_tree.sht: rebuilt, root matches
... (all 4 control lines: rebuilt, root matches)
[SHARING_NONE] hash_tree.sht: left index of sparse node 2 changed: load with clear_hash_tree FAILS: ... inconsistent sparse hash tree nodes
[SHARING_ALL]  ... same
[*] hash_tree.sht truncated to 64 bytes: ... FAILS: backing file ... length (64) does not match desired backing length (6144)
[*] hash_tree.phtc: unknown file tag: ... FAILS: corrupted page hash-tree cache: file tag mismatch
[*] RAM .dpt truncated to 10 bytes: ... FAILS: backing file ... length (10) does not match desired backing length (32768) when initializing RAM
[SHARING_NONE] RAM .dht missing: ... FAILS: unable to open backing file ...dht: No such file or directory
[SHARING_ALL]  RAM .dht missing: rebuilt, root matches
VIOLATED: ... 9 of 10 load(s) failed
run.sh: R1-O1-1: exit 1 (bug present)
```

Once the loader stops trusting the structure of cached data that it is about to clear (for example by
re-initializing the cached files instead of validating them when `clear_hash_tree` is set), all 10 loads succeed
with the reference root and the test exits 0.
