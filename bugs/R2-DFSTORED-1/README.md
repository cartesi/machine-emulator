# R2-DFSTORED-1: store with sharing none/config re-emits the pre-rebuild hash tree after an O1 adoption

## What is asserted

An operator adopts a stored machine it did not produce. It loads it with `clear_hash_tree = true`, as O1 requires,
and gets the content hash `H`. It then stores the adopted machine (`machine:store(dir, sharing)`), runs
`sync_stored(dir)`, and later reloads its own snapshot without a rebuild, which R1 and O2 allow. The test asserts
that, for each store mode `all`, `config` and `none`, the reloaded root hash equals `H` and `verify_hash_tree()`
returns true.

Setup: the test copies `bugs/harness/work/configs/baremetal-template/machine` to a temp dir and populates its cache
(SHARING_ALL load, `get_root_hash`, sync). It then overwrites 64 bytes of a RAM page in the `.bin` file without
going through the emulator. The `.dht`/`.dpt` files then describe the old contents. The test checks these
preconditions and exits 2 if one fails:

- the rebuilt hash differs from the stale cached hash;
- the stored directory, when reloaded *with* a rebuild, still gives `H`, so its contents are right and only the
  cached data is wrong.

## Requirement

- THREAT_MODEL R9: "The content hash must equal the root of the actual contents. This applies to every cached,
  incremental, or persisted hash, after any sequence of documented operations. It includes ... every snapshot the
  emulator itself writes", where that means "a directory that O2 guarantees". The stored directory was written
  by the operator's own process, synced, and never used with sharing.
- Section 5: "O1 and O2 bind the emulator too ... A defect that defeats the rebuild itself, or that damages a
  directory while O2 guarantees it, is not excused by them."
- R1: cached hash-tree data "was either written by the operator's own process into a directory that O2
  guarantees, or rebuilt from the contents on adoption (O1). This rule applies to it".

Cause: `machine::store` (src/machine.cpp, unshared branch) uses `os::copy_file` to copy the source directory's
`.dht`/`.dpt` files for ranges that are not shared. `clear_hash_tree` rebuilds only the in-memory (MAP_PRIVATE)
trees, so those files still hold the template's stale cached data.

## Run

```sh
bugs/run.sh R2-DFSTORED-1      # about 8 s, uses about 300 MB in a temp dir under /tmp (removed at exit)
```

## Expected output on audit/prt2

```
template stale cached root: 0x428a6bb8...ac75
template content hash (O1): 0xfda9eee8...d27d
store sharing=all    reload root 0xfda9eee8...  (== content hash)  verify_hash_tree=true
page 0x80100000 (in RAM) is not marked dirty but is dirty
! FAILED!
store sharing=config reload root 0x428a6bb8...  (== STALE template cache)  verify_hash_tree=false
...
store sharing=none   reload root 0x428a6bb8...  (== STALE template cache)  verify_hash_tree=false
OK: ... sharing=all ...
VIOLATED: ... sharing=config ...
VIOLATED: ... sharing=none ...
run.sh: R2-DFSTORED-1: exit 1 (bug present)
```

Exit 1 while the defect is present. SHARING_ALL is the passing control. The test exits 0 once store writes cached
data that matches the contents (for example by writing blank trees, or the in-memory trees, for unshared ranges
whose source trees were cleared).
