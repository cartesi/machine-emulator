# R5-INVHASH-1: replace_memory_range keeps the supplied .dht inner nodes on an already-hashed machine

## What is asserted

A machine with one 8-page flash drive (image A) computes its root hash once. Then
`replace_memory_range` replaces the drive with image B and a `.dht` file that holds B's true page hashes (leaves)
but garbage inner nodes, in two documented ways:

1. `dht_filename` + `dpt_filename` + `mark_pages_dirty = true`;
2. `dht_filename` only (no `.dpt`), where the emulator marks all pages dirty itself.

For each, the test asserts that

- `get_root_hash()` equals the content hash of image B (root of a fresh machine created with image B);
- `get_node_hash(start, 15)` of the replaced range equals its content hash;
- (variant 2) a snapshot written by `store(dir)` has a cached root equal to the root rebuilt with
  `clear_hash_tree = true`.

Control (setup check, exit 2 if it fails): the same backing stores used at machine creation give the content hash.

Cause: after a successful hash-tree update `hash_tree::m_bubble_up_unchanged_pages` is false
(`src/hash-tree.cpp`, `update`). The replaced range only marks its dirty-page tree dirty
(`src/memory-address-range.cpp`), and `return_updated_dirty_pages` marks each page clean without bubbling up when
its recomputed hash equals the stored leaf, so the supplied inner nodes (and the range root copied into the sparse
tree) are kept. `verify_hash_tree()` still returns true.

## Requirement

doc/README.md (backing_store): "When both tree filenames are supplied and both files already exist, the emulator
reuses the dirty-page flags to avoid recomputing unchanged page hashes. Otherwise, it marks all pages dirty. Setting
`backing_store.mark_pages_dirty` to `true` forces all pages to be marked dirty even when both tree files exist, so
their hashes are recomputed on the next hash-tree update."

THREAT_MODEL R9: "The content hash must equal the root of the actual contents. This applies to every cached,
incremental, or persisted hash, after any sequence of documented operations. It includes interrupted or failed
updates, and every snapshot the emulator itself writes."

## Run

```sh
bugs/run.sh R5-INVHASH-1
```

Takes about a second; temporary files go to a `mktemp -d` directory that is removed.

## Expected output on audit/prt2

```
content hash (fresh machine, image B):     ff90e966...
creation with mark_pages_dirty tree files: ff90e966...
creation with .dht but no .dpt:            ff90e966...
[mark_pages_dirty=true] root after replace:         3822f18d...
[mark_pages_dirty=true] range node after replace:   eeeeeeee... (content: 0d674deb...)
[mark_pages_dirty=true] verify_hash_tree():         true
VIOLATED: ... root hash after replace_memory_range equals the content hash
VIOLATED: ... node hash of the replaced range equals its content hash
[no dpt_filename] ... (same)
[no dpt_filename] stored snapshot cached root: 3822f18d... rebuilt: ff90e966...
VIOLATED: [no dpt_filename] snapshot written by store() has a cached root equal to its rebuilt root (R9)
run.sh: R5-INVHASH-1: exit 1 (bug present)
```

Exit 0 once the replaced range's inner nodes are rebuilt (all asserts OK).
