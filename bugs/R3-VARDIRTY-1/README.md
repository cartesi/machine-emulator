# R3-VARDIRTY-1: an exception inside `hash_tree::update` leaves ancestors of stored page hashes stale for good

## What is asserted

After `get_root_hash()` fails inside a running process because a host allocation fails inside
`hash_tree::update`, and the process keeps using the machine, the next `get_root_hash()` must equal the root
of the machine's actual contents. The test compares it with the root rebuilt by `clear_hash_tree()`. (If the
later call failed loudly instead, that would not be a wrong hash, and the test would pass.)

Requirement (THREAT_MODEL.md, R9): "The content hash must equal the root of the actual contents. This applies
to every cached, incremental, or persisted hash, after any sequence of documented operations. It includes
interrupted or failed updates [...] "Interrupted or failed updates" means updates that fail inside a running
process, which then keeps using the machine." Section 4: "A host fault [...] may stop the honest operator, but
the emulator must never turn one into a wrong hash, a wrong proof, [...]".

## How it works

- `fail-new.cpp` is an LD_PRELOAD fault injector. It replaces the global `operator new` and, while an arm file
  exists, throws `std::bad_alloc` for the first request of exactly 16384 bytes, as an allocator under a memory
  limit would. Every injected failure is counted in a file that the test reads.
- The machine (64 MiB RAM) uses runtime `concurrency.update_hash_tree = 1`, so `update_dense_trees` reserves a
  batch of `min(1 << 10, 16384)` = 1024 entries of 16 bytes = 16384 bytes, on any host. In the update, that
  request comes after `update_dirty_pages` (98304-byte batch) has hashed the dirty pages and stored their new
  hashes in the dense trees; it is the only 16384-byte request of the update.
- Control: the same operations without the fault keep the cached root equal to the rebuilt root (else exit 2).
- Faulty run: hash once, write to 64 distinct pages, arm, `pcall(get_root_hash)` must fail with exactly one
  injected failure (else exit 2), disarm, write once more ("keep using the machine"), `get_root_hash()`, then
  `clear_hash_tree()` and `get_root_hash()` again.

Defect: in `src/hash-tree.cpp`, `hash_tree::update` sets `m_bubble_up_unchanged_pages = !update_succeeded`
only when `update_dirty_pages`, `update_dense_trees` and `update_sparse_tree` return. An exception skips the
assignment and leaves the flag false, though the page hashes are already stored (the comment at that line and in
`hash-tree.hpp` says the flag exists for exactly this case). The next update finds those pages' stored hashes
equal to their contents, so `update_dirty_pages` marks them clean (`mark_clean_page_and_up`) instead of
bubbling them up, and their ancestors in the dense and sparse trees are never recomputed. The root stays stale
until `clear_hash_tree()`. `verify_hash_tree()` compares only pages against their page nodes and still reports
true. Setting the flag on every exit path (for example, before the work starts or in a scope guard) fixes it,
and the test would then exit 0.

## Run

```sh
bugs/run.sh R3-VARDIRTY-1      # needs g++ and the in-tree emulator build; about 2 s
```

## Expected output on audit/prt2 (exit 1)

```
control: no fault, cached root == rebuilt root 0xb6640061f50463f54f05c6429f157bf4dbc257bc0042689161b4d929483c4690
get_root_hash failed as injected (16384-byte dense-tree batch reservation): std::bad_alloc
get_root_hash() after the failure  0x14b95ed6e4817e645550c788100cbb8a56f2f4907f80b6370f60cdecf54a972e
root rebuilt by clear_hash_tree()  0xb6640061f50463f54f05c6429f157bf4dbc257bc0042689161b4d929483c4690
verify_hash_tree() after the failure true
VIOLATED: R9: after hash_tree::update fails inside a running process (host allocation failure), get_root_hash() must equal the root of the actual contents
run.sh: R3-VARDIRTY-1: exit 1 (bug present)
```

The rebuilt root of the faulty machine equals the control's root (same contents); the cached one does not.
