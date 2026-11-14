## R5-INVHASH-1

**Title.** `replace_memory_range` on a machine whose hash tree was already updated keeps the inner nodes of the
supplied `.dht` even with `mark_pages_dirty = true` or no `.dpt`, so the root hash, node hashes and stored
snapshots disagree with the contents.

**Severity.** Medium (preferred reading: an operation of the machine API off the honest operator's path that, used as
documented, leaves the hash tree and a stored directory inconsistent with the contents, R9). Under the reading that a
`.dht` whose inner nodes do not match its leaves is misuse by the trusted caller, it is Low.

### Problem

The manual (doc/README.md, `backing_store`) says: "When both tree filenames are supplied and both files already exist,
the emulator reuses the dirty-page flags to avoid recomputing unchanged page hashes. Otherwise, it marks all pages
dirty. Setting `backing_store.mark_pages_dirty` to `true` forces all pages to be marked dirty even when both tree
files exist, so their hashes are recomputed on the next hash-tree update." The constructor of the replaced range does
mark the whole dirty-page tree dirty (its comment says "Rebuild the entire dense tree when requested or when its
backing files cannot be reused"). When the machine is created with those files, the dense tree is rebuilt and the
root is the content hash.

`replace_memory_range` uses the same constructor, but on a machine that has already completed one hash-tree update
`hash_tree::m_bubble_up_unchanged_pages` is `false`. The next update recomputes each page hash, finds that it equals
the leaf stored in the `.dht`, and marks the page clean "because its contents already matched its hash" without
adding the range to the changed list. The inner nodes of the supplied `.dht`, and its root, which ends up in the
sparse tree, are then kept as they are. The machine's root hash, `get_node_hash`, proofs built from those nodes, and a
snapshot written by `store()` all report a hash that is not the root of the contents. `verify_hash_tree()` still
returns `true`, so the emulator's own check does not catch it.

This violates R9 ("The content hash must equal the root of the actual contents. This applies to every cached,
incremental, or persisted hash, after any sequence of documented operations. It includes interrupted or failed
updates, and every snapshot the emulator itself writes.") and contradicts the manual's promise for
`mark_pages_dirty` and for a missing `.dpt`. It does not threaten the goal of section 1 on the honest operator's path
as known (see Rating): the production paths that obtain a template (load with `clear_hash_tree`) and deliver inputs
(`send_cmio_response`) do not go through `replace_memory_range`. It weakens the recovery tool the manual offers for
tree files that cannot be trusted: a user who replaces a range with tree files left by a crashed process and asks for
all pages to be recomputed gets a wrong root, and then a wrong snapshot.

### Component, role and area

- `machine::replace_memory_range` and `machine_address_ranges::replace`: "The rest of the machine API (C, Lua and
  JSON-RPC)", Honest operator only "where a production validator node plausibly calls it on the honest operator's
  path". No such caller is known for PRT (inputs are delivered with `send_cmio_response`, templates are loaded), so
  the preferred rating treats it as off the honest path.
- The hash tree (`hash_tree::update`, `return_updated_dirty_pages`): Honest operator, but it shows the defect only
  for a range that appears after the first update, which only `replace_memory_range` produces.
- `memory_address_range` (the constructor that honours `mark_pages_dirty`): part of the same path.

### Location

- `src/hash-tree.cpp`, `hash_tree::update` (line 758): `m_bubble_up_unchanged_pages = !update_succeeded;` is the only
  write after construction (`src/hash-tree.hpp:255`, default `true`).
- `src/hash-tree.cpp`, `hash_tree::return_updated_dirty_pages` (from line 278, branch at 386-393): an unchanged page
  hash with the flag `false` calls `mark_clean_page_and_up` instead of adding the range to `changed_ars`.
- `src/memory-address-range.cpp`, constructor (lines 76-79): `mark_pages_dirty` or an empty tree filename only calls
  `m_dpt.mark_dirty()`.
- `src/machine-address-ranges.cpp`, `machine_address_ranges::replace` (662-686), comment "This will automatically
  start with all pages dirty."; `src/machine.cpp`, `machine::replace_memory_range` (723-779) does not tell the hash
  tree that a range was replaced.

### Evidence and test

`bugs/R5-INVHASH-1/` contains `test.lua` (the test), `README.md` (what it asserts) and this entry. Run it with
`bugs/run.sh R5-INVHASH-1`; it takes about a second and works in a `mktemp -d` directory that it removes.

The test builds an 8-page flash drive. Image B's emulator-written `.dht` and `.dpt` come from storing a fresh machine
that holds B; a copy of the `.dht` keeps the 8 true leaves (page hashes) and overwrites the 7 inner nodes with `0xEE`.
A machine with image A computes its root once, then replaces the drive with B and the crafted `.dht`, (1) with the
`.dpt` and `mark_pages_dirty = true`, and (2) without `dpt_filename`. It asserts that `get_root_hash()` equals the root
of a fresh machine holding B, that `get_node_hash(start, 15)` equals the range's content hash, and, for (2), that a
snapshot written by `store()` and synced with `sync_stored()` has a cached root equal to the root rebuilt with
`clear_hash_tree = true`. Control (exit 2 if it fails): the same backing stores at machine creation give the content
hash. On audit/prt2 (d7e126c) it prints, three runs identical:

```
content hash (fresh machine, image B):     ff90e966f0c00e09d6858ae8a617a083d8341e6c3b35286869104489a43101dc
creation with mark_pages_dirty tree files: ff90e966f0c00e09d6858ae8a617a083d8341e6c3b35286869104489a43101dc
creation with .dht but no .dpt:            ff90e966f0c00e09d6858ae8a617a083d8341e6c3b35286869104489a43101dc
[mark_pages_dirty=true] root after replace:         3822f18da58ae052f14d1444b62b7fe02150fcd784706bcb424a0d71a504a2dc
[mark_pages_dirty=true] range node after replace:   eeeeeeee...eeee (content: 0d674deb903a1e2b70b4576a4c97fcc8e42b3072906d2007f869d2899047e966)
[mark_pages_dirty=true] verify_hash_tree():         true
VIOLATED: [mark_pages_dirty=true] root hash after replace_memory_range equals the content hash (R9, manual)
VIOLATED: [mark_pages_dirty=true] node hash of the replaced range equals its content hash (R9)
[no dpt_filename] (same three lines and two violations)
[no dpt_filename] stored snapshot cached root: 3822f18d... rebuilt: ff90e966...
VIOLATED: [no dpt_filename] snapshot written by store() has a cached root equal to its rebuilt root (R9)
run.sh: R5-INVHASH-1: exit 1 (bug present)
```

The reviewer added the `sync_stored()` call to the prover's test so the snapshot is one that O2 guarantees; the
result is unchanged. A separate reviewer check isolated the cause: the same replace done before any hash-tree update
gives the content hash; done after one update it does not; an emulator-written, internally consistent `.dht` and no
`.dht` at all both give the content hash. Found, proved and reviewed on Opus 5.5; no fallback model.

### Trigger and reachability

A trusted caller of the machine API calls `replace_memory_range` with a `backing_store` that names a `.dht` whose inner
nodes do not match its leaves, together with `mark_pages_dirty = true` or without a `.dpt`, on a machine that has
already computed a root hash, a proof, a log or a computation hash. All fields used are documented. A `.dht` of that
kind is not written by a clean `store()`; it is what a process that stopped while updating a shared tree file can
leave (O2), or a file from another party, which are exactly the cases where a user asks for all pages to be
recomputed. Guests and input senders cannot trigger it. It is not a guest-reachable state question: the state
(contents) is correct; only the cached hash is wrong.

### Rating

1. Out of scope: not excluded. "The effect of a deliberate state change made through the machine API, when the API
   performs it as documented" does not apply: the contents are replaced as asked, but the API does not recompute the
   hashes the manual says it recomputes. "Defects triggered only by loading a snapshot that the emulator did not write
   and that does not meet the conditions of a valid template" and "Defects that need the cached hash-tree data of a
   stored machine the operator did not produce to survive its adoption without a rebuild (O1)" are about adopting a
   stored machine; here no snapshot is loaded, and the caller asked for the range's pages to be recomputed, which the
   same files honour at creation. The snapshot that comes out wrong is one the emulator writes itself and syncs.
2. Role: the operation is `replace_memory_range`, "The rest of the machine API (C, Lua and JSON-RPC)", which is
   Honest operator only "where a production validator node plausibly calls it on the honest operator's path". The
   PRT honest path (section 2: obtaining the template with the O1 rebuild, delivering inputs, storing, reloading)
   does not call it. The hash tree is Honest operator, but no honest-path operation adds a range after the first
   update. Preferred: off the honest path.
3. High and Medium cases: Medium, "A machine API operation off the honest operator's path that, used as documented,
   leaves the hash tree, the cached state of the machine or a stored directory inconsistent with the machine's
   contents (R9)." It covers this component and this symptom: root, node hashes and a synced stored directory
   disagree with the contents after documented calls. Also "A contradiction between the manual and the behavior on a
   security-relevant point ... takes the severity it would have if the manual were right."
4. Critical: would apply only on the honest operator's path (R9 "after any sequence of documented operations ... every
   snapshot the emulator itself writes"). If a production node replaced ranges with tree files it had not written and
   relied on `mark_pages_dirty` instead of `clear_hash_tree`, this would be Critical; no such node is known.

Readings: Medium (preferred) treats supplying any `.dht` with `mark_pages_dirty = true` or without a `.dpt` as
documented use, because the manual says all pages are then marked dirty and recomputed and the code's own comment and
creation path rebuild the whole dense tree. Low applies if a `.dht` whose inner nodes do not match its leaves counts as
"a failure that needs misuse of an API by its trusted caller" (section 4: callers are "trusted in intent, not in
data", but tree files are cached hash-tree data, not data from other parties). Critical applies only if a production
validator node calls `replace_memory_range` with such files on the honest path. The deciding facts are whether the
manual's `mark_pages_dirty` promise extends to the inner nodes (the code comment says it does) and whether any
production node uses `replace_memory_range` on its path.

### Possible solution and risks

When a range is replaced, make the next update rebuild it: set `m_bubble_up_unchanged_pages = true` (or a per-range
"rebuild" flag) from `machine::replace_memory_range`, or have `return_updated_dirty_pages` add a range to
`changed_ars` whenever its dirty-page tree was marked dirty by construction (`mark_pages_dirty` or a missing tree
file). A per-range flag avoids rehashing every other range's unchanged pages; a global flag costs one extra
bubble-up pass over all dirty pages once. Either should also make `verify_hash_tree()` compare inner nodes with their
children for replaced ranges. Risk: low; the change only adds work for ranges that the emulator already treats as
fully dirty.

### Risk of not fixing it

A user who replaces a range with tree files it cannot trust (left by a crashed process, or received from another
party) and relies on the documented `mark_pages_dirty` or on omitting the `.dpt` gets a root hash, proofs and a stored
snapshot that do not match the contents, and `verify_hash_tree()` does not detect it. If such a hash were committed,
the claim would lose. Only a trusted caller can trigger it. Mitigation outside the code: after `replace_memory_range`
with supplied tree files, call `clear_hash_tree()` (or omit `dht_filename`, which uses a zeroed tree that is always
rebuilt), or load with `clear_hash_tree = true` before computing hashes.
