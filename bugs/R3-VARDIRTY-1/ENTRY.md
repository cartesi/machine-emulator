## R3-VARDIRTY-1

**Title.** An exception inside `hash_tree::update`, after new page hashes are stored, leaves `m_bubble_up_unchanged_pages` false, so the ancestors of those pages are never recomputed and later root hashes, proofs and snapshots are wrong

**Severity.** Critical (preferred reading: a host fault turned into a wrong hash, which R9 covers for failed updates). Low under the alternative reading that an allocation failure is not a host fault the model covers, or that continuing after an API error is misuse.

### Problem

`hash_tree::update` runs three phases: `update_dirty_pages`, `update_dense_trees` and `update_sparse_tree`.
`update_dirty_pages` hashes every dirty page and writes the new page hash into the page node of the address
range's dense tree. The dense-tree ancestors and the sparse tree are recomputed only in the two later phases. Only
after all three phases return does `update` assign `m_bubble_up_unchanged_pages = !update_succeeded`. The flag exists
for exactly this situation. Its declaration in `hash-tree.hpp` says "Stored dense trees left by an interrupted update,
or a failed one, may hold the new hashes of dirty pages without those of their ancestors", and the comment at the
assignment says "a failed update may already have stored their new hashes". A failure reported by return value is
handled. A C++ exception that escapes a later phase skips the assignment and leaves the flag false. In practice this
is `std::bad_alloc` from the `pmr` batch reservation in `update_dense_trees`, which requests up to 256 KiB from the
upstream allocator on every update with a changed range, or from the allocations in `update_sparse_tree`.

The pages stay marked dirty, because `clean()` runs only on success. On the next update, their stored page hashes
already equal their contents, so `changed` is false. With the flag false, `return_updated_dirty_pages` calls
`mark_clean_page_and_up` for each of them instead of adding the range to `changed_ars`. Their ancestors in the dense
tree and the sparse tree are never recomputed. The cached root then stays wrong until `clear_hash_tree()`.
`verify_hash_tree()` still returns true, because it compares pages only with their page nodes. Every later
`get_root_hash`, `get_node_hash`, `get_proof`, `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`
on that machine reads the stale tree, and so does a snapshot stored from it. This is a completeness failure of section
1: "The honest operator computes a wrong hash".

### Component, role and area

The hash tree (`src/hash-tree.cpp`, `src/hash-tree.hpp`), reached through `machine::update_hash_tree` from
`get_root_hash`, `get_node_hash`, `get_proof` and the computation-hash collectors. AUDIT.md table: "Interpreter,
state-access layers, devices, uarch program, hash tree, log producers, `collect_mcycle_root_hashes` and
`collect_uarch_cycle_root_hashes`, input delivery, and storing, loading, cloning and syncing machines | Honest
operator". Area: exception safety of the incremental hash-tree update.

### Location

- `src/hash-tree.cpp`, `hash_tree::update` (lines 758-771). The flag is assigned only on normal return (line 769).
- `src/hash-tree.cpp`, `hash_tree::update_dense_trees` (lines 503-535). The batch reservation
  `batch.reserve(batch_size)` with `batch_size = min(m_concurrency << 10, 16384)` (lines 508-510) is an upstream
  allocation of 16-byte entries, 16384 bytes at concurrency 1.
- `src/hash-tree.cpp`, `hash_tree::update_sparse_tree` (from line 537): further allocations (`changed_backing`,
  `marked`) after the page hashes are stored.
- `src/hash-tree.cpp`, `hash_tree::return_updated_dirty_pages` (lines 380-398). `if (changed ||
  m_bubble_up_unchanged_pages)` decides whether to bubble up or call `mark_clean_page_and_up` (line 393).
- `src/hash-tree.hpp` lines 252-255: declaration and documented purpose of `m_bubble_up_unchanged_pages`.
- `src/machine.cpp`: `machine::update_hash_tree` (line 1645), called by `get_root_hash` (1652), `get_node_hash`
  (1710), `get_proof` (1723), `collect_mcycle_root_hashes` (2451, 2520) and `collect_uarch_cycle_root_hashes` (2780).

### Evidence and test

`bugs/R3-VARDIRTY-1/` contains:

- `test.sh`: builds `fail-new.cpp` with `g++` into a temporary directory and runs `check.lua` under `LD_PRELOAD`.
  It maps any status other than 0 and 1 to 2.
- `fail-new.cpp`: an LD_PRELOAD fault injector that replaces the global `operator new`. While an arm file exists,
  it throws `std::bad_alloc` for the first request of exactly `FAIL_NEW_EXACT` (16384) bytes, as an allocator under
  a memory limit would, and counts each injected failure in a file.
- `check.lua`: a machine with 64 MiB of RAM and runtime `concurrency.update_hash_tree = 1`, so the dense-tree batch
  is 16384 bytes on any host. The control runs the same operations without a fault and requires the cached root to
  equal the root rebuilt by `clear_hash_tree()` (else exit 2). The faulty run calls `get_root_hash`, writes to 64
  distinct pages, and arms the injector. `pcall(get_root_hash)` must then fail with exactly one injected failure
  (else exit 2). The test disarms the injector and makes one more `write_memory`, so the process keeps using the
  machine. It then asserts that `get_root_hash()` equals the root after `clear_hash_tree()`. If the later call fails
  loudly instead, the test passes.
- `README.md`: description and expected output.

Run with `bugs/run.sh R3-VARDIRTY-1` (about 2 s). The prover ran it twice and the reviewer three more times. It exits 1
on audit/prt2 every time, with identical output:

```
control: no fault, cached root == rebuilt root 0xb6640061f50463f54f05c6429f157bf4dbc257bc0042689161b4d929483c4690
get_root_hash failed as injected (16384-byte dense-tree batch reservation): std::bad_alloc
get_root_hash() after the failure  0x14b95ed6e4817e645550c788100cbb8a56f2f4907f80b6370f60cdecf54a972e
root rebuilt by clear_hash_tree()  0xb6640061f50463f54f05c6429f157bf4dbc257bc0042689161b4d929483c4690
verify_hash_tree() after the failure true
VIOLATED: R9: after hash_tree::update fails inside a running process (host allocation failure), get_root_hash() must equal the root of the actual contents
run.sh: R3-VARDIRTY-1: exit 1 (bug present)
```

The reviewer made two further checks with scratch builds and scripts that are not part of `bugs/R3-VARDIRTY-1/`:

- **Fix check.** The reviewer recompiled only `hash-tree.cpp` with `m_bubble_up_unchanged_pages = true;` inserted
  before the three phases of `hash_tree::update`, and relinked `cartesi.so` from the in-tree objects. Against that
  module the same `test.sh` prints `get_root_hash() after the failure 0xb664...` and exits 0. Relinking without the
  change still exits 1.
- **Snapshot check.** In a variant of `check.lua`, `m:store(dir)` runs after the failure. Loading that snapshot gives
  root `0x14b9...`, and after `clear_hash_tree()` it gives `0xb664...`, so the stored cached hash-tree data is
  stale too.

Found, proved and reviewed on Opus 5.5. No fallback model was used.

### Trigger and reachability

Two things are needed. First, a hash-tree update with at least one changed range. This happens on every
`get_root_hash`, proof or computation-hash collection after the guest or a delivery writes memory, which is the
normal case on the honest operator's path. Second, an exception escapes `update_dense_trees` or
`update_sparse_tree`. On that path this is a host allocation failure. `update_dense_trees` requests its batch, up to
256 KiB, from the upstream allocator on every such update: the test injects the failure after an earlier successful
update and still hits it. The request can throw `std::bad_alloc` under `RLIMIT_AS`, a container memory limit or a
memory-capped host. The error reaches the caller. `cm_get_root_hash` and the other C API calls return an error code.
The Lua binding raises an error, and the JSON-RPC server reports it and keeps serving the same machine. A node that
then retries, keeps using the machine or stores it gets wrong hashes from then on. The guest can raise the number of
dirty pages per update, but the fault itself comes from the host. No unreachable state is involved, and any guest
that writes memory sets up the precondition.

### Rating

1. Out of scope: not excluded. The relevant exclusion is "Host faults, such as a full disk, as long as the emulator
   does not turn them into a wrong hash, a wrong proof, or a directory that O2 guarantees but that later loads as a
   different state (section 4)". Here the emulator turns the fault into a wrong hash and a stale stored snapshot, so
   the exclusion does not apply. Section 4 says the same: "A host fault ... may stop the honest operator, but the
   emulator must never turn one into a wrong hash, a wrong proof, or a directory that O2 guarantees but that later
   loads as a different state." No other exclusion applies. The machine is created in-process, so no directory that
   O2 does not guarantee is reloaded. No untrusted party calls the API, and every call is a documented one.
2. Role: the hash tree, reached through `get_root_hash` and the computation-hash collectors. AUDIT.md lists "hash
   tree, ... `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`" as "Honest operator". Section 3:
   "The transition function, its log producers, the computation-hash builders, the hash tree and its node proofs ...
   play this role in every deployment." The clause covers this component directly.
3. High and Medium cases: none fits. The only candidate is "A machine API operation off the honest operator's path
   that, used as documented, leaves the hash tree, the cached state of the machine or a stored directory inconsistent
   with the machine's contents (R9)". It does not fit: `get_root_hash`, proofs and the collectors are on the honest
   operator's path ("Computing claims", "Producing proofs", "Storing and reloading the machine"). No High case
   fits, because the state is reachable and no data from other parties is involved.
4. Critical: R9 is violated on the honest operator's path. "R9. Hash integrity. The content hash must equal the root
   of the actual contents. This applies to every cached, incremental, or persisted hash, after any sequence of
   documented operations. It includes interrupted or failed updates, and every snapshot the emulator itself writes."
   and "'Interrupted or failed updates' means updates that fail inside a running process, which then keeps using the
   machine." A failed incremental hash-tree update in a running process is the literal case. Section 8: "violating
   any rule or obligation at a reachable state, or anywhere on the honest operator's path, is critical."

Two readings, as for R1-O2-3. Critical (preferred): an allocation failure is a host resource fault like the full disk
named in section 4, and R9 explicitly covers a process that keeps using the machine after a failed update. The code
itself also intends failed updates to be recoverable: the flag's documented purpose is this case. Low: an allocation
failure could be read as outside "host faults", or as impossible on a host provisioned "on the resources the
deployment was sized for". Continuing after an API error could also count as "a failure that needs misuse of an API
by its trusted caller". Two facts would decide it: whether the host-fault clause covers memory exhaustion (it says
"such as a full disk", which suggests resource faults in general), and whether the manual or `cm.h` documents that a
machine must be discarded after a failed call. Neither currently does, and R9's definition says the opposite.

### Possible solution and risks

In `hash_tree::update`, set `m_bubble_up_unchanged_pages = true` before the three phases and set it to
`!update_succeeded` only after they return. A scope guard that leaves it true on any exit works too. With this
change, the next update bubbles up every page still marked dirty, as it already does after a failure reported by
return value. The reviewer's scratch build confirms that the test then exits 0. Check `update_words` and
`update_page` for the same pattern, where a page node is written before its ancestors. The update could also avoid
upstream allocations after the first page hash is stored, for example by reserving all batches up front. Risks: the
first update after any failure rehashes the ancestors of all dirty pages, which matters for performance only after
an error. Setting the flag on entry has no cost on success.

### Risk of not fixing it

Suppose a validator node's host hits a memory limit while it updates the hash tree, and the node retries or keeps the
machine, for example a long-running JSON-RPC machine server or a Lua or C node that reports the error and goes on. It
then silently computes wrong root hashes, computation hashes and proofs, and `verify_hash_tree()` does not detect
it. A snapshot it stores afterwards reloads with the wrong root. Its honest claim can then be wrong or unprovable,
and a dishonest claim can win. Mitigations outside the code: treat any failed `get_root_hash`, proof or collection
call as fatal for the machine and reload from the last guaranteed snapshot, or call `clear_hash_tree()` before using
the machine again.
