## R1-O2-3

**Title.** A failed `collect_mcycle_root_hashes` loses the dirty marks it holds only in its context, so the hash tree, later root hashes and stored snapshots no longer match the machine's contents

**Severity.** Critical (preferred reading: a host fault turned into a wrong hash, which R9 covers for failed updates). Low under the alternative reading that an allocation failure is not a host fault the model covers.

### Problem

During `collect_mcycle_root_hashes`, the interpreter runs with `collect_mcycle_hashes_state_access`. That state
access records two kinds of writes only in a local `context.dirty_pages` set: memory writes that do not go through
the write TLB (`do_write_memory_word`, used for example by the page walk when it sets a PTE's A or D bit) and
writes to the shadow TLB (`do_write_tlb`). The collection copies those marks into the dirty page trees only after
`interpret_with_console` returns. The `try` around the call catches only `machine_console_exception`. Any other
exception thrown inside the interpreter, for example `std::bad_alloc` when `context.dirty_pages` grows past its
reservation of 4096 pages under a memory limit, unwinds and drops the set. The contents have changed, but the
affected pages are not marked dirty. Every later `update_hash_tree` skips them. The cached root hash, node hashes and
proofs then no longer match the contents. The caller gets an error and keeps the machine (Lua, C API, JSON-RPC
server). If it keeps using it, as R9 allows, every later root hash, computation hash and proof it produces from that
machine is wrong, which is a completeness failure of section 1 ("The honest operator computes a wrong hash"). A
snapshot stored afterwards carries the stale cached hash-tree data, and loading it gives the wrong root.

### Component, role and area

`collect_mcycle_root_hashes` and its state access `collect_mcycle_hashes_state_access`, with the hash tree's dirty
page tracking. AUDIT.md table: "Interpreter, state-access layers, devices, uarch program, hash tree, log producers,
`collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, ... | Honest operator". Area: error handling of
the mcycle hash collection (dirty-page bookkeeping on an exception).

### Location

- `src/machine.cpp`, `machine::collect_mcycle_root_hashes`: `context` declared at line 2472. The `try`/`catch
  (const machine_console_exception &)` around `interpret_with_console` is at lines 2495-2510. The marking of
  `context.dirty_pages` into the dirty page trees, which runs only after a normal return, is at lines 2512-2517.
- `src/collect-mcycle-hashes-state-access.hpp`: `mark_dirty_word` (lines 77-83, inserts into `m_c.dirty_pages`),
  `do_write_memory_word` (lines 464-467), `do_write_tlb` (lines 497-501), `do_write_mcycle` (lines 147-158).
- `src/translate-virtual-address.hpp:77`: the page walk writes the PTE A/D update with `a.write_memory_word`, which
  does not use the write TLB.
- Reservation of the set: `src/machine.cpp:2482` (at most 4096 entries); growth beyond it allocates.

### Evidence and test

`bugs/R1-O2-3/` contains:

- `test.sh`: builds `fail-new.cpp` with `g++` into a temporary directory and runs `check.lua` under `LD_PRELOAD`.
- `fail-new.cpp`: a fault injector that replaces the global `operator new`. While an arm file exists, every request
  of at least 100000 bytes throws `std::bad_alloc`, as an allocator under a memory limit would. Inside the armed
  collection the only such request is the rehash of `context.dirty_pages` when it grows past 4096 pages.
- `guest.lua`: assembles a bare-metal guest (no toolchain needed). In M-mode it writes one Sv39 1 GiB identity leaf
  PTE with A=0 and D=0 at 0x80010010, sets `satp`, runs `sfence.vma` and enters S-mode. It spins, then stores to
  8000 distinct pages. The first store makes the page walk set the D bit, a write to the page-table page outside the
  write TLB.
- `check.lua`: runs a control (the same collection without a fault must leave `get_root_hash()` equal to the root
  rebuilt by `clear_hash_tree()`, else exit 2). It then runs the machine to mcycle 1000000, arms the injector, calls
  `collect_mcycle_root_hashes(start + 2^24, 24, 0, 0)` under `pcall`, requires that the failure was injected and
  that the D bit is now set (else exit 2), and asserts that `get_root_hash()` equals the rebuilt root and that
  `verify_hash_tree()` is true.
- `README.md`: description and expected output.

Run `bugs/run.sh R1-O2-3` (about 3 s). On audit/prt2 it exits 1 on every run (prover: 4 runs; reviewer: 2 more
runs, identical output):

```
control: no fault, cached root == rebuilt root 0xc458e981dcffb765bef61ae9f90223981ff6507f175d36f02f3fecd16c5ea93c
collect_mcycle_root_hashes failed as injected: std::bad_alloc
after the failure: mcycle=1000000 (started at 1000000), leaf PTE at 0x80010010 = 0x200000cf (D bit set)
page 0x80010000 (in RAM) is not marked dirty but is dirty
! FAILED!
get_root_hash() after the failure    0x53e7b6b510b05d7fe2b78bc0dedf3bbb3ace4d456b1c67094d871a82fef3ff3c
root rebuilt by clear_hash_tree()    0xd6fa527c0529e1b0090a3779c67a15912dc88233ce93697318df983de74a3713
verify_hash_tree() after the failure false
page-table page 0x80010000 node hash: cached 0x9240..., rebuilt 0xde53...
VIOLATED: R9: after collect_mcycle_root_hashes fails inside a running process (host allocation failure), ...
run.sh: R1-O2-3: exit 1 (bug present)
```

`verify_hash_tree()` names exactly the page-table page. The reviewer also checked, with a scratch variant of
`check.lua` that is not part of `bugs/R1-O2-3/`, that `m:store(dir)` after the failure writes a snapshot whose loaded
root hash is the stale 0x53e7... while the root rebuilt from its contents is 0xd6fa....

Side observation, not asserted: after the failure, `mcycle` keeps its starting value while other registers and
memory have advanced, because the interpreter writes `mcycle` only when it leaves its loop. That is a related
consequence of the same unhandled exception and is not covered by this test.

### Trigger and reachability

Two things are needed. First, during a collection period the guest makes a write that does not go through the write
TLB or refills the TLB. Any guest with paging does this all the time (PTE A/D updates on page walks, shadow TLB
refills), including the Linux guests of every template. Second, an exception other than a console error is thrown
inside the interpreter. On the honest operator's path this is a host allocation failure. The only allocation inside
the interpreter is the growth of `context.dirty_pages`, which happens when a period touches more than 4096 distinct
pages. A guest can do that with ordinary stores (the test touches 8000), within the linear cost of R12. Under
`RLIMIT_AS`, a container memory limit or a memory-capped host, that allocation can fail with `std::bad_alloc`. The
error reaches the caller (`cm_collect_mcycle_root_hashes` returns an error; the JSON-RPC server catches
`std::exception` and keeps serving the same machine), and a node that retries or keeps using the machine, or
stores it, computes from a hash tree that no longer matches the contents. No unreachable state is involved.

### Rating

1. Out of scope: not excluded. The relevant exclusion is "Host faults, such as a full disk, as long as the emulator
   does not turn them into a wrong hash, a wrong proof, or a directory that O2 guarantees but that later loads as a
   different state (section 4)". Here the emulator turns the fault into a wrong hash, so the exclusion does not
   apply. Section 4 says the same: "A host fault ... may stop the honest operator, but the emulator must never turn
   one into a wrong hash". No other exclusion applies: the machine was not loaded from a directory O2 does not
   guarantee, no untrusted party calls the API, and the API is used as documented (`cm.h` documents no state of the
   machine as unusable after an error).
2. Role: `collect_mcycle_root_hashes`, its state access and the hash tree are listed in the AUDIT.md table as
   "Honest operator". Section 3: "the computation-hash builders, the hash tree and its node proofs ... play this role
   in every deployment." The clause covers this component directly.
3. High and Medium cases: none fits. The only candidate is "A machine API operation off the honest operator's path
   that, used as documented, leaves the hash tree ... inconsistent with the machine's contents (R9)". It does not
   fit, because computing claims ("Computing claims" in the honest operator's path) is exactly what
   `collect_mcycle_root_hashes` does. No High case fits: the state is reachable, and no data from other parties is
   needed.
4. Critical: R9 is violated on the honest operator's path. "R9. Hash integrity. The content hash must equal the root
   of the actual contents. This applies to every cached, incremental, or persisted hash, after any sequence of
   documented operations. It includes interrupted or failed updates, and every snapshot the emulator itself writes."
   and "'Interrupted or failed updates' means updates that fail inside a running process, which then keeps using
   the machine." Section 8: "violating any rule or obligation at a reachable state, or anywhere on the honest
   operator's path, is critical."

Two readings. Critical (preferred): an allocation failure is a host resource fault like the full disk named in
section 4, and R9 explicitly covers a process that keeps using the machine after a failed update. Low: if an
allocation failure inside the interpreter is read as outside "host faults", or as impossible on a host provisioned
"on the resources the deployment was sized for", or if continuing after an API error counts as "misuse of an API by
its trusted caller". What would decide it: whether the model's host-fault clause covers memory exhaustion (the
text names "such as a full disk", which suggests resource exhaustion in general), and whether the manual documents
that a machine must be discarded after any failed call (it currently does not; R9's definition says the opposite).

### Possible solution and risks

Copy `context.dirty_pages` into the dirty page trees on every exit from the interpreter, normal or exceptional,
for example with a scope guard or a `catch (...)` that marks and rethrows, in `machine::collect_mcycle_root_hashes`
(and check `collect_uarch_cycle_root_hashes` and every other path that uses a context-only dirty set for the same
pattern). Alternatively, conservatively mark the whole affected address ranges dirty, or invalidate the hash tree,
when an exception escapes. The marking on the error path should not allocate, so that it cannot fail for the same reason.
The page whose insertion threw had not been written yet (`do_write_memory_word` marks before writing), so it needs no
mark. Separately, the interpreter should write `mcycle` back, or the machine should be declared unusable, when an
exception escapes, because otherwise the state itself is left in a combination no execution reaches. Risks: a
`catch (...)` must not swallow the exception or change the collection's results on success; a performance cost only
on the error path.

### Risk of not fixing it

A validator node whose host hits a memory limit during hash collection, and that retries or keeps the machine (for
example a long-running JSON-RPC machine server), silently computes wrong root hashes, computation hashes and
proofs from then on, and a snapshot it stores afterwards reloads with the wrong root. Its honest claim can then be
wrong or unprovable, and a dishonest claim can win. The guest can raise the chance by touching many pages per period,
but the fault itself comes from the host. Mitigation outside the code: treat any error from
`collect_mcycle_root_hashes` (other than a reported console error) as fatal for the machine, discard it and reload
from the last guaranteed snapshot, or call `clear_hash_tree()` (or verify with `verify_hash_tree()`) before using it
again.
