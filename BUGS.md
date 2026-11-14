# Bugs

Confirmed issues of the audit, ordered by severity. Severities, roles and rules follow `THREAT_MODEL.md`. The process
and every rejected candidate are in `AUDIT_REPORT.md`. Run a test with `bugs/run.sh <ID>`; it exits 1 while the bug is
present and 0 once it is fixed. IDs take the form `R<round>-<ANGLE>-<n>`: the round, the hunter's angle, and the
candidate's number within that angle.

Flags required by `AUDIT.md` (fallback-only confirmations, issues without a proof of concept, tests that model a
component instead of running it):

- None yet.

Where the threat model can be read two ways, the severity column gives the reviewer's preferred reading first.

| ID | Title | Component | Role | Cited rules | Severity |
|---|---|---|---|---|---|
| [R1-O1-2](#r1-o1-2) | Unhashed config.json hash_tree.phtc_size survives clear_hash_tree, so a template's distributor sets the honest operator's adoption memory without bound (12 kB/entry) | Emulator core: loading stored machines (machine_config::load, hash_tree / page_hash_tree_cache sized from stored phtc_si | Honest operator | Section 8 OOS snapshot clause, R12, R4, O1 (section 5), section 2 honest operato | Critical / Low (if the whole template directory, unhashed config included, is trusted input) |
| [R1-O2-3](#r1-o2-3) | Failed collect_mcycle_root_hashes (non-console exception, e.g. bad_alloc) drops context-only dirty marks; hash tree, later roots and stored snapshots mismatch contents | collect_mcycle_root_hashes / collect_mcycle_hashes_state_access / hash tree dirty tracking | Honest operator | R9, section 4 (host faults), section 1 completeness | Critical (preferred: host fault turned into a wrong hash, R9 failed update) / Low (if memory exhaustion is not a covered host fault or continuing after an error |
| [R1-O1-3](#r1-o1-3) | PRT player's store_first_epoch_checkpoint loads the template without clear_hash_tree and records a cached-tree root that crisium compares with the on-chain hash, so a valid template is refused | PRT player in doc/recipes: prt.lua store_first_epoch_checkpoint (2743-2776), assert_rolling_template; crisium.lua:236; p | Support (AUDIT.md: "The PRT player and bridge in doc/recipes | O1, section 5 binding clause, section 2 honest operator's path (obtaining the va | Medium (preferred reading); Out of scope under the literal-exclusion reading |
| [R1-O2-1](#r1-o2-1) | PRT stored player, after a power loss, restarts from its unsynced machine.revert clone, deletes the synced epoch machine, trusts the stale cached hash tree, and records wrong roots. | doc/recipes/prt.lua stored player: stored_machine_pair_methods:commit, revert_interrupted_input, reopen_epoch_directory | Support (PRT player), standing in for the honest operator | O2, R4, section 5 (O1/O2 bind reference implementations), section 3 Support | Medium (Out of scope under a literal reading of the O2 reload exclusion) |
| [R1-O2-2](#r1-o2-2) | Reopening a sealed epoch after a stop past the seal commit replaces the synced epoch machine with an unsynced clone and deletes machine.revert, leaving no O2-guaranteed copy | PRT stored player epoch directory, doc/recipes/prt.lua (seal_epoch_state, revert_interrupted_input, reopen_epoch_directo | Support (PRT player), standing in for the honest operator | O2, R4, section 5 (tools must follow O2), section 3 support rule | Medium (preferred); Out of scope under a broad reading of the host-fault exclusion |
| [R1-R2-1](#r1-r2-1) | write_reg("iunrep") changes the hashed unreproducible-mode register while every guard reads the config copy, so store writes a directory its own load refuses | machine::write_reg case reg::iunrep (src/machine.cpp ~1444); machine::is_unreproducible reading m_c config copy (src/mac | Rest of the machine API, off the honest operator's path (wri | R2, R14, R9 (section 8 Medium API-operation case), manual "creation-time mode" | Medium (preferred); Low under the trusted-caller-misuse reading; Out of scope if the deliberate-change exclusion is read to cover every consequence |
| [R1-R6-1](#r1-r6-1) | cartesi-machine --print-uarch-cycle-root-hashes passes a fake revert uarch tail {revert_root_hash, revert_root_hash}, printing wrong uarch hashes for the mcycle after a rejection | cartesi-machine CLI, src/cartesi-machine.lua uarch_cycle_root_hashes_runner_run | Support | R6, R4 (via section 3 support-Medium clause) | Medium (preferred: CLI printer counts as a tool that computes claims); Low (if read as a tool's diagnostics) |

<!--
Template for each issue. Copy it below the index, in the same order as the index.

## <ID>

**Title.** <one line>

**Severity.** <Critical | High | Medium>

### Problem

<What goes wrong, and how it threatens the security goal of section 1, or why it still violates a rule.>

### Component, role and area

<The component, its role from the AUDIT.md table, and the area within it.>

### Location

<Files and functions.>

### Evidence and test

<What `bugs/<ID>/` contains (test, guest programs, configurations, crafted logs or proofs, inputs, scripts), how to
run it, and what it prints on audit/prt2. Say which model found, proved and reviewed it if a fallback was used.>

### Trigger and reachability

<Who triggers it and how. For an unreachable state, why no input sequence from any valid template produces it.>

### Rating

1. Out of scope: <why not, quoting the exclusions checked>.
2. Role: <component and role, quoting section 3>.
3. High and Medium cases: <the case that fits, quoted, or why none does>.
4. Critical: <the rule or obligation violated at a reachable state or on the honest operator's path, quoted>.

<If two readings give different classes, give both and the facts that would decide.>

### Possible solution and risks

<The fix, and what it could break.>

### Risk of not fixing it

<What a deployment that leaves it unfixed is exposed to, who can trigger it, and any mitigation outside the code.>
-->

## R1-O1-2

**Title.** The unhashed `hash_tree.phtc_size` in a template's `config.json` survives the O1 rebuild, so whoever ships
the directory sets the memory the honest operator spends adopting it, without bound.

**Severity.** Critical (preferred reading). Low under the reading that the whole template directory, unhashed
configuration included, is trusted input (see Rating).

### Problem

The capacity of the page hash-tree cache, `hash_tree.phtc_size`, is read from the stored `config.json` of a machine
directory. It is not part of the hashed state: it does not change the root hash. Loading with
`clear_hash_tree = true`, the rebuild that O1 requires before an operator trusts the root hash of a template it did
not produce, clears the cache's contents but keeps its capacity. No runtime option can override the capacity. The
cache maps `phtc_size` entries of about 12 KiB each, and both its initialization and `clear()` write every entry.
The peak memory of adopting a template therefore grows linearly with a number that the template's distributor
chooses freely, independent of the machine's size. A sparse `hash_tree.phtc` of the matching length costs the
distributor no disk.

A distributor can thus ship a directory whose hashed contents form a valid template, and whose root hash after the
rebuild matches the on-chain commitment, but which the honest operator cannot adopt on the host the deployment was
sized for. The load either fails with an error, as when a memory budget makes the mapping fail, or is killed when
it exhausts the host's memory. An operator that cannot obtain its valid template cannot defend the honest claim.
That is a completeness failure (section 1). The inflated value is also copied into every directory the operator
later stores or clones from that machine.

### Component, role and area

Emulator core: loading stored machines. AUDIT.md component table: "Interpreter, state-access layers, devices, uarch
program, hash tree, log producers, ..., input delivery, and storing, loading, cloning and syncing machines |
Honest operator". The area is the hash tree's page hash-tree cache, sized from the loaded configuration.

### Location

- `src/machine-config.cpp`, `machine_config::load` and `adjust_ht_backing_store_config`: the stored `hash_tree`
  configuration, `phtc_size` included, is taken from `config.json`. Only the filenames and the sharing mode are
  adjusted. `src/json-util.cpp:1784` reads `phtc_size` with no bound.
- `src/hash-tree.cpp:979` (`hash_tree::hash_tree`): builds `m_page_cache` with `config.phtc_size`.
- `src/page-hash-tree-cache.hpp:413-453` (constructor): maps `get_storage_length(num_entries)`, calls
  `m_map.reserve(num_entries)`, and initializes every entry and payload of an uninitialized file. The checks at
  461-472 refuse only zero and `ptrdiff_t` overflow. `clear()` at 597-604 writes every payload.
- `src/machine.cpp:326` (`machine::machine`): `clear_hash_tree` runs `clear_hash_tree()` on the cache as sized.
  Nothing resets or bounds the capacity.
- `src/machine.cpp:504-516, 566`: `store` and `clone_stored` write or clone a phtc of the same capacity.
- `src/machine-runtime-config.hpp`: no runtime field sets the cache capacity.

### Evidence and test

`bugs/R1-O1-2/` contains `test.lua` (the test), `child.lua` (adopts one directory in a child process and reports its
root hash, peak RSS `VmHWM`, CPU time and loaded `phtc_size`), and `README.md`. Run it with
`bugs/run.sh R1-O1-2`. `R1O12_BIG=<n>` changes the large capacity, which defaults to 65536.

The test copies the harness's stored `baremetal-template` machine as the control. That machine has 64 MiB of RAM,
waits at a manual yield with the accepted reason, was stored with the default `phtc_size` 4096, and covers 19403
pages. The test then makes copies that differ only in `config.json` `hash_tree.phtc_size` (16384 and 65536), each
with an empty sparse `hash_tree.phtc` of the exact length. The length formula is checked against the file the
emulator wrote. Each copy is adopted as O1 requires, by loading without sharing with `clear_hash_tree = true` and
then calling `get_root_hash()`. The test requires the root hash to be unchanged. It also requires the peak memory to
be no larger than the larger of 2x the control's and the control's plus a cache covering every page of the machine.
Output on audit/prt2, the same on two reviewer runs apart from a few kB:

```
machine covers 19403 pages (75.8 MiB)
control: phtc_size=4096   VmHWM= 139732 kB cpu=0.28 s root=428a6bb8...ac75
crafted: phtc_size=16384  VmHWM= 287940 kB cpu=0.35 s root=428a6bb8...ac75  (2.06x control memory)
crafted: phtc_size=65536  VmHWM= 880080 kB cpu=0.77 s root=428a6bb8...ac75  (6.30x control memory)
marginal cost: 12.0 kB of peak resident memory per phtc entry (MID->BIG)
phtc_size survives clear_hash_tree: stored 65536 entries -> loaded 65536
allowed peak: 372568 kB (max of 2.0x control, control + 19403 pages x 12 KiB)
VIOLATED: R12 ... must cost at most 372568 kB of peak memory (bounded by the machine's size); observed 880080 kB, 6.30x the control's 139732 kB
run.sh: R1-O1-2: exit 1 (bug present)
```

Reviewer repair: the prover's limit was 2x the control alone. A fix that clamps the capacity to the machine's own
page count, about 323 MB here, would still have failed it. The limit now also allows the control plus 12 KiB per
page of the machine. The test still exits 1, with a 2.4x margin.

Two more reviewer checks, not part of the test:

- A machine created from a configuration with `hash_tree.phtc_size = 65536`, from the same template's config, is
  accepted. Its `store()` writes `"phtc_size":65536` and an 807 MB `hash_tree.phtc`. So a directory that the
  emulator itself writes, for a machine created from a configuration with no check disabled, carries the value.
- In a child under `prlimit --as=2GiB`, the control adopts normally (139 MB). The same contents with
  `phtc_size = 262144` fail to load, with `unable to map backing file '.../hash_tree.phtc' to memory: Cannot
  allocate memory`.

The trend is linear at about 12 kB per entry. By extrapolation, not run, about 2^20 entries (12 GB) exhaust this
16 GB host. Found, proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

The trigger is whoever produces or relays the template directory the honest operator adopts. They set
`hash_tree.phtc_size` in `config.json`, either at creation or by editing it, and ship a `hash_tree.phtc` of the
matching length, which may be sparse. The honest operator triggers the cost on its own path by following O1: it
loads the directory with `clear_hash_tree` to rebuild the cached data and compare the root hash with the on-chain
commitment. Every load path reads the value. The hashed contents are a valid template. The root hash is the
committed one, and the test checks this against the stored `root-hash.txt`. No unreachable state is involved.

### Rating

1. Out of scope: not excluded. The snapshot exclusion covers "Defects triggered only by loading a snapshot that the
   emulator did not write and that does not meet the conditions of a valid template (section 4)". The contents here
   meet every condition: "created from a configuration, without disabling any of the emulator's consistency
   checks", and with the committed content hash "after rebuilding its cached hash-tree data (O1)". An
   emulator-written directory with the same value exists (above). The same entry continues: "Once a snapshot meets
   them, nothing it carries outside the hashed state may affect any transition (R1), crash the honest operator, or
   corrupt its memory." That covers this case. The O1 exclusion ("Defects that need the cached hash-tree data of a
   stored machine the operator did not produce to survive its adoption without a rebuild (O1)") does not apply. The
   operator performs the rebuild, and the capacity survives it. Section 5 adds: "A defect that defeats the rebuild
   itself ... is not excused by them."
2. Role: Honest operator. Section 3: "storing, loading, cloning and syncing machines (within the limits of O1 and O2)
   play this role in every deployment". The AUDIT.md row quoted above lists loading machines as Honest operator.
   The clause covers this component directly. The defect is on the honest operator's path, section 2: "Obtaining its
   valid template. For a template the operator did not produce, this includes rebuilding its cached hash-tree data
   (O1)."
3. High and Medium cases: none fits. The constant-factor case is "A defect that lets the guest, or host load that
   the deployment was sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor".
   Here the trigger is neither the guest nor host load. The factor is not constant either: the distributor picks it
   freely, and the same entry says "When the sizing is unknown, rate ... a super-linear or unbounded one Critical."
   The cost does not arise only from unreachable states. No Medium case concerns loading on the operator's path.
4. Critical: violated on the honest operator's path. Section 8, Out of scope (snapshots): "nothing it carries outside
   the hashed state may ... crash the honest operator". The adoption fails, or exhausts the host's memory, from an
   unhashed value. R12: "storing, loading, cloning or syncing a machine" has a worst case "bounded and at most
   linear in the cycles it executes or the bytes it covers". The cost is set by `phtc_size`, not by the machine's
   contents. R4/section 1: an operator that cannot adopt its valid template "cannot respond in time". Section 8:
   "violating any rule or obligation ... anywhere on the honest operator's path, is critical."

Second reading, Low: section 4 lists "the valid template it chose to defend" as trusted and says "Snapshots are
trusted input". `phtc_size` is a documented configuration field (manual, "Fields `hash_tree.phtc_size` ... control
the *page hash-tree cache*"), plain in `config.json`. On that reading, choosing or accepting a huge value is a
trusted party's configuration choice that the deployment sizes for: "a failure that needs misuse of an API by its
trusted caller" (Low). Two facts would decide, and the text points to the first reading. First, whether the
section 8 sentence about what a snapshot "carries outside the hashed state" covers unhashed configuration values as
well as cached hashes. Second, whether "the bytes it covers" in R12 means the machine's state, or also the logical
length of a stored cache file. Taken literally, the second meaning would make even a sparse file count.

### Possible solution and risks

Do not take the cache capacity from the stored directory when it is adopted. Under `clear_hash_tree`, the file is
being rebuilt anyway. Either reset the capacity to the default or to a new runtime option, recreating
`hash_tree.phtc` at that length, or clamp it to the number of pages that the machine's address ranges cover.
Optionally also refuse, at creation and on load, a `phtc_size` above that page count.

Risks: the phtc file layout depends on the capacity, so a shared load must resize or recreate the file before
mapping it. Directories stored afterwards get a different `hash_tree.phtc` length, and tools that check that length
must follow. Operators that deliberately use a large cache for speed would need the runtime option. The root hash
must stay unaffected, because the cache is only a cache. The test checks this.

### Risk of not fixing it

Anyone who distributes or relays a template, for example an application's published snapshot or a mirror of it, can
make every honest operator that adopts it as O1 prescribes fail to load it. They can also make the load consume all
of the host's memory, while the directory's root hash still matches the on-chain commitment. The emulator offers no
documented setting against this. An operator can mitigate it outside the code. It can inspect `config.json` and
reset `hash_tree.phtc_size`, recreating `hash_tree.phtc` at the matching length, before loading. It can also build
the template itself from its configuration, or load under a memory limit and treat a failure as a sabotaged
directory.

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

## R1-O1-3

**Title.** The PRT player adopts the template without rebuilding its cached hash-tree data. `prt.store_first_epoch_checkpoint` records a root read from that cache, crisium compares it with the on-chain template hash, and a valid template whose cache is stale is refused on every start.

**Severity.** Medium

### Problem

`prt.store_first_epoch_checkpoint` is how the PRT player adopts the application's template. `prt-demo.lua` calls it before it launches the players, and once more for each sentinel. The function clones the template directory and loads the clone with `cartesi.machine(temporary_directory)`, which does not pass `{ clear_hash_tree = true }`. On the tree loaded from the cache, it runs `assert_rolling_template`, whose pristine-uarch check calls `get_node_hash`. It then writes `machine:get_root_hash()` into `epoch.json` as `initial_state_hash` and `final_state_hash`. The root it writes therefore comes from the cached hash-tree data, not from the contents.

Next, `crisium.lua` asserts that this `final_state_hash` equals the application's on-chain template hash ("epoch 0's checkpoint is not the template"). That is a comparison with the on-chain commitment made before any rebuild, which O1 forbids. The rebuild happens only later, in `new_stored_player`.

Take a valid template that someone else distributed and whose cached data does not match its contents. The player records a wrong hash for it and refuses to defend it. The checkpoint directory then exists, so on a relaunch `store_first_epoch_checkpoint` returns early, keeps the wrong hash, and the refusal repeats on every start.

In the role the player stands in for, this is a completeness failure: the honest operator cannot obtain its valid template, so it cannot respond, and a dishonest claim can win by default. The reverse case only fails later. If the cache matches the on-chain hash but the contents do not, crisium passes and `new_stored_player`'s rebuild then aborts. So the defect is a stall, not the adoption of a wrong state.

### Component, role and area

The component is the PRT player in `doc/recipes`. AUDIT.md lists it as "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs the player". The area is template adoption and the epoch-0 checkpoint.

### Location

- `doc/recipes/prt.lua`, `store_first_epoch_checkpoint`, lines 2743-2776. The load without a rebuild is at line 2757: `cartesi.machine(temporary_directory)`. The function also calls `assert_rolling_template` (lines 956-969) and records `template_hash = machine:get_root_hash()`.
- `doc/recipes/crisium.lua:236`: `assert(manifest.final_state_hash:lower() == template_hash, "epoch 0's checkpoint is not the template")`.
- `doc/recipes/prt-demo.lua:76` and `:131` call the function. `doc/recipes/prt.lua` `new_stored_player`, lines 3206-3218, is the only place where the template is rebuilt.

### Evidence and test

`bugs/R1-O1-3/` contains `test.lua` and `README.md`. Run the test with `bugs/run.sh R1-O1-3`. It takes about 3 s and needs the in-tree build and `bugs/harness/work/configs/baremetal-template`. It does the following:

1. It stores the harness `baremetal-template`, a valid template whose content hash is `0x428a6bb8...ac75`, together with its cached hash-tree data.
2. Control: on an untouched copy, `store_first_epoch_checkpoint` records the content hash.
3. It makes only the cached data stale. It overwrites 32 bytes at offset 96 of the RAM `.dht` and marks the RAM `.dpt` clean. No `.bin` file and no `config.json` changes. Control: loading with `clear_hash_tree` still gives `0x428a...ac75`.
4. It calls `prt.store_first_epoch_checkpoint(template, prt.new_geometry(10), out)` and requires that the recorded hashes equal the content hash.

On audit/prt2 it prints the following. The reviewer re-ran it twice and got the same output and exit 1 both times:

```
control: untouched template, epoch-0 checkpoint records 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
template content hash (rebuilt with clear_hash_tree): 0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
root read from the stale cached data (no rebuild):    0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint initial_state_hash: 0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint final_state_hash:   0x0f8f9593489424e02efc1b2d019ef86be51d4a29d95bb2b2e8e5faf93ac63f82
epoch-0 checkpoint machine rebuilt:    0x428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75 (differs from the manifest: new_stored_player would abort too)
VIOLATED: O1: adopting a stored machine rebuilds the cached hash-tree data, and only then compares/records the root hash (...)
run.sh: R1-O1-3: exit 1 (bug present)
```

The reviewer then tested the fix. It placed an out-of-tree copy of `prt.lua` first on `LUA_PATH_5_4`, with `{ clear_hash_tree = true }` added to that one load. The test then printed `0x428a...ac75` for both recorded hashes and "(matches the manifest)", and exited 0. Opus 5.5 found, proved and reviewed the issue, with no fallback.

### Trigger and reachability

Anyone who distributes the template directory can trigger this. They hand the operator a valid template whose cached hash-tree data does not match its contents: a stale, corrupted or deliberately altered `.dht`/`.dpt`, or a dirty-page record that is wrongly clean. The manual says the stored template "is the artifact distributed to anyone who wants to run the application in their own Cartesi Node", and it tells operators to load a directory they did not produce with `--clear-hash-tree` "before trusting its state hash".

Such a directory is still a valid template. Its contents, and the content hash rebuilt from them, are unchanged. THREAT_MODEL section 4 says: "A snapshot's cached hash-tree data is not part of any valid-template condition". No machine state has to be reached, because the trigger is the directory the operator adopts.

### Rating

1. **Out of scope: no, under the reading judged best supported.** The exclusion checked is "Defects that need the cached hash-tree data of a stored machine the operator did not produce to survive its adoption without a rebuild (O1)." Here the cache survives because the shipped tool itself skips the rebuild. Section 5 makes that the tool's defect: "O1 and O2 bind the emulator too. The tools and reference implementations that ship with it must follow them". That clause covers this component, a reference player shipped in `doc/recipes`. The snapshot exclusion ("loading a snapshot ... that does not meet the conditions of a valid template") does not apply, because the template is valid.
2. **Role: Support.** AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support." Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role the component stands in for, such as ... the honest operator for an implementation of an operator". The player is an implementation of an operator. No honest-operator component shares the defect: the emulator's `clear_hash_tree` rebuild works, as the test's control shows.
3. **High and Medium cases: Medium.** "A defect that only a support component shows, when section 3 rates it Medium." The stood-in role's rating, given in step 4, is Critical. No High or Medium case fits it in the honest-operator role, since it is not a case about unreachable states or data the operator may decline.
4. **Critical in the stood-in role.** Section 2, honest operator's path: "Obtaining its valid template. For a template the operator did not produce, this includes rebuilding its cached hash-tree data (O1)." O1: "rebuilds the cached hash-tree data from the contents when loading it, and only then compares the root hash with the on-chain commitment." Section 1, completeness failure: the honest operator "cannot respond in time". Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is critical." That is Critical in the honest-operator role, so Medium for the support player.

There is a second reading. It applies the section 8 exclusion "need the cached hash-tree data ... to survive its adoption without a rebuild (O1)" literally, to any component, and then the issue is Out of scope. The facts that decide between the readings are textual. The exclusion would have to cover the case where the shipped tool's own adoption skips the rebuild. Section 5 says those tools "must follow" O1, and that a defect that "defeats the rebuild itself" is not excused. That supports the first reading.

### Possible solution and risks

In `store_first_epoch_checkpoint`, load the clone with `cartesi.machine(temporary_directory, { clear_hash_tree = true })` before `assert_rolling_template` and `get_root_hash`. Optionally, compare the result with the on-chain template hash there. The rebuild costs one full hash of the template at adoption, which `new_stored_player` already pays. It does not rewrite the stale cache in the checkpoint directory. Later loads of that directory rebuild (`new_stored_player`) or come from the operator's own process, so this is harmless. Alternatively, rebuild in the clone with sharing so that the stored cache is refreshed too.

Checkpoints written before the fix keep the wrong hash, because the function returns early when the directory exists. Operators must delete `checkpoints/epoch-0` once.

### Risk of not fixing it

An operator who runs the reference player on a template it did not produce, and whose cached data is stale or was altered by the distributor, never defends epoch 0. Until someone notices and rebuilds the template by hand, a dishonest claim can win by default. Because the player is support, no production deployment is exposed directly. The risk is that the reference implementation teaches the pattern O1 forbids: trusting the cached root of a received template. Outside the code, operators can mitigate it by re-storing a received template with `--clear-hash-tree` before handing it to the player.

## R1-O2-1

**Title.** After a power loss, the PRT stored player restarts from its unsynced backup clone (`machine.revert`),
discards the synced epoch machine, and trusts the clone's cached hash tree, recording wrong root hashes.

**Severity.** Medium

### Problem

`stored_machine_pair_methods:commit` in `doc/recipes/prt.lua` refreshes the backup of the epoch machine after
`state.json` already records the new input boundary: it removes `machine.revert`, clones the (synced) epoch machine
into `machine.revert` under that final name, and only then syncs it. If the process stops between the clone and its
sync (power loss), `machine.revert` is a directory that was being written when its process stopped, so O2 does not
guarantee it, while the epoch machine `machine`, synced by `commit_epoch_state` before `state.json` was written, is
guaranteed.

On relaunch, `revert_interrupted_input` prefers the backup: if the backup's contents, rehashed with
`clear_hash_tree`, match the root hash in `state.json`, it removes the guaranteed epoch machine and replaces it with
a clone of the unsynced backup. `reopen_epoch_directory` then loads that clone with `SHARING_ALL` and without
`clear_hash_tree` (`new_stored_machine`), so the player keeps using cached hash-tree data that was never synced. The
contents check cannot detect damage to that cached data, and the load check compares only the cached root. The
player then advances, and as pages change their stale leaf hashes enter the root: it silently records root hashes
(and would build computation hashes and proofs) that are not the content hashes of its machine. An honest operator
built like this would commit a wrong claim and lose its dispute, which is a completeness failure of section 1 in
the role the player stands in for.

### Component, role and area

The PRT player in `doc/recipes` (`prt.lua`, stored player and its epoch directory, crash recovery). AUDIT.md table:
"The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI, and the Lua helper libraries ... | Support.
No production deployment runs the player, the bridge or the CLI." It stands in for the honest operator. The
emulator's `clone_stored`, `sync_stored` and `load` behave as documented; no component in another role shows the
defect.

### Location

- `doc/recipes/prt.lua`, `stored_machine_pair_methods:commit` (clone into `<directory>.revert` under its final
  name, sync afterwards; around lines 1137-1150), called by `run_next_input` right after `commit_epoch_state`
  (around lines 2268-2270).
- `doc/recipes/prt.lua`, `revert_interrupted_input` (around lines 2864-2880): picks the backup by a content rehash
  (`get_stored_root_hash`, lines 2850-2861), removes the synced epoch machine, clones the backup without a sync.
- `doc/recipes/prt.lua`, `reopen_epoch_directory` (around lines 3066-3102) and `new_stored_machine` (lines
  1007-1012): load the epoch machine with `SHARING_ALL` and without `clear_hash_tree`.

### Evidence and test

`bugs/R1-O2-1/` contains:

- `test.lua`: runs `doc/recipes/prt.lua`'s stored player, loaded unchanged as a module, in child processes on the
  harness `baremetal-template` configuration, with two advance inputs. (1) Control: a fresh epoch directory gets
  inputs 0 and 1 without a stop and records root R. (2) Crash: a fresh epoch directory gets input 0; the power loss
  is modelled right before the player syncs the not-yet-synced clone of the epoch machine (`machine.revert`): one
  4 KiB block of that clone's RAM `.dht` (leaf hashes of RAM pages 0..127) reads back as zeros, and the process
  exits with `os.exit` without cleanup. Directories already synced are untouched. (3) Relaunch: a new process opens
  the same epoch directory and is delivered inputs 0 and 1, as a restarted listener does; it records root R'. The
  test asserts R' == R and also prints the relaunched machine's content hash rebuilt with `clear_hash_tree`.
- `player.lua`: the driver (`run` and `crash` modes; `crash` wraps `clone_stored`/`sync_stored` to model the loss).
- `README.md`: description of the mechanism and the test.

Run `bugs/run.sh R1-O2-1` (about 10 s, about 100 MB in a `mktemp -d` directory that it removes). On audit/prt2 it
exits 1, deterministically (re-run twice by the reviewer), printing:

```
POWER LOSS before syncing /tmp/r1-o2-1.XXXXXX/crashed/machine.revert
uninterrupted player, root after input 1:          0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
relaunched player, root it records after input 1:  0x2ff8357c3ac58955664922c4616289535d729a6d82f113c9de5d5f8d6a578a12
relaunched player's machine, contents rehashed:    0x45dfda061ef00a368c1950bbfdca9bd0b2c6a9c0270b63d0e16e3db3dec0cba1
VIOLATED: R4/O2: after a power loss the stored player must resume from a guaranteed directory and record the same root hash as an uninterrupted player (...)
run.sh: R1-O2-1: exit 1 (bug present)
```

The relaunched player passes all its own checks; its machine's contents hash to R, but it records R'. The reviewer
applied a tmp+sync+rename commit (clone into `machine.revert.tmp`, sync, remove the old backup, `rename_stored`) to a
scratch copy of `prt.lua` placed first on `LUA_PATH_5_4`; the modelled loss then hits `machine.revert.tmp`, the
relaunch falls back to the synced epoch machine, records R, and the test exits 0. Found, proved and reviewed on
Opus 5.5 (no fallback).

### Trigger and reachability

A host stop (power loss) of the player process after the clone into `machine.revert` and before its sync, at the end
of any input, followed by a relaunch on the same epoch directory. No adversary action is needed beyond inputs that
make the guest run (any input); the window opens once per input. The damaged state is the cached hash-tree data of
an unsynced clone, which O2 explicitly allows to be anything ("leaves every stored directory it was writing or
sharing in an unspecified state"); losing cached data while contents survive is a plausible outcome of unflushed
writeback across separate files. No unreachability argument is involved.

### Rating

1. Out of scope: not excluded. The closest exclusion is "Defects that need the honest operator to reload a stored
   directory that O2 does not guarantee, such as one being written or shared when its process stopped". Here the
   reload of the unguaranteed directory is not an external precondition imposed on the audited code: it is the
   audited component's own choice, and the defect is that choice. Section 5 binds it: "O1 and O2 bind the emulator
   too. The tools and reference implementations that ship with it must follow them", and "A defect that defeats the
   rebuild itself, or that damages a directory while O2 guarantees it, is not excused by them" (the player deletes
   the guaranteed epoch machine). The "Host faults" exclusion applies only "as long as the emulator does not turn
   them into a wrong hash"; the player does turn the stop into a wrong hash.
2. Role: Support (AUDIT.md table above). Section 3: "A defect that only a support component shows is Medium when it
   would rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". The player is an implementation of an operator that no deployment runs; it
   stands in for the honest operator. "How to rate" step 2: "A defect that only a support component shows is never
   above Medium."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." That
   requires the stood-in rating to be High or Critical, which step 4 gives.
4. Critical (in the stood-in honest-operator role): O2 "The operator discards those directories and resumes from a
   guaranteed one", and R4 "After a stop, it restarts from a directory that O2 guarantees and keeps defending its
   claim", violated on the honest operator's path ("Restarting after a stop (O2)", section 2); the result is a
   completeness failure ("The honest operator computes a wrong hash"). Critical for the honest operator, hence
   Medium for this support component.

Two readings: under the reading above (section 5 binds reference implementations to O2), Medium. Under a literal
reading of the out-of-scope entry ("need the honest operator to reload a stored directory that O2 does not
guarantee"), it would be Out of scope. The second reading would make O2 unenforceable on the very tools section 5
says must follow it, so the first is better supported. The deciding fact is whether the out-of-scope entry covers a
component under audit that itself performs the forbidden reload; the text of section 5 says it does not excuse it.

### Possible solution and risks

Make the backup refresh atomic, as other parts of `prt.lua` already do for checkpoints: clone into
`machine.revert.tmp`, `sync_stored` it, then remove the old `machine.revert` and `rename_stored` the temporary into
place (and sync the epoch directory). Add `machine.revert.tmp` (and the same for `pair`/`agreed` if they use the same
pair) to the names that `clear_epoch_directory` and `remove_epoch_leftovers` remove, so a leftover temporary does not
make reopening fail. Independently, `revert_interrupted_input` should prefer the epoch machine synced before
`state.json` was written when it matches, and the reopened epoch machine could be loaded with `clear_hash_tree` (at
the cost of a full rehash per reopen). Risks: a crash between removing the old backup and the rename leaves no
backup, so the reopen logic must handle the backup's absence (it already falls back to the epoch machine and
re-creates the backup); extra syncs cost I/O per input.

### Risk of not fixing it

The player and its stored mode are a reference implementation, not run by deployments; operators who copy its
crash-recovery design would, after a power loss at the end of an input, silently defend a wrong claim and lose
disputes. Anyone running the recipes for testing can get wrong root hashes after an unclean shutdown. Mitigation
outside the code: after any unclean stop, delete `machine.revert` before relaunching, or rebuild the epoch
directory from the template.

## R1-O2-2

**Title.** After a stop just past the seal commit, reopening the sealed epoch swaps the synced epoch machine for an
unsynced clone and deletes `machine.revert`, so no O2-guaranteed copy is left and a later power loss blocks every
reopen.

**Severity.** Medium

### Problem

`seal_epoch_state` destroys and syncs the epoch machine, commits the sealed `state.json`, and only then removes
`machine.revert`. Suppose the player stops between those last two steps (crash, `kill -9` or power loss). On the
relaunch, `reopen_epoch_directory` calls `revert_interrupted_input`. `machine.revert` rehashes to the sealed root hash,
so branch 1 runs: it removes the synced `machine/`, then runs `clone_stored(machine.revert, machine)` and never calls
`sync_stored`. Next, the sealed-epoch path of `reopen_epoch_directory` removes `machine.revert` ("A sealed epoch no
longer needs the backup").

After that, the epoch directory holds no machine directory that O2 guarantees. `machine/` was changed and never synced,
and the synced backup is gone. On the next relaunch there is no backup, so `revert_interrupted_input` asserts that
`machine/` rehashes to `state.json`'s root hash. If a power loss has dropped the unsynced clone data, that assertion
fails with "the epoch machine does not match its state". Every later relaunch fails the same way. The player has no
fallback, such as clearing the epoch directory and replaying from the epoch checkpoint (`crisium.lua` `new_player`
calls `new_stored_player` directly). The honest player therefore stops defending the sealed epoch's claim, which in
the honest-operator role is a completeness failure (section 1).

### Component, role and area

The PRT stored player in `doc/recipes/prt.lua`, specifically its epoch directory and its restart path. AUDIT.md
assigns it this role: "The PRT player and bridge in `doc/recipes` ... Support. No production deployment runs the
player". It stands in for the honest operator's storing, reloading and restart after a stop.

### Location

- `doc/recipes/prt.lua`, `seal_epoch_state` (about lines 2720-2739): it commits `state.json` before removing
  `machine.revert`.
- `doc/recipes/prt.lua`, `revert_interrupted_input` (about lines 2864-2880): branch 1 runs `clone_stored` with no
  `sync_stored`, while branch 2 does sync its clone.
- `doc/recipes/prt.lua`, `reopen_epoch_directory` (about lines 3124-3127): it removes `machine.revert` for a sealed
  epoch without checking that `machine/` is synced.

### Evidence and test

`bugs/R1-O2-2/` contains three files:

- `test.lua`, the test.
- `player.lua`, the child process. It runs one player step per process: `seal-crash`, `reopen`, and the control's
  `reopen-synced-clone`.
- `README.md`.

Run it with `bugs/run.sh R1-O2-2`. It takes about 15-25 s and needs `strace` and the harness `baremetal-template`
configuration.

The test opens an epoch from `baremetal-template`, runs one input and seals. Through an `fs.exists` hook, the seal
process exits with `os.exit(17, false)` (no cleanup, the disk left as `kill -9` leaves it) right after the sealed
`state.json` commit and before `machine.revert` is removed. The test checks that `state.json` is sealed and that
`machine/` and `machine.revert/` both rehash to its root hash. It then relaunches under `strace -f -y` and makes two
checks:

- **(A)** Some machine directory must remain that matches `state.json` and was synced after its last change to file
  data and directory entries.
- **(B)** The test models a power loss: every file the relaunch changed and did not sync becomes a hole of the same
  size, which O2 allows because it leaves such files unspecified. The next relaunch must then reopen the sealed epoch.

A control in the same run applies the same steps to a relaunch whose `clone_stored` calls are each followed by
`sync_stored`. The control must pass both checks, or the test exits 2.

The reviewer re-ran the test twice on audit/prt2. It exited 1 both times. It prints:

```
control: after the relaunch, machine: matches state.json=true, files changed and not synced=0, entries synced=true
control: relaunch after the power loss: status 0
player: after the relaunch, machine: matches state.json=true, files changed and not synced=26, entries synced=false
player: after the relaunch, machine.revert does not exist
player: power loss discarded the data of 26 unsynced file(s)
player: reopen failed: .../doc/recipes/prt.lua:2874: the epoch machine does not match its state
control (reopen with synced clones): A and B hold
VIOLATED: O2/R4: after relaunching a sealed epoch, its directory keeps a machine directory at state.json's root hash that was synced after its last change
VIOLATED: O2/R4: after a power loss that follows that relaunch, the next relaunch reopens the sealed epoch
run.sh: R1-O2-2: exit 1 (bug present)
```

The power loss is modeled, not injected at the block layer, and the model is conservative: it keeps every directory
entry and drops only the data of unsynced files. Check (A) does not depend on the model. It applies O2's definition of a
guaranteed directory to the traced syscalls. The test ran on the temp directory's ext4, where `clone_file` copies. A
reflink clone also needs `sync_stored` to be durable (prt.lua's own comment on `get_stored_root_hash`). No reviewer
changes were made to the test. Opus 5.5 found, proved and reviewed the issue; no fallback model was used.

### Trigger and reachability

No adversary is needed. The trigger is two stops of the honest player's host:

1. A crash, kill or power loss inside the window of `seal_epoch_state` between the `state.json` write and the removal
   of `machine.revert`. That window covers `fs.sync_directory`, `remove_evicted` and the removal of the files the
   previous `state.json` named.
2. A power loss after the relaunch, before the kernel writes back the clone.

Both stops happen on the honest operator's path ("Restarting after a stop (O2)"). They work with any template and any
inputs, and the sealed epoch is reached on every epoch.

### Rating

1. **Out of scope: no.** I checked the exclusion "Defects that need the honest operator to reload a stored directory
   that O2 does not guarantee, such as one being written or shared when its process stopped". It does not apply. The
   first relaunch reloads `machine.revert`, which was synced. The defect is that the relaunch itself discards the only
   guaranteed copy. I also checked "Host faults, such as a full disk, as long as the emulator does not turn them into
   a wrong hash, ...". The second stop is a power loss, but O2 names power loss as an ordinary stop the operator
   resumes from: "A process that stops (crash, kill, or power loss) ... The operator discards those directories and
   resumes from a guaranteed one". Section 5 adds "The tools and reference implementations that ship with it must
   follow them". The trigger is the player's restart logic, not the fault.
2. **Role: Support.** The AUDIT.md table rows the PRT player as "Support. No production deployment runs the player".
   Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role
   the component stands in for, such as ... the honest operator for an implementation of an operator". That clause
   covers this component, an implementation of an operator.
3. **High and Medium cases.** "A defect that only a support component shows, when section 3 rates it Medium." This
   case applies through step 4's rating in the stood-in role. No High case fits.
4. **Critical in the stood-in role.** In the honest-operator role, the defect violates two clauses on the honest
   operator's path. R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim".
   O2: "The emulator guarantees a stored directory only when it was synced after the last change to its contents".
   Both would rate Critical, so the support rule gives **Medium**.

Alternative reading: if the host-fault exclusion were read to cover any power loss that ends in a loud failure, with
no wrong hash, the issue would be Out of scope. I judge that reading weaker. O2 and R4 make recovery from a power loss
an explicit requirement, and the fault here only exposes a guarantee the restart had already destroyed.

### Possible solution and risks

In `revert_interrupted_input` branch 1, call `cartesi.machine:sync_stored(machine_directory)` after `clone_stored`, as
branch 2 already does for its clone. The control in the test models exactly this fix. Another fix is to remove
`machine.revert` for a sealed epoch only after `machine/` is synced. The cost is one extra sync of a machine directory
per relaunch, a bounded per-restart cost. The fix touches only the restart path and does not change hashes.

### Risk of not fixing it

An operator that copies the reference player can lose the ability to restart a sealed epoch. That takes a stop inside
the seal window, then a power loss soon after the relaunch. It then stops defending that epoch's claim, and a
dishonest claim can win by timeout. No adversary can trigger it directly. As mitigations outside the code, an operator
can sync the filesystem after every relaunch, or recover by clearing the epoch directory and replaying the epoch from
its checkpoint.

## R1-R2-1

**Title.** `write_reg("iunrep", ...)` changes the hashed unreproducible-mode register while every guard reads the config copy, and `store` then writes a directory that refuses to load

**Severity.** Medium

### Problem

The unreproducible mode is kept in two places: the hashed shadow register `iunrep` and the copy in the machine's
configuration (`m_c.processor.registers.iunrep`). Every behavior that depends on the mode reads the config copy.
That includes the uarch refusal, the refusals of `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`,
the `store` refusal, and host interrupt polling. The two copies are compared only when a machine is created or
loaded. `machine::write_reg` refuses writes to the machine-ID registers (`mvendorid`, `marchid`, `mimpid`), which
the same load-time check binds to the configuration. It has no such guard for `iunrep`.

After `write_reg("iunrep", 1)` on a reproducible machine, the root hash commits to an unreproducible machine. The
machine still runs, logs uarch steps, collects computation hashes and stores. `store` writes the shadow state with
`iunrep = 1` next to a `config.json` with `"iunrep":0`. Loading that directory fails with "iunrep mismatch between
shadow state and config". The reverse write (0 on an unreproducible machine) produces a hash that says reproducible
while the machine refuses the uarch and the collectors.

This violates R2: "Every register and every configuration value that affects a transition has one source of truth in
the hashed state, and every path reads it from there." It also contradicts the manual, which calls `iunrep` "a
creation-time mode", and R14: "The unreproducible mode is fixed at creation and recorded in the hashed state." No
valid template and no honest-operator operation reaches the split state, so the goal of section 1 is not affected.
The defect is a machine API operation, used as documented, that leaves the machine's cached state and its stored
directory inconsistent with its contents.

### Component, role and area

- `machine::write_reg` belongs to "the rest of the machine API (C, Lua and JSON-RPC)". A production validator node
  does not plausibly write `iunrep` on the honest operator's path, so this use is off that path.
- The guarded paths (uarch, collectors, `store` and load) belong to "interpreter, state-access layers, ..., and
  storing, loading, cloning and syncing machines", which is the honest-operator role. They behave correctly on every
  machine where the two copies agree, and the copies always agree unless `write_reg("iunrep")` was called.
- Area: the source of truth for the unreproducible mode, and its consistency between the machine and a stored
  directory.

### Location

- `src/machine.cpp`, `machine::write_reg`, `case reg::iunrep:` (around line 1444). It writes
  `m_s->shadow.registers.iunrep` with no read-only check. Compare `case reg::mvendorid` / `marchid` / `mimpid`
  (around lines 1354-1359), which throw "register is read-only".
- `src/machine.hpp`, `machine::is_unreproducible()` (around line 857). It returns
  `m_c.processor.registers.iunrep != 0`, which is the config copy.
- `src/machine.cpp`, callers of `is_unreproducible()`: `store` (around line 430), uarch (around line 2194),
  `poll_external_interrupts` (around line 2348), and the collectors (around lines 2445, 2619, 2770).
- `src/machine.cpp`, `validate_processor_shadow` (around lines 222-224). It is the only comparison of the two copies,
  and it runs at create and load only.

### Evidence and test

`bugs/R1-R2-1/` contains `test.lua` and `README.md`. The test uses the shared harness configuration
`baremetal-minimal`, a reproducible bare-metal machine. It first checks, as a control, that `log_step_uarch` works on
a fresh copy of the machine. It then calls `write_reg("iunrep", 1)`. It exits 0 in either of two cases:

- the write is refused;
- every path follows the hashed register: `log_step_uarch` refuses, and `store` either refuses or writes a directory
  that loads back with the same root hash and `iunrep`.

Run with `bugs/run.sh R1-R2-1`. It takes about a second. On audit/prt2 it prints the following and exits 1. The
prover ran it three times and the reviewer twice more, with the same result every time.

```
write_reg('iunrep', 1) accepted; read_reg('iunrep') = 1; root hash changed: true
VIOLATION: log_step_uarch succeeded on a machine whose hashed iunrep is 1 (the guard reads the config copy, not the hashed register)
store succeeded
VIOLATION: store wrote a directory that refuses to load: .../bugs/R1-R2-1/test.lua:75: iunrep mismatch between shadow state and config
VIOLATED: R2/R14: iunrep must have one source of truth in the hashed state (write refused, or every path follows it)
run.sh: R1-R2-1: exit 1 (bug present)
```

The reviewer also checked two facts by hand. After the write, `run` and `collect_mcycle_root_hashes` still succeed.
The stored `config.json` holds `"iunrep":0` while the stored shadow holds 1. Either fix in "Possible solution" makes
the test exit 0. The test was not modified. No fallback model was used.

### Trigger and reachability

Only a trusted caller of the machine API triggers it, by calling `write_reg("iunrep", v)` with `v` different from
the configured value, locally or over JSON-RPC. No guest action triggers it. R8 makes `iunrep` unreachable from guest
memory accesses, and no instruction writes it: the interpreter never calls `write_iunrep`. No input triggers it
either, because delivery does not touch `iunrep`.

A valid template is "created from a configuration ... and changed only by running it and delivering inputs", so its
two copies always agree. Every machine the honest operator stores, loads, clones or syncs therefore keeps them in
agreement. The split state is reachable only through this API call, and the honest-operator path never makes it.

### Rating

1. Out of scope. The exclusions checked are these.
   - "The effect of a deliberate state change made through the machine API, when the API performs it as documented
     (section 4)." This clause covers the component (`write_reg` is a machine API operation), but it does not cover
     the defect. The documented effect is that the register changes ("The value of any register can be changed with
     the `machine:write_reg` ... method"). That effect, the hash now committing to `iunrep = 1`, is out of scope. The
     emulator's own copy of the mode then disagreeing with the register, and `store` writing a directory its own
     `load` refuses, are not documented effects of the write. The Medium case quoted in step 3 is written for exactly
     such a documented API use, and it would be empty if this exclusion swallowed it.
   - "Defects that need an untrusted party to call the machine API directly" does not apply: the caller is trusted.
   - The exclusion for snapshots the emulator did not write does not apply: the emulator wrote this directory.
   - The O2 exclusion does not apply: there is no stop and no sharing.
2. Role. `write_reg` is "the rest of the machine API", which is honest operator only "where a production validator
   node plausibly calls it on the honest operator's path". No node writes `iunrep`, so this use is off the path. The
   paths that show the inconsistency (`store`/load, uarch, collectors) are honest operator. Section 3 says they play
   this role "within the limits of O1 and O2", and they misbehave only on a machine that the off-path call produced.
3. High and Medium cases. Section 8 Medium: "A machine API operation off the honest operator's path that, used as
   documented, leaves the hash tree, the cached state of the machine or a stored directory inconsistent with the
   machine's contents (R9)." This clause covers the component. `write_reg` is off the path and used as documented
   ("The value of any register can be changed"). It leaves the cached config copy that every guard reads
   inconsistent with the hashed register, and `store` then writes a directory whose `config.json` disagrees with its
   shadow state and does not load. The manual contradiction points the same way: "A contradiction between the manual
   and the behavior on a security-relevant point ... takes the severity it would have if the manual were right." The
   manual calls `iunrep` "a creation-time mode", and R14 says "fixed at creation". No High case applies, since the
   state is not reached by any input sequence from a valid template and no verifier or honest path diverges on a
   reachable state.
4. Critical. Not reached, because step 3 matched. R2 ("one source of truth in the hashed state, and every path reads
   it from there") is violated structurally. But it is observable only after the off-path API write, never at a
   reachable state or on the honest operator's path.

Other readings:

- **Low.** "A failure that needs misuse of an API by its trusted caller". Writing a register the manual calls
  "creation-time" could be called misuse. The deciding fact is whether the manual's general statement that any
  register can be written counts as documenting writes to `iunrep`. The code refuses the analogous machine-ID
  registers, and the manual does not list `iunrep` as read-only. On that text the write is documented use, so Medium
  is the better-supported reading.
- **Out of scope.** If the first exclusion is read to cover every consequence of a documented write, including the
  emulator's own inconsistency, the defect is out of scope. That reading would empty the Medium case above, so it is
  not preferred.

### Possible solution and risks

The preferred fix makes `iunrep` read-only to the host. `write_reg(reg::iunrep, ...)` would throw "register is
read-only", as for `mvendorid`/`marchid`/`mimpid`. `init_processor` would write the configured value straight into
the shadow, as it already does for the machine-ID registers. The manual's `write_reg` paragraph would list the
read-only registers. Risk: any tool or test that writes `iunrep` after creation breaks. That use is unsupported in any
case, because such a machine cannot be stored and reloaded.

An alternative or addition is to have `is_unreproducible()` read the shadow register, so that there is a single
source of truth. Risk: the VirtIO devices and the TTY setup are fixed at creation from the config, so a machine whose
register flips to 0 would keep host devices while it claims to be reproducible. Read-only is the safer fix.

### Risk of not fixing it

A trusted caller (a development tool, a debugger, a test script, or a careless integration) that writes `iunrep` gets
a machine whose hash claims one mode while it behaves as the other. It can keep computing hashes and storing, and the
stored directory then cannot be loaded. Untrusted parties and guests cannot trigger it, and the honest operator's path
never writes `iunrep`, so the security goal is not exposed. Mitigation outside the code: never call `write_reg` on
`iunrep`.

## R1-R6-1

**Title.** `cartesi-machine --print-uarch-cycle-root-hashes` prints made-up uarch hashes for the mcycle after a
rejection: it passes a fake revert uarch tail made of the revert root hash twice.

**Severity.** Medium (Low under the reading that treats the printer as diagnostics; see Rating).

### Problem

When the window of `--print-uarch-cycle-root-hashes` contains a rejecting instruction, the CLI prints, for the mcycle
that follows it, two hashes labelled `<rej>,1` and `<rej+1>`, both equal to the revert root hash. R6 requires the
uarch-level hashes of every mcycle after the rejecting instruction to be "the uarch trajectory that starts from the
canonical state", that is, the per-uarch-cycle state hashes of the machine to which the rejected input was delivered
(44 hashes in the test, the first `a6f7bf8f...`). The first printed hash claims to be the state after uarch cycle 1
and is not; the uarch trajectory is collapsed to a single cycle.

The cause is that the runner hands `collect_uarch_cycle_root_hashes` a fabricated `revert_uarch_tail`
`{ revert_root_hash, revert_root_hash }`. The library documents that this tail is "the state root hashes after each
uarch cycle of the machine corresponding to the revert root hash", which the caller must obtain by running the same
function on that machine, and at a rejected manual yield it emits that tail as the extra period. The library itself is
correct: given the real tail, the same chunked calls return the required trajectory. The code comment justifying the
fake tail ("which never happens outside cmio mode") is false: the CLI's default yield settings allow manual yields, so
any guest that rejects stops the run there, with or without cmio options.

Threat to the goal: none directly, because the CLI is not run by a deployment. The tool's output is exactly the set of
uarch-level hashes (or, with bundling, the subtree roots) that a uarch-level computation hash is built from. A user who
computes or checks uarch-level claims with it after a rejection gets a wrong trajectory, which in the honest-operator
role would be a completeness failure (wrong uarch-level claim).

### Component, role and area

`cartesi-machine` CLI, role Support (AUDIT.md: "The PRT player and bridge in `doc/recipes`, the `cartesi-machine` CLI,
and the Lua helper libraries ... | Support. No production deployment runs the player, the bridge or the CLI."). Area:
the `--print-uarch-cycle-root-hashes` runner. The library function `collect_uarch_cycle_root_hashes` (role Honest
operator) does not show the defect.

### Location

`src/cartesi-machine.lua`, `uarch_cycle_root_hashes_runner_run` (lines 4053-4061 on audit/prt2):

```lua
-- The revert uarch tail only matters when the run stops at a rejected manual yield, which
-- never happens outside cmio mode. ...
local revert_root_hash = m:read_revert_root_hash()
local fake_revert_uarch_tail = { revert_root_hash, revert_root_hash }
...
self.runner:collect_uarch_cycle_root_hashes(chunk_end, self.log2_bundle, fake_revert_uarch_tail)
```

Contract of the tail: `src/cm.h`, documentation of `cm_collect_uarch_cycle_root_hashes` (`revert_uarch_tail`, and the
paragraph on the rejected manual yield).

### Evidence and test

`bugs/R1-R6-1/` contains `test.lua` and `README.md`. Run with `bugs/run.sh R1-R6-1` (about 1 s). The test:

1. loads the shared `baremetal-template` configuration (the `emit-output` guest waiting at an accepted manual yield)
   and computes the uarch trajectory of one mcycle from it with `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)`
   (44 hashes; the last equals the template's root hash);
2. delivers the advance-state payload `R` (the guest rejects it), runs 30 mcycles, stores the machine in a
   `mktemp -d` directory, and finds the rejecting mcycle on the in-memory machine;
3. runs `cartesi-machine --load=<stored> --print-uarch-cycle-root-hashes=8,start:3526402`, checks that the hash
   printed for the reset of the rejecting mcycle is the revert root hash, and collects the hashes printed after it;
4. exits 1 if any printed hash differs from the trajectory of step 1, 0 otherwise, 2 on setup errors.

On audit/prt2 it exits 1 on every run (three runs by the prover, three by the reviewer), printing:

```
rejecting mcycle 3526406; revert root hash 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
required: 44 uarch-level hashes for mcycle 3526406 (trajectory from the canonical state), first a6f7bf8f8873acb46fd11c6fdbfdde23c49fde9a9bc3cc03257645c26fb53425
printed:  2 hashes after the rejection:
  3526406,1: 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
  3526407: 428a6bb85a7c345472540be79f09a3406f4a8539ac1bac32d90cea6aec92ac75
first difference at entry 1 (3526406,1): printed 428a6bb8..., required a6f7bf8f...
VIOLATED: R6: in every later mcycle, the uarch-level hashes printed by --print-uarch-cycle-root-hashes are the uarch trajectory that starts from the canonical state
run.sh: R1-R6-1: exit 1 (bug present)
```

The reviewer ran the test against a scratch copy of the CLI whose only change is to pass the real tail (computed with
`collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` on the template); it printed the 44-hash trajectory
(`3526406,1: a6f7bf8f...`, `3526406,2: a05f14b2...`, ...) and the test exited 0. The reviewer also relaxed the test so
that printing fewer hashes after the rejection, or none, is accepted (only a printed hash that differs from the
required one fails), so that a fix that declines to print the period instead of computing it passes rather than ending
in a setup error. Found by the R6 hunter, proved and reviewed in campaign round 1.

### Trigger and reachability

A trusted CLI user runs `--print-uarch-cycle-root-hashes` over a window that contains a rejecting instruction. Any
guest that rejects an input reaches it; the test reaches it from the shared valid bare-metal template by delivering an
advance-state input, running, and storing the machine, all documented operations. No untrusted party is involved
beyond the input sender choosing a payload that the guest rejects.

### Rating

1. Out of scope: no. The trigger is a guest rejection of an input, reachable from a valid template, followed by a
   documented CLI option. It needs no "deliberate state change made through the machine API", no untrusted caller of
   the machine API, no violation of A1 to A8, and no non-guaranteed directory (the loaded directory was stored and
   not shared). The application is correctly designed (it yields with the rejected reason as the rollup interface
   allows).
2. Role: the `cartesi-machine` CLI, Support per the AUDIT.md table quoted above; that clause names the CLI, so it
   covers this component. Section 3: "A defect that only a support component shows is Medium when it would rate High
   or Critical in the role the component stands in for, such as ... the honest operator for an implementation of an
   operator or a tool that computes claims." The printer computes the per-uarch-cycle state hashes and, with
   `log2_bundle_uarch_cycle_count`, their subtree roots, which are the leaves and parts of uarch-level computation
   hashes ("A computation hash can be built whole or in parts", section 3). It therefore stands in for the honest
   operator. The honest-operator library it calls (`collect_uarch_cycle_root_hashes`) does not share the defect: the
   wrong hashes come only from the tail the CLI fabricates, and the real tail yields the correct output.
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." In the
   honest-operator role the defect would be Critical (step 4), so section 3 rates it Medium.
4. Critical (for the role it stands in for): R4, "After a rejection, every hash the honest operator commits to follows
   R6, however it is computed", and R6, "In every later mcycle, the uarch trajectory that starts from the canonical
   state." The printed `<rej>,1` hash is not a state of that trajectory, at a reachable state.

Second reading: the example "a defect in a tool's diagnostics" under Low could be read to cover the CLI's printing
options, which the manual presents as a way to "see" state hashes. Under that reading the class is Low. The deciding
fact is whether `--print-uarch-cycle-root-hashes` counts as a tool that computes claims; its output is the claim
material itself (state hashes and bundle roots), not a diagnostic message about it, which is why Medium is the reading
taken here.

### Possible solution and risks

Pass the real tail: let the user supply the machine to which the rejected input was delivered (for example a
`--revert-machine=<dir>` option, or the snapshot the CLI itself takes before each cmio delivery) and compute the tail
with `collect_uarch_cycle_root_hashes(MCYCLE_MAX, 0)` on it, checking that its last entry equals the recorded revert
root hash. When no such machine is available, stop printing at the reset of the rejecting mcycle and say that the
following period needs the reverted machine, instead of printing fabricated hashes. Risk: low; it changes only the
CLI's output after a rejection, and scripts that parse that output would see the extra (correct) period or a message
in its place.

### Risk of not fixing it

No deployment runs the CLI, so the goal is not affected. Developers, auditors or operators who use the printer to
compute, compare or debug uarch-level claims after a rejected input get a wrong trajectory, labelled as real state
hashes, and could build or trust a wrong uarch-level commitment, or misdiagnose a correct implementation. Mitigation
outside the code: do not use the printer across a rejection; compute the period after it with
`collect_uarch_cycle_root_hashes` on the pre-delivery machine.
