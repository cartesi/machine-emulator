## R10-PERGUEST-2

**Title.** `collect_mcycle_root_hashes` updates the hash tree over the always-dirty shadow pages twice at every automatic yield, even when no sample is due. A guest that loops on automatic yields multiplies the worst-case per-mcycle cost of the mcycle-level claim by about 5x.

**Severity.** High under the preferred reading: a guest multiplies the worst-case cost of "a part of a claim" (R12) by a constant factor, and the deployment's sizing is unknown. Out of scope under the alternative reading, which takes the section 8 exclusion for "the number of its outputs or yields" literally, because each yield still has a bounded cost.

### Problem

`machine::collect_mcycle_root_hashes` returns on every break reason other than `reached_target_mcycle`. That includes
`yielded_automatically`. The manual documents this: the result's `break_reason` has "the same values `machine:run()`
returns". The honest builder then calls it again for the rest of the period (`doc/recipes/prt.lua`, `run_to_stop` ->
`mcycle_computation_hash_run`). Each such call does two hash-tree updates that the computation hash does not need at
a yield that is not a sampling point.

1. On entry it calls `update_hash_tree()`. That function marks the shadow uarch state, the shadow registers and the 6
   shadow TLB pages dirty (`machine_address_ranges::mark_always_dirty_pages`) and runs `m_ht.update`.
2. When `interpret` returns at the yield, the loop runs `m_ht.update(m_ars)` unconditionally. It does this before it
   computes the phase and tests whether the reached mcycle is a sampling point or a fixed point. On every interpreter
   exit, `collect_mcycle_hashes_state_access::do_write_mcycle` has marked all 8 pages of `AR_SHADOW_STATE_LENGTH`
   (registers and TLB) dirty.

Only a sampling point or a fixed point needs a root hash. At a non-sampling automatic yield, nothing reads the
updated tree before the next call updates it again. Dirty marks accumulate correctly, so both updates could be
deferred to the next point where a hash is collected.

The result is that a non-sampling automatic yield costs about as much as a real sample. The test measures 16
hash-tree pages and 59 node hashes per yield. A sample at log2 period 0 costs 8 pages and about 60 hashes. A guest
that yields automatically every 2 mcycles makes the mcycle-level claim pay this at any sampling period. That claim is
"a part of a claim" in R12. The reviewer compared it with the most expensive pattern found without the defect: a
guest that stores to a different page in every store, measured at log2 period 30 on warm host memory. That guest
costs 0.5 to 0.67 hash-tree pages and 1.2 to 8.7 node hashes per mcycle, about 1.2 to 3 us per mcycle. The yield loop
costs 8 pages and 29.5 node hashes per mcycle, about 14 to 16 us. The ratio is about 5x in time. The first touch of
fresh host pages raises the store guest to about 9 to 14 us per mcycle, but only once for each RAM page, so it does
not change the per-mcycle slope over a long span. The hunter's figure of about 6000x compares with a spin loop, which
is the average case, not the worst case. The worst-case factor is the one that matters here.

The defect erodes the A7 margin: the clocks are sized for "the worst-case costs of R12". It produces no wrong hash.

This is distinct from R1-R8-3, which is the re-scan of every valid write-TLB slot on entry. R1-R8-3 used these
always-dirty pages as its baseline "without this defect". This test keeps the write TLB empty (the guest writes no
RAM), so R1-R8-3 contributes nothing to it. Fixing R1-R8-3 alone leaves this cost.

### Component, role and area

`collect_mcycle_root_hashes`, its state access, and the hash-tree update (`src/machine.cpp`,
`src/collect-mcycle-hashes-state-access.hpp`, `src/machine-address-ranges.cpp`). Role: honest operator. The AUDIT.md
table row "Interpreter, state-access layers, devices, uarch program, hash tree, log producers,
`collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, ... | Honest operator" covers it directly.

### Location

- `src/machine.cpp`, `machine::collect_mcycle_root_hashes` (from line 2424):
  - `update_hash_tree()` on entry (line 2451);
  - an unconditional `m_ht.update(m_ars)` after every `interpret` return (around line 2520), before the
    sampling-point test (`result.mcycle_phase == 0 || at_fixed_point`, around line 2532);
  - a break on any reason other than `reached_target_mcycle` (around line 2558).
- `src/machine.cpp`, `machine::update_hash_tree` (line 1645).
- `src/machine-address-ranges.cpp`, `machine_address_ranges::mark_always_dirty_pages` (lines 129-134).
- `src/collect-mcycle-hashes-state-access.hpp`, `do_write_mcycle` (lines 147-158), which marks every page of
  `AR_SHADOW_STATE_LENGTH` dirty.
- Caller on the honest operator's path: `doc/recipes/prt.lua`, `run_to_stop` (line 1396) and
  `mcycle_computation_hash_run` (line 1576).

### Evidence and test

`bugs/R10-PERGUEST-2/` contains `test.lua`, `README.md` and this entry. The test has two hand-assembled bare-metal
guests inlined as instruction words. Run it with `bugs/run.sh R10-PERGUEST-2`. It runs in well under a second.

The test builds a machine with 4 MiB of RAM. Its guest loops on `sd t1,0(t4); j .`, with `t1` set to an automatic
yield (progress), and writes no RAM, so the write TLB holds no valid slot. After one warm-up call, the test makes 256
calls to `collect_mcycle_root_hashes(MCYCLE_MAX, 30, phase, 0)`. Each call runs 2 mcycles to the next yield, and no
sampling point falls in the span. The control is a guest that spins (`addi; j`) over the same 512 mcycles in one call
with the same period. The test reads `get_hash_tree_stats` and asserts, deterministically and without timing, that
the pages looked up (`page_hits + page_misses`) by the subject are at most the control plus 2 per yield. The 2 pages
are the shadow-registers page that the yield writes, plus one of margin. The CPU times are printed for information
only.

The reviewer re-ran it twice. Both runs exited 1, with identical page and hash counts:

```
subject (automatic yield every 2 mcycles): 512 mcycles, 256 collect calls, 0 samples: 4096 pages, 15104 hashes (16.0 pages, 59.0 hashes per yield)
control (no yields, same span, 1 call):     512 mcycles, 0 samples: 16 pages, 62 hashes
info: one real sample (log2 period 0):      8.0 pages, 60.5 hashes per sample
info: CPU per collect call at a yield 28.0 us, per run() to the same yield 0.11 us
extra hash-tree pages per automatic yield: 15.9 (allowed 2)
VIOLATED: R12 / section 8 High: an automatic yield that is not a sampling point must not make collect_mcycle_root_hashes update the hash tree over the always-dirty shadow pages (per-yield hash-tree work above the no-yield control must stay within the pages the yield writes)
run.sh: R10-PERGUEST-2: exit 1 (bug present)
```

The test passes after a correct fix. For example, the entry could only mark pages dirty, and the loop could update the
tree only when it collects a hash. Then the subject looks up no pages per yield. The reviewer made no changes to the
test.

The worst-case comparison above comes from the reviewer's own scratch measurements and is not part of the test. A
store guest (`sd t0,0(t2); add t2,t2,t3`, or two stores and one add) was run at log2 period 30 over 9000 to 40000
mcycles, with a second pass on host pages that the first pass had already touched.

### Trigger and reachability

The guest triggers it. Any input that takes control of the guest can make it loop on an automatic yield (section 4:
"Any input may take control of the firmware, the kernel, the rollup libraries, and the application. It may then run
any instruction stream at any privilege level"). Automatic yields are plain HTIF stores, and the manual's default
configuration enables them. The yield reason can be progress, or tx-output with length 0. "Any assignment of
guest-writable memory and registers is presumed reachable." No condition on the template is needed. The honest
builder must re-enter after every yield to finish the claim, so it pays the cost once per yield, at every mcycle-level
sampling period greater than one mcycle.

### Rating

1. **Out of scope.** Two exclusions were checked.
   - "Average-case performance that does not change the worst-case cost of any operation listed in R12." This does
     not apply. The automatic-yield loop is the most expensive per-mcycle pattern of the mcycle-level claim. The
     cheapest alternatives the reviewer found without the defect, guests that dirty a new page every 1.5 to 2 mcycles,
     cost about 5x less per mcycle on warm memory. So the defect raises the worst case itself.
   - "An application that tries to exhaust the honest operator through the number of its outputs or yields. Each
     costs the guest mcycles, which the application's own bound limits (section 2). This holds as long as ... each
     yield costs it a bounded amount (R12)." Each yield's cost here is bounded, about 16 pages. But "How to rate"
     step 1 says: "The entries about applications exclude what an application loses, never an emulator defect that
     its guest triggers". The defect is the avoidable size of each yield's cost inside the emulator, not the number of
     yields. Under the preferred reading the exclusion does not cover it. This clause speaks of applications, and the
     trigger here is a guest taken over by an input, so the clause covers the trigger only under the literal reading.
2. **Role.** Honest operator. Section 3: "The transition function, its log producers, the computation-hash builders,
   the hash tree and its node proofs ... play this role in every deployment". The AUDIT.md table row quoted above
   names `collect_mcycle_root_hashes` and the hash tree. These clauses cover this component directly.
3. **High and Medium cases.** Section 8, High: "A defect that lets the guest, or host load that the deployment was
   sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
   operation without the defect, while staying within what the deployment was sized for. A cost that the specified
   semantics require is not a defect. When the sizing is unknown, rate such a constant-factor increase High". R12
   lists "a part of a claim". The specified semantics (the manual's computation hash: "collects the state hash every
   2<sup>*q*</sup> mcycles", plus a fixed point) need no hash at a non-sampling automatic yield. Returning the yield
   to the caller needs no tree update either: `machine:run()` returns at the same yield in 0.11 us. The increase is a
   constant factor of about 5x per mcycle. It is bounded by the fixed set of always-dirty pages, so the case is High.
4. **Critical.** This step does not apply. The cost stays linear in mcycles, with a bounded constant per yield, so it
   is not "unbounded, super-linear". It would be "larger than what the deployment was sized for" only if a given
   deployment's sizing were known to be exceeded, and the sizing is unknown.

**Two readings.** Under the literal reading of the yield exclusion, any cost that is bounded per yield is excluded,
and this is Out of scope. Under the reading that step 1 supports, application exclusions never excuse an emulator
defect that the guest triggers, and the High constant-factor case covers it, so this is High. The text favours the
second reading, and R1-R8-3 was rated the same way. The ambiguity is whether "each yield costs it a bounded amount
(R12)" means any bound, or the R12 worst case of the same operation without a defect.

### Possible solution and risks

Defer hash-tree work to the points that need a hash. On entry to `collect_mcycle_root_hashes`, only mark the
always-dirty pages (and, if R1-R8-3 is not fixed separately, the write-TLB pages) instead of calling
`update_hash_tree()`. Inside the loop, move `m_ht.update(m_ars)` under the test `result.mcycle_phase == 0 ||
at_fixed_point`, just before the root hash is read. Every other reader of the root hash, a node hash or a proof
already calls `update_hash_tree()` first, so the dirty marks left pending at a returned yield are applied on the next
read. Optionally, mark the 6 shadow TLB pages in `do_write_mcycle` only when a TLB slot changed, since `do_write_tlb`
already marks its own page.

Risk: a pending dirty mark that some reader skips would give a stale root hash. That would be an R9 violation on the
honest operator's path, which is Critical. Check every accessor that reads `m_ht` directly without
`update_hash_tree()` (the `skip_hash_tree_update` overloads, `get_hash_tree_stats`, store and verify paths). Add a
test that compares `get_root_hash` with `verify_hash_tree` after collect calls that end at non-sampling yields,
followed by every API operation.

### Risk of not fixing it

A guest, controlled by any input that subverts it, can make the honest operator's mcycle-level claim computation about
5x slower per mcycle than the worst case without the defect, for as many mcycles as the application's own bound allows.
A deployment whose clocks and hardware were sized on the cost without the defect loses that margin (A7). If the margin
is thin, the honest claim could miss its clock. Mitigation outside the code: size A7 against this measured worst
case, a guest that yields automatically every 2 mcycles, at about one sample's cost per yield.
