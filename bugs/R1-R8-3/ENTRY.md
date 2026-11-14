## R1-R8-3

**Title.** Every `collect_mcycle_root_hashes` call re-marks and word-compares every page mapped by the write TLB, even when nothing was written since the last call. A guest that fills the write TLB and loops on automatic yields makes each yield about 6x more expensive than it needs to be.

**Severity.** High under the preferred reading: a guest multiplies the worst-case cost of "a part of a claim" (R12) by a constant factor, with the deployment's sizing unknown. Out of scope under the alternative reading, which takes the section 8 exclusion for "the number of its outputs or yields" literally, because each yield still has a bounded cost.

### Problem

`machine::collect_mcycle_root_hashes` calls `update_hash_tree()` on entry. That function runs
`mark_write_tlb_dirty_pages()`, which marks dirty the page of every valid slot of the 256-slot write TLB
(`TLB_SET_SIZE = 256`), whether or not anything was written there since the hash tree was last updated. `m_ht.update`
then looks up each marked page and compares all 128 of its 32-byte words against the page hash-tree cache. Inside the
call this marking is not needed. The collect state access records every write in `context.dirty_pages`
(`collect-mcycle-hashes-state-access.hpp`, `m_c.dirty_pages.insert`), and the loop marks only those pages before each
`m_ht.update`. So when a call returns, the hash tree is already up to date. If the next call follows with no other
mutation in between, its entry marking repeats about 1 MiB of comparisons for nothing.

A call returns at every automatic yield: the loop breaks on any break reason other than `reached_target_mcycle`.
The honest operator's builder then calls it again (`doc/recipes/prt.lua`, `run_to_stop` -> `mcycle_computation_hash_run`).
A guest can yield automatically every one or two mcycles. With a full write TLB, it pays the 256-page re-scan once
per yield.

So the per-call constant term of the cost of "a part of a claim" grows from about 17 pages (the always-dirty pages)
to about 272 pages. Measured in time, it grows from about 30 us to about 190 us per yield. For a yield-every-2-mcycles
guest, which is already the most expensive per-mcycle pattern without this defect, that raises the worst-case cost of
computing the mcycle-level claim from about 15 us to about 95 us per mcycle. That is about 6x. It erodes the A7 margin:
the clocks are sized for "the worst-case costs of R12". It does not produce a wrong hash.

The hunter called this "rehashing". That is not accurate. The number of hash computations per call is the same with
and without a full TLB (59 in the test). The extra work is marking, looking up and comparing unchanged pages.

### Component, role and area

`collect_mcycle_root_hashes` and the hash tree (`src/machine.cpp`, the hash-tree update and its page cache). Role:
honest operator. The AUDIT.md table lists "Interpreter, state-access layers, devices, uarch program, hash tree, log
producers, `collect_mcycle_root_hashes` and `collect_uarch_cycle_root_hashes`, ..." as "Honest operator".

### Location

- `src/machine.cpp`: `machine::collect_mcycle_root_hashes` (from line 2424). It calls `update_hash_tree()` on entry
  (line 2451) and breaks on any reason other than `reached_target_mcycle` (around line 2557).
- `src/machine.cpp`: `machine::update_hash_tree` (line 1645), `machine::mark_write_tlb_dirty_pages` (line 1639) and
  `machine::mark_write_tlb_dirty_page` (line 1619).
- `src/collect-mcycle-hashes-state-access.hpp`: write tracking into `context.dirty_pages` (lines 78 and 82).
- Caller on the honest operator's path: `doc/recipes/prt.lua`, `run_to_stop` (line 1396) and
  `mcycle_computation_hash_run` (line 1576).

### Evidence and test

`bugs/R1-R8-3/` contains `test.lua` (the test, with a hand-assembled bare-metal guest inlined as six instruction words)
and `README.md`. Run it with `bugs/run.sh R1-R8-3`. It runs in well under a second.

The guest runs on a machine with 4 MiB of RAM. It stores non-zero data to N distinct pages, which fills N write-TLB
slots, and then loops on `sd t1,0(t4); j .` with `t1` set to an automatic yield (progress). After one warm-up call,
the test makes 64 calls to `collect_mcycle_root_hashes(MCYCLE_MAX, 10, 0, 0)`. Each call runs 2 mcycles to the next
yield and writes no memory. The test then reads `get_hash_tree_stats`. The control uses N = 1 and the subject uses
N = 256. The test asserts, deterministically and without timing, that pages visited per call (`page_hits +
page_misses`) with a full TLB are at most the control plus 16.

Output on audit/prt2 (the reviewer re-ran it twice; the prover reports four runs, all exit 1). The CPU times vary and
are printed for information only:

```
control  (1 write-TLB slot):    17.0 pages, 2048.0 words compared, 59.0 hashes, 2.0 mcycles per collect call (29.7 us, info)
full TLB (256 write-TLB slots): 272.0 pages, 34688.0 words compared, 59.0 hashes, 2.0 mcycles per collect call (183.1 us, info)
ratio of hash-tree pages visited per call: 16.0x
VIOLATED: R12 / section 8 High: a collect_mcycle_root_hashes call that resumes at an automatic yield with no memory written must not re-visit every page mapped by the write TLB (per-call hash-tree work must not grow with valid write-TLB slots)
run.sh: R1-R8-3: exit 1 (bug present)
```

The page counts, word counts and hash counts are identical across runs. The test exits 0 once a call that resumes
with an up-to-date hash tree skips the re-scan of unchanged write-TLB pages. The reviewer made no changes to the test.

### Trigger and reachability

The guest triggers it. Any input that takes control of the guest (section 4: "Any input may take control of the
firmware, the kernel, the rollup libraries, and the application") can store to 256 distinct pages and then yield
automatically in a loop. Any assignment of guest-writable memory and registers is presumed reachable. Ordinary guests
that touch many pages, such as Linux, also tend to keep the write TLB full, so a large part of this overhead is paid
at every automatic yield even without an adversary. Ordinary guests yield far less often, though.

### Rating

1. **Out of scope.** Two exclusions were checked.
   - "Average-case performance that does not change the worst-case cost of any operation listed in R12." This does
     not apply: the per-mcycle worst case of computing a claim is a guest that yields every one or two mcycles, and the
     defect multiplies exactly that case by about 6x in time.
   - "An application that tries to exhaust the honest operator through the number of its outputs or yields. ... This
     holds as long as ... each yield costs it a bounded amount (R12)." The per-yield cost here stays bounded (at most
     256 pages). But "How to rate" step 1 says: "The entries about applications exclude what an application loses,
     never an emulator defect that its guest triggers". The defect is the avoidable size of each yield's cost in the
     emulator, not the number of yields, so under the preferred reading the exclusion does not cover it.
2. **Role.** Honest operator. Section 3: "The transition function, its log producers, the computation-hash builders,
   the hash tree and its node proofs ... play this role in every deployment". The AUDIT.md table names
   `collect_mcycle_root_hashes` and the hash tree as honest operator. These clauses cover this component directly.
3. **High and Medium cases.** Section 8, High: "A defect that lets the guest, or host load that the deployment was
   sized for, multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
   operation without the defect, while staying within what the deployment was sized for. A cost that the specified
   semantics require is not a defect. When the sizing is unknown, rate such a constant-factor increase High". R12 lists
   "a part of a claim". The specified semantics do not require re-scanning pages that the collect call itself already
   tracked as unchanged. The factor is constant (bounded by the 256 write-TLB slots), so the case is High.
4. **Critical.** This step does not apply. The cost stays linear in mcycles, with a bounded constant per call, so it is
   not "unbounded, super-linear". It would be Critical only if the inflated cost exceeded what a given deployment was
   sized for, which is unknown.

**Two readings.** Under the literal reading of the yield exclusion (any cost that is bounded per yield is excluded),
this is Out of scope. Under the reading that step 1 supports (application exclusions never excuse an emulator defect
that the guest triggers, and the High constant-factor case covers it), it is High. The text favours the second
reading. The threat model does not say whether "each yield costs it a bounded amount (R12)" means any bound, or the
R12 worst case of the same operation without a defect. Settling that would decide the class.

### Possible solution and risks

Track whether the hash tree may be stale with respect to writes made through the untracked fast path. Set a flag on
`machine::run`, `write_memory`, `write_reg`, shadow writes, loads, TLB changes and every other mutation that does not
mark dirty pages itself. Make `update_hash_tree` run `mark_write_tlb_dirty_pages()` only when the flag is set, and
clear it after a successful update. `collect_mcycle_root_hashes`, whose state access tracks every write, would then
leave the flag clear when it returns. As a secondary improvement, avoid the per-call `result.hashes.reserve` of up to
16384 hashes (512 KiB) when the call ends at an early yield.

Risk: missing a single mutation path that writes through the write TLB without setting the flag would leave pages
unmarked and produce a stale root hash. That is an R9 violation on the honest operator's path, which is Critical. The
change needs a test that compares against `verify_hash_tree` after every API operation sequence, and a careful audit
of every writer.

### Risk of not fixing it

A guest, controlled by any input that subverts it, can make the honest operator's mcycle-level claim computation about
6x slower per mcycle than the worst case without the defect, for as many mcycles as the application's own bound
allows. A deployment whose clocks and hardware were sized on measurements of the cost without the defect loses that
margin (A7). If the margin is thin, the honest claim could time out. Mitigation outside the code: size A7 against
this measured worst case, a guest yielding every one or two mcycles with a full write TLB.
