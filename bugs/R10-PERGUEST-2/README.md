# R10-PERGUEST-2: every automatic yield costs `collect_mcycle_root_hashes` two shadow-state hash-tree updates

## What is asserted

`machine::collect_mcycle_root_hashes` (`src/machine.cpp`) returns at every automatic yield (documented: it reports
the same break reasons as `machine:run()`), and the honest builder calls it again for the rest of the period
(`doc/recipes/prt.lua`, `run_to_stop` / `mcycle_computation_hash_run`). Each such call:

1. runs `update_hash_tree()` on entry, which marks the shadow uarch state, the shadow registers and the 6 shadow TLB
   pages dirty (`machine_address_ranges::mark_always_dirty_pages`) and updates the tree;
2. after the interpreter returns at the yield, updates the tree again (`m_ht.update(m_ars)`) over the 8 shadow-state
   pages that `collect_mcycle_hashes_state_access::do_write_mcycle` marks dirty on every interpreter exit, before it
   checks whether the reached mcycle is a sampling point at all.

No hash is needed at an automatic yield that is not a sampling point.

The test runs a hand-assembled guest (4 MiB RAM, no RAM stores, so the write TLB holds no valid slot and R1-R8-3
does not contribute) that loops on `sd t1,0(tohost); j .` with `t1` = automatic yield (progress). With log2 sampling
period 30, after a warm-up call it makes 256 `collect_mcycle_root_hashes` calls (2 mcycles each, no sample
collected) and reads `get_hash_tree_stats` (pages looked up = `page_hits + page_misses`). Control: a guest that spins
(`addi; j`) over the same number of mcycles, collected in one call with the same period.

Required (deterministic, no timing): pages looked up by the subject <= control + 2 per automatic yield (the
shadow-registers page the yield actually writes, plus one of margin).

Observed on audit/prt2: 16 pages and 59 node hashes per yield (4096 pages, 15104 hashes for 512 mcycles), against 16
pages and 62 hashes for the whole no-yield span. For comparison (information only), a real sample at log2 period 0
costs 8 pages and ~60 hashes: a non-sampling yield costs about as much as a sample. CPU time, printed for information
and not asserted: ~28 us per collect call at a yield, ~0.1 us for `machine:run()` to the same yield.

## Requirement

THREAT_MODEL.md R12: "Each of the following operations has a worst case in host time and memory that is bounded and
at most linear in the cycles it executes ... a part of a claim ...". Section 8, High: "A defect that lets the guest
... multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
operation without the defect, while staying within what the deployment was sized for. A cost that the specified
semantics require is not a defect. When the sizing is unknown, rate such a constant-factor increase High".

The reviewer must weigh the section 8 exclusion "An application that tries to exhaust the honest operator through
the number of its outputs or yields ... This holds as long as ... each yield costs it a bounded amount (R12)": the
per-yield cost here is bounded (two updates over ~16 shadow pages) but is not required by the semantics.

## Run

```sh
bugs/run.sh R10-PERGUEST-2
```

Runs in well under a second.

## Expected output on audit/prt2

```
subject (automatic yield every 2 mcycles): 512 mcycles, 256 collect calls, 0 samples: 4096 pages, 15104 hashes (16.0 pages, 59.0 hashes per yield)
control (no yields, same span, 1 call):     512 mcycles, 0 samples: 16 pages, 62 hashes
info: one real sample (log2 period 0):      8.0 pages, 60.5 hashes per sample
info: CPU per collect call at a yield 27.8 us, per run() to the same yield 0.11 us
extra hash-tree pages per automatic yield: 15.9 (allowed 2)
VIOLATED: R12 / section 8 High: ...
run.sh: R10-PERGUEST-2: exit 1 (bug present)
```

Exit 1 while the defect is present; exit 0 once a collect call that resumes and stops at a non-sampling automatic
yield no longer updates the hash tree over the always-dirty shadow pages (for example, by updating only at sampling
and fixed points, and only marking pages dirty on entry); exit 2 on setup errors.
