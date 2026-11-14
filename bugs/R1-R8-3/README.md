# R1-R8-3: every `collect_mcycle_root_hashes` call re-visits all pages mapped by the write TLB

## What is asserted

`machine::collect_mcycle_root_hashes` (`src/machine.cpp`) calls `update_hash_tree()` on entry, which runs
`mark_write_tlb_dirty_pages()`: it marks dirty the page of every valid write-TLB slot, whether or not anything was
written since the previous update (inside the call, the collect state access already tracks every write in
`context.dirty_pages`). The call returns at every automatic yield, and the honest operator's builder calls it again
for the rest of the period (`doc/recipes/prt.lua`, `run_to_stop` / `mcycle_computation_hash_run`).

The test runs a hand-assembled guest (4 MiB RAM) that stores non-zero data to N distinct pages (filling N write-TLB
slots) and then loops on `sd t1,0(t4); j .` with `t1` = automatic yield (progress). After a warm-up call, it makes
64 `collect_mcycle_root_hashes` calls, each of which runs 2 mcycles to the next automatic yield without writing any
memory, and reads the hash-tree statistics (`get_hash_tree_stats`: pages looked up = `page_hits + page_misses`,
words compared). Control: N = 1. Subject: N = 256 (a full write TLB). Same mcycles per call in both.

Required (deterministic, no timing): pages visited per call with a full write TLB <= control + 16.

Observed on audit/prt2: 17 pages / 2048 words compared per call (control) vs 272 pages / 34688 words compared per
call (full TLB), 16x. The number of hash computations is the same in both runs (59 per call): the extra work is
marking, looking up and word-comparing ~1 MiB of unchanged pages against the page cache (the hunter's description
of it as "rehashing" is not accurate; the pages are compared, not rehashed). CPU time per call, printed for
information only and not asserted: about 30 us (control) vs about 190-200 us (full TLB), against ~0.1 us for
`machine:run` to the same yield.

## Requirement

THREAT_MODEL.md R12: "Each of the following operations has a worst case in host time and memory that is bounded and
at most linear in the cycles it executes ... a part of a claim ...". Section 8, High: "A defect that lets the guest
... multiply the worst-case cost of an operation listed in R12 by a constant factor, compared with the same
operation without the defect, while staying within what the deployment was sized for. A cost that the specified
semantics require is not a defect."

The reviewer must weigh the exclusion in section 8 ("An application that tries to exhaust the honest operator
through the number of its outputs or yields ... as long as ... each yield costs it a bounded amount (R12)"): the
per-yield cost here is bounded (at most 256 pages), but its size is what the guest inflates.

## Run

```sh
bugs/run.sh R1-R8-3
```

Runs in well under a second.

## Expected output on audit/prt2

```
control  (1 write-TLB slot):    17.0 pages, 2048.0 words compared, 59.0 hashes, 2.0 mcycles per collect call (~30 us, info)
full TLB (256 write-TLB slots): 272.0 pages, 34688.0 words compared, 59.0 hashes, 2.0 mcycles per collect call (~195 us, info)
ratio of hash-tree pages visited per call: 16.0x
VIOLATED: R12 / section 8 High: ...
run.sh: R1-R8-3: exit 1 (bug present)
```

Exit 1 while the defect is present; exit 0 once a collect call stops re-visiting unchanged write-TLB pages; exit 2 on
setup errors.
