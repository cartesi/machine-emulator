## R1-R12-3

**Title.** The PRT epoch listener (`prt-epoch.lua` `poll()`) and the PRT bridge (`prt-bridge.lua` `observe()`) copy,
sort and rescan every log already processed on every observation, so the cost of observing one more input or match log
grows with the number already seen, and the total over an epoch is quadratic.

**Severity.** Medium

### Problem

Both observers get their logs from `prt-log-history.lua`, which fetches only new blocks but keeps every fetched log.
They then redo all the work on all of those logs on every call:

- `poll()` (`prt-epoch.lua` lines 35-66) copies every InputBox and consensus log fetched since the epoch's first block
  into a new table, `table.sort`s it (`less` decodes `blockNumber` and `logIndex` with `eth.small` on every
  comparison), and walks it again to check duplicates, block hashes and the `applied` prefix. Only after that does it
  handle the logs past `#self.applied`.
- `observe()` (`prt-bridge.lua` lines 64-203) copies every log of the factory, consensus, root and inner tournaments
  fetched since the seal, sorts them with `log_less`, and replays all of them to rebuild `contexts`, `matches`,
  `events` and the duplicate and block-hash checks from scratch.

The PRT player `crisium.lua` runs `pass()` on every new block (lines 360-372): each listener polls, and each sealed
epoch's bridge ticks, which observes at least once (`refresh()`). So with n logs already in an open epoch or dispute,
every block costs O(n log n) work on logs that were already processed, and an adversary who adds one input or one
match log per block makes the honest work of an epoch O(n^2 log n) instead of O(n).

R12 requires: "The honest operator's own work outside the emulator, such as observing the chain, keeping and
persisting its own records, and restarting, has a bounded cost per input, per yield, and per match". The cost of
observing one more input or one more match log here is not bounded: it grows with the number of inputs (up to
2^24 per epoch, `ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = 24`) or match logs already seen. In the role the player
stands in for, this threatens the goal through completeness: an honest operator whose observation work grows
quadratically with adversarial inputs and Sybil moves may fall behind the dispute clocks (R4, "observes the chain and
submits its transactions within the dispute clocks"; A7 sizes clocks for the worst-case costs of R12).

The unfiltered fetch of the shared factory's logs is a separate candidate (R1-BOUNDARY-1) and is not tested here.

### Component, role and area

The PRT player's epoch listener and dispute bridge in `doc/recipes` (`prt-epoch.lua`, `prt-bridge.lua`, with
`prt-log-history.lua` and the player loop in `crisium.lua`). AUDIT.md table: "The PRT player and bridge in
`doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the CLI." It stands in for the
honest operator (section 3: "implementations of an operator that no deployment runs"). Area: chain observation.

### Location

- `doc/recipes/prt-epoch.lua`, `methods:poll()` (lines 25-135; the full copy, sort and rescan at lines 35-66).
- `doc/recipes/prt-bridge.lua`, `methods:observe()` (lines 48-204; the full copy at 64-105, sort at 110, replay at
  111-179), called by `refresh()` (336-344) from `tick()` (692).
- `doc/recipes/prt-log-history.lua`, which keeps every fetched log in `self.logs` and returns all of them from
  `get_logs_of()`.
- `doc/recipes/crisium.lua`, `pass()` (295-320) and the main loop (360-380), which poll and tick on every new block.

### Evidence and test

`bugs/R1-R12-3/` contains `test.lua` (the test), `README.md` (the prover's description) and this entry. Run it with
`bugs/run.sh R1-R12-3` (about 1 s; no chain and no emulator machine needed).

The test loads the real `prt-epoch` and `prt-bridge` modules against an in-memory chain whose logs are proxies that
count reads of their fields (the mock's own reads are not counted, and the ABI decoder is a table lookup). For the
listener it lets `poll()` deliver K `InputAdded` logs, marks them processed, appends one more input and counts the
field reads of the K old logs during the next `poll()`. For the bridge it lets `observe()` see K `CommitmentJoined`
logs in the root tournament, appends one more and counts the reads of the K old logs during the next `observe()`. It
asserts that going from K=300 to K=3000 at most doubles that count (plus 64), which an incremental implementation,
even one with logarithmic lookups, meets; the prover's scratch incremental `poll()` read 1 field at both sizes.
Counts, not time, so it is deterministic.

On audit/prt2 the reviewer re-ran it twice; both runs printed the same counts and exited 1:

```
prt-epoch poll (K inputs): field reads of already-processed logs in one observation after one new log: K=300 -> 7188, K=3000 -> 90974 (x12.7)
VIOLATED: prt-epoch poll (K inputs): R12 bounded cost per input/match: the work of one observation on logs already processed must not grow with their number
prt-bridge observe (K commitments): field reads of already-processed logs in one observation after one new log: K=300 -> 11775, K=3000 -> 155055 (x13.2)
VIOLATED: prt-bridge observe (K commitments): R12 bounded cost per input/match: the work of one observation on logs already processed must not grow with their number
run.sh: R1-R12-3: exit 1 (bug present)
```

The growth (x12.7 and x13.2 for x10 logs) is the K log K of the sort plus the linear rescan. The test was not
modified by the reviewer. All agents ran on Opus 5.5; no fallback model was used.

### Trigger and reachability

Any input sender ("Send any number of inputs the deployment accepts", section 7) adds inputs for the application to
the InputBox, at most 2^24 per epoch; any dishonest claimant ("Post any number of claims (Sybils)") adds joins and
match logs to the dispute. Each new block then makes the player re-sort and rescan every log of the open epoch and of
each open dispute. Nothing has to be unreachable: these are ordinary chain histories, and the player polls on every
new header by design.

### Rating

1. Out of scope: no. The trigger is inputs and Sybil claims, which section 7 grants the adversary. It is not
   "Average-case performance that does not change the worst-case cost of any operation listed in R12": the defect
   raises the worst case (adversarial inputs and match logs, one per block) from linear to quadratic. It needs no
   untrusted call to the machine API, no deployment violation, and no reorganization.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support." This clause covers both
   `prt-epoch.lua` (the player's listener, driven by `crisium.lua`) and `prt-bridge.lua`. Section 3: "A defect that only
   a support component shows is Medium when it would rate High or Critical in the role the component stands in for,
   such as ... the honest operator for an implementation of an operator". The player stands in for the honest
   operator. No component in the honest-operator role in this campaign shares the code (the validator nodes are out
   of scope).
3. High and Medium cases: for the support component, "A defect that only a support component shows, when section 3
   rates it Medium." That depends on the stood-in rating, which falls to step 4 (Critical); the High constant-factor
   case does not fit because the factor grows with the number of inputs and match logs, and the Critical bullet "An
   operation listed in R12 whose worst-case cost a guest can make unbounded, super-linear" names the operations of
   R12's first paragraph, which do not include observing the chain.
4. Critical (in the stood-in honest-operator role): R12, "The honest operator's own work outside the emulator, such as
   observing the chain, ... has a bounded cost per input, per yield, and per match", is violated on the honest
   operator's path ("Observing the chain", section 2): the cost of observing one more input or match log grows as
   O(n log n) in the n logs already seen. Critical in the stood-in role, hence Medium for the support component.

Second reading: R12 also says the total "grows only with the inputs, yields, and matches of the epochs still open",
and the rescan is limited to the open epoch and its dispute (after the seal `poll()` returns early, and the bridge
fetches from the seal on). If "bounded cost per input" were read as satisfied whenever the work depends only on
open-epoch items, with the number of observations treated as a deployment constant (epoch and dispute duration over
the block time), the defect would be a constant-factor multiplication of the honest work (High in the stood-in role)
and still Medium for the support component. Only a reading that drops "bounded cost per input" entirely would make it
Low. The facts that decide between the first two readings are whether the polls per epoch count as a constant; both
give Medium here.

### Possible solution and risks

Process logs incrementally. In `poll()`, keep the duplicate set and per-block hash map across calls and handle only
the logs past those already applied (the history returns logs per address in fetch order, so a merge of the new tail
suffices). In `observe()`, keep `contexts`, `matches`, `deleted`, `recovered`, `events` and the duplicate and block
maps as persistent state, and apply only the new tail of each address's logs, in global order. Risks: reorg handling.
Today a reorg is handled by `history:reset()` plus a full rebuild; an incremental version must roll its derived state
back to the common ancestor (or rebuild from scratch only on a reorg), and must keep the global log order across
addresses when new logs of different tournaments arrive in the same observation. The bridge's snapshot currently
returns fresh `events` and `logs` arrays, which callers may iterate; those consumers would need to accept incremental
or shared tables.

### Risk of not fixing it

A player run from these recipes slows down quadratically when an adversary floods an epoch with inputs or a dispute
with Sybil joins and moves, and may miss the dispute clocks while it rescans. No production deployment runs the
player, so the direct exposure is limited to demonstrations and tests; the risk is that a production node modeled on
these recipes inherits the rescan. Mitigation outside the code: longer poll intervals reduce the per-epoch total but
not the per-observation O(n log n), and lengthen reaction times.
