# R1-R12-3: PRT epoch listener and bridge rescan every processed log on each observation

**Component:** `doc/recipes/prt-epoch.lua` `poll()` and `doc/recipes/prt-bridge.lua` `observe()` (with
`prt-log-history.lua`, which keeps every fetched log). Role: support (PRT player and bridge), standing in for the
honest operator.

**Requirement (THREAT_MODEL.md, R12):** "The honest operator's own work outside the emulator, such as observing the
chain, keeping and persisting its own records, and restarting, has a bounded cost per input, per yield, and per
match, and its total grows only with the inputs, yields, and matches of the epochs still open."

**Defect:** on every call, `poll()` copies every InputBox/consensus log fetched since the epoch's first block into a
new table, `table.sort`s it, and walks all of it (duplicate and block-hash checks, comparison with `applied`) before
handling the new ones. `observe()` likewise copies, sorts and replays every log of the factory, consensus, root and
inner tournaments fetched since the seal. So the cost of observing one more input or one more claim/move is
O(n log n) in the logs already processed, and the total over an epoch is quadratic in its inputs and match logs.
(The unfiltered fetch of the shared factory's logs is R1-BOUNDARY-1 and is not tested here.)

**What the test does:** it drives the real recipe modules against an in-memory chain whose logs are proxies that
count field reads. After K logs have been observed and processed (K delivered `InputAdded` logs for `poll()`, K
`CommitmentJoined` Sybil joins in the root tournament for `observe()`), it appends one log and observes once more,
counting reads of fields of the K already-processed logs. It requires that going from K=300 to K=3000 at most doubles
that work (plus 64), which an incremental implementation, even one with logarithmic lookups, meets. Counts, not time,
so the result is deterministic. A scratch experiment with an incremental `poll()` (processing only the logs past
those already seen) gave 1 read at both K and passed that check.

**Run:** `bugs/run.sh R1-R12-3` (about 1 s, no chain, no emulator machine).

**Expected output on audit/prt2 (exit 1):**

```
prt-epoch poll (K inputs): field reads of already-processed logs in one observation after one new log: K=300 -> 7188, K=3000 -> 90974 (x12.7)
VIOLATED: prt-epoch poll (K inputs): R12 bounded cost per input/match: ...
prt-bridge observe (K commitments): field reads of already-processed logs in one observation after one new log: K=300 -> 11775, K=3000 -> 155055 (x13.2)
VIOLATED: prt-bridge observe (K commitments): R12 bounded cost per input/match: ...
run.sh: R1-R12-3: exit 1 (bug present)
```

Exit 0 once both `poll()` and `observe()` process new logs incrementally; exit 2 on setup errors.
