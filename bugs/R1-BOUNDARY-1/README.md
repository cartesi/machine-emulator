# R1-BOUNDARY-1: the PRT bridge's observation grows with foreign logs of the shared tournament factory

Component: PRT bridge, `doc/recipes/prt-bridge.lua` `methods:observe` with `prt-log-history.lua`, as
`prt-epoch.lua` starts it (`first_block = seal_block`). Role: Support (it stands in for the honest operator's
chain observation).

## Requirement

THREAT_MODEL.md R12:

> The honest operator's own work outside the emulator, such as observing the chain, keeping and persisting its own
> records, and restarting, has a bounded cost per input, per yield, and per match, and its total grows only with the
> inputs, yields, and matches of the epochs still open. That total must not grow with the application's age, with the
> number of past epochs, or with chain activity that does not belong to the application.

Section 7 gives the adversary: "Raise activity on the chain that does not belong to the application".

## What the test does

`observe` fetches the logs of `{factory, consensus, root}` from the seal block up to the head, keeps every
one of them in the history, and on every observation re-sorts and walks all of them, putting every decoded
event into `snapshot.events`. The tournament factory is shared by every Dave application and its
`instantiate` is permissionless, but the bridge only needs its own root's `TournamentCreated`, which is in
the seal block.

`test.lua` builds a mock chain (the style of the pruning fixture of `prt-bridge-test.lua`, decoded events
behind a stub ABI) with a fixed application history: the root's `TournamentCreated` and `EpochSealed` in the
seal block and three events of the root. After the seal, K `TournamentCreated` logs of other tournaments
come from the factory. A `new_observer` bridge observes once, then four more times while the head advances
with no new log. The run is done with K = 0 (control) and K = 3000 (`bugs/run.sh R1-BOUNDARY-1 <K>` to
change it). Asserted, each within 64 of the control:

* `fetched`: log records the chain hands to the bridge;
* `logs`, `events`: sizes of the last snapshot's `logs` and `events`;
* `reads`: field reads on log records (through proxies) during the four later observations, a
  deterministic measure of the per-observation sort and walk.

Exit 0 when all four counts do not depend on K, 1 when they grow with K, 2 on setup error. A copy of the
bridge that reads the factory only over `[first_block, seal_block]` and keeps only the root's creation log
passes (exit 0), so the test does not depend on the current design.

## Run

```sh
bugs/run.sh R1-BOUNDARY-1        # < 1 s
```

## Expected output on audit/prt2

```
fetched  control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
logs     control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
events   control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
reads    control (K=0) = 352      with K=3000 foreign factory logs = 844852   grows with K
VIOLATED: R12: ...
run.sh: R1-BOUNDARY-1: exit 1 (bug present)
```

Each of the four later observations reads about 280 fields per foreign log (the sort is O(n log n)), so the
work of every observation grows with chain activity that does not belong to the application, and the
records stay in memory for the life of the bridge.
