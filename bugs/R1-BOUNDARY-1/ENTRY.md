## R1-BOUNDARY-1

**Title.** The PRT bridge fetches, keeps, re-sorts and rescans every log of the shared, permissionless tournament
factory on every observation, so its chain observation grows with chain activity that does not belong to the
application.

**Severity.** Medium

### Problem

`methods:observe` of the PRT bridge fetches the logs of `{factory, consensus, root}` from `first_block` (the seal block,
as `prt-epoch.lua` starts it) up to the observation head. The tournament factory is shared: `DaveAppFactory` passes
one immutable `TOURNAMENT_FACTORY` to every `DaveConsensus` it creates, and `MultiLevelTournamentFactory.instantiate`
is permissionless (its own interface says "Anyone can call `instantiate`"). Every `TournamentCreated` log that the
factory emits after the seal, whether from another application's epoch seal or from anyone calling `instantiate`, is
therefore fetched, kept for the life of the bridge in `prt-log-history.lua` and in the bridge's `decoded` cache,
appended to `logs`, `table.sort`ed and walked again on every observation, and put into `snapshot.events`, which
later bridge code walks again. The bridge only needs its own root's `TournamentCreated`, which is in the seal block,
and it discards every foreign one in the walk (`address == self.root` fails). `TournamentCreated` has no indexed
parameters, so the factory's logs cannot be narrowed by topic; the bridge must bound the block range instead.

This does not break the goal by itself (the bridge is not run by any deployment), but it violates R12, which requires
the honest operator's chain observation not to grow with chain activity that does not belong to the application. A
real operator built like this bridge would be slowed, per observation and in memory, by foreign activity during an
open dispute, eating into the clock margin that R4 and A7 rely on.

### Component, role and area

The PRT bridge in `doc/recipes` (chain observation), with the log history it uses. AUDIT.md: "The PRT player and
bridge in `doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the CLI." It stands
in for the honest operator's observing of the chain.

### Location

- `doc/recipes/prt-bridge.lua`, `methods:observe`: line 57 (`addresses = { self.factory, self.consensus, self.root }`),
  lines 58-59 (`first_blocks[self.factory] = self.first_block`, no upper bound), the fetch loop (66-105,
  `logs[#logs + 1] = log` for every factory log), `table.sort(logs, log_less)` (line 110), the walk that adds every
  decoded event to `events` (111-179), and the returned `events` and `logs`.
- `doc/recipes/prt-log-history.lua`, `get_logs_of`/`fetch`: keeps every fetched log per address until a reset.
- `doc/recipes/prt-epoch.lua` (around line 126): `first_block = self.seal_block` when it creates the bridge.
- Pinned Dave v3.0.0-alpha.7: `prt/contracts/src/ITournamentFactory.sol` (event without indexed fields, "Anyone can
  call `instantiate`"), `MultiLevelTournamentFactory.instantiate` (lines 79-92, external, no access control, emits
  `TournamentCreated`), `cartesi-rollups/contracts/src/DaveAppFactory.sol` (one immutable `TOURNAMENT_FACTORY` for
  every application).

### Evidence and test

`bugs/R1-BOUNDARY-1/` contains `test.lua` and `README.md`. Run `bugs/run.sh R1-BOUNDARY-1` (under a second; an
optional argument sets K, default 3000). The test builds a mock chain in the style of the pruning fixture of
`prt-bridge-test.lua` (log records behind read-counting proxies, a stub ABI returning decoded events) with a fixed
application history: the root's `TournamentCreated` and `EpochSealed` in seal block 1, and three events of the root.
After the seal, the factory emits K `TournamentCreated` logs of other tournaments. A bridge `new_observer` (with
`first_block = seal_block = 1`, as `prt-epoch.lua` starts it) observes once, then four more times while the head
advances with no new log. It runs once with K = 0 and once with K = 3000 and requires four counts to stay within 64 of
the control: log records handed to the bridge, `#snapshot.logs`, `#snapshot.events`, and field reads on log records
during the four later observations. On audit/prt2 it prints:

```
fetched  control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
logs     control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
events   control (K=0) = 5        with K=3000 foreign factory logs = 3005     grows with K
reads    control (K=0) = 352      with K=3000 foreign factory logs = 852972   grows with K
VIOLATED: R12: the honest operator's chain observation 'must not grow ... with chain activity that does not belong to the application' (foreign TournamentCreated logs of the shared tournament factory)
run.sh: R1-BOUNDARY-1: exit 1 (bug present)
```

The `reads` count varies slightly between runs (for example 842812, 852972) because Lua 5.4's `table.sort`
randomizes its pivot on large arrays; it is always about 280 reads per foreign log against 352 in the control, and
the exit status is always 1. The prover ran it twice and with K = 10000 (exit 1 each time); the reviewer re-ran it
twice (exit 1 both times).

The reviewer also checked that the test passes once the defect is fixed: a scratch copy of `prt-bridge.lua` that,
when `seal_block` is known, reads the factory once over `[first_block, seal_block]`, keeps only the root's
`TournamentCreated`, and fetches only `{consensus, root}` incrementally, makes the test print 5, 5, 5, 332 for both
K = 0 and K = 3000 (and for K = 10000) and exit 0. The test asserts the R12 property, not the current design.

### Trigger and reachability

Anyone, during an open dispute of the application: by calling `instantiate` on the shared factory any number of
times (section 7: "Raise activity on the chain that does not belong to the application"), or with no adversary at
all, through other applications created by the same `DaveAppFactory`, each of whose epoch seals emits a
`TournamentCreated` on the same factory. The bridge observes on every `refresh` (`methods:refresh`, line 337, called again at line 601), for as long as the epoch's dispute is open. No emulator state is involved; the trigger is ordinary
chain activity, so there is no reachability condition.

### Rating

1. Out of scope: no. The trigger is chain activity, which section 7 grants the adversary ("Raise activity on the chain
   that does not belong to the application, such as inputs to other applications that share its input record"). The
   closest exclusion, "Average-case performance that does not change the worst-case cost of any operation listed in
   R12", does not fit: the worst-case cost of each observation and the bridge's memory grow without bound with K.
   AUDIT.md excludes "the validator nodes (the sling node ... and the Cartesi Rollups Node)", not the bridge, which
   its table lists as in-scope Support.
2. Role: Support (AUDIT.md table above). Section 3: "Support. ... Examples are ... implementations of an operator that
   no deployment runs ... A defect that only a support component shows is Medium when it would rate High or Critical
   in the role the component stands in for, such as ... the honest operator for an implementation of an operator".
   This clause covers the bridge: it is the chain-observation part of an implementation of an operator, so it stands
   in for the honest operator, and section 2 lists "Observing the chain" on the honest operator's path. Step 2 also
   says "A defect that only a support component shows is never above Medium".
3. High and Medium cases: the Medium case "A defect that only a support component shows, when section 3 rates it
   Medium" fits, given the rating in the honest-operator role from step 4. No High case fits in that role: the
   constant-factor case speaks of "an operation listed in R12" multiplied "by a constant factor", while here the
   growth is unbounded in K.
4. Critical (in the stood-in role): R12, "The honest operator's own work outside the emulator, such as observing the
   chain, keeping and persisting its own records, and restarting, has a bounded cost per input, per yield, and per
   match, and its total grows only with the inputs, yields, and matches of the epochs still open. That total must not
   grow with the application's age, with the number of past epochs, or with chain activity that does not belong to
   the application." Section 8: "violating any rule or obligation ... anywhere on the honest operator's path, is
   critical." In the honest-operator role this is Critical, so section 3 rates the support defect Medium.

Both readings considered give Medium: whether the stood-in rating is Critical (step 4) or High (if one read the
constant-factor case as covering it), section 3 maps it to Medium. The bridge would be Low only if it were not taken
to stand in for the honest operator, which the quoted example of section 3 contradicts.

### Possible solution and risks

When the seal block is known, read the factory only over `[first_block, seal_block]` (once, then cache), keep only the
`TournamentCreated` whose `tournament` is the root named by the consensus's `EpochSealed`, and fetch only the consensus
and the tournaments reached from the root incrementally. Alternatively, take the root's creation log from the seal
transaction's receipt. Risks: the seal block can hold other applications' `TournamentCreated` logs (bounded by the
block gas limit, so a constant); a reorg of the seal block must still reset the cached creation log (the bridge
already asserts the seal is canonical on every observation); and a bridge started without `seal_block` (the generic
path) must keep reading the factory until it finds the root, then stop. The related full re-sort and rescan of the
application's own logs on each observation is a separate candidate (R1-R12-3).

### Risk of not fixing it

The bridge is not run by any deployment, so no deployment is exposed directly. Code that follows it as a reference
for a validator node inherits a chain observation whose time and memory per observation grow with every
`TournamentCreated` on the shared factory during a dispute, which anyone can raise at gas cost and which other
applications raise without intent; with enough of it, observations slow until the operator risks missing its dispute
clocks. Outside the code, an operator can only shorten the dispute window it watches or restart the bridge, which
does not help because a restart refetches from the seal block.
