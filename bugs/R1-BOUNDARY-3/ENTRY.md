## R1-BOUNDARY-3

**Title.** crisium's seal lookup fetches, keeps and re-decodes every consensus log since the deployment block, so the
player's restart and each new epoch cost work and memory that grow with the number of past epochs.

**Severity.** Medium (preferred reading). Low under a reading that would excuse the growth because each past epoch
adds only a few small logs (see Rating).

### Problem

`get_seal(number)` in `doc/recipes/crisium.lua` looks up the seal of one epoch by asking the process-wide
`seal_history` (a `prt-log-history` object) for every log the consensus has emitted since
`getDeploymentBlockNumber()`, with no topic filter. It then decodes them in order with `abi:event` until it finds
`EpochSealed(number)`. `open_epochs` calls it once for every epoch it opens, and `pass()` calls `open_epochs` on every
pass. `prt-log-history.lua` never drops a log except on a reorg rewind. The result:

- a relaunch fetches every consensus log since deployment (`EpochSealed`, `EpochStaged`, `SentryClaim`, ...);
- the process keeps all of them in memory for as long as it lives;
- every new epoch decodes all of them again.

Only the seal of the previous epoch is needed, and `epochNumber` is an indexed topic of `EpochSealed`
(`IDaveConsensus.sol`), so a constant-cost lookup is available.

This does not break the goal of section 1 at realistic ages, since the logs are small. It violates the letter of R12:
"The honest operator's own work outside the emulator, such as observing the chain, keeping and persisting its own
records, and restarting, has a bounded cost per input, per yield, and per match, and its total grows only with the
inputs, yields, and matches of the epochs still open. That total must not grow with the application's age, with the
number of past epochs, or with chain activity that does not belong to the application."

### Component, role and area

The PRT player process `doc/recipes/crisium.lua`, with `doc/recipes/prt-log-history.lua`. AUDIT.md role: "The PRT
player and bridge in `doc/recipes`, ... | Support. No production deployment runs the player, the bridge or the CLI."
It stands in for the honest operator's chain observation and restart. Area: observing consensus seals.

### Location

- `doc/recipes/crisium.lua`: `first_block = getDeploymentBlockNumber()` (line 125); `seal_history =
  log_history.new(chain)` and `get_seal` (lines 207-219); `open_epochs` (from line 222), which `pass()` calls.
- `doc/recipes/prt-log-history.lua`: `get_logs`/`get_logs_of` keep every fetched log in `self.logs` and never prune
  it.

### Evidence and test

`bugs/R1-BOUNDARY-3/` contains `README.md` and `test.lua`. Run it with `bugs/run.sh R1-BOUNDARY-3` (optional
arguments `E_small E_large`, default 2 and 200). Set `CRISIUM_LUA=<file>` to test a candidate fix. The test loads the
real `crisium.lua` in-process, with the real `prt-log-history.lua` and the real ABI decoding of the pinned Dave
artifacts (`bugs/harness/work/dave/patched`). It stubs only the transport (`prt-rpc`, an in-memory mock chain), the
checkpoint loader and player (`prt`), the epoch listener (`prt-epoch`), `prt-bridge.read_geometry`, `prt-dishonest`
and `prt-websocket`, none of which takes part in `get_seal`. The mock consensus holds `EpochSealed(k)` for
k = 0..E-1 and `EpochStaged(k)` for k = 0..E-2. The test runs two phases:

1. A restart from checkpoint `epoch-E`, which needs the seal of epoch E-1.
2. Epoch E is sealed, checkpoint `epoch-(E+1)` appears, and the player opens epoch E+1.

In each phase the test counts the logs `eth_getLogs` hands over and the logs `abi:event` decodes. It requires both
counts to stay within 4 logs of the E = 2 value at E = 200. On audit/prt2 it prints the following (plus a harmless
"Relink ... IFUNC" loader warning on stderr) and exits 1:

```
past epochs    2 (consensus logs    5): restart fetched    3 decoded    3 (1 requests) | new epoch fetched    2 decoded    5 (1 requests)
past epochs  200 (consensus logs  401): restart fetched  399 decoded  399 (1 requests) | new epoch fetched    2 decoded  401 (1 requests)
VIOLATION restart: logs fetched grow from 3 (2 past epochs) to 399 (200 past epochs)
VIOLATION restart: logs decoded grow from 3 (2 past epochs) to 399 (200 past epochs)
VIOLATION new epoch: logs decoded grow from 5 (2 past epochs) to 401 (200 past epochs)
VIOLATED: R12: crisium's seal lookup must not grow with the number of past epochs (restart and per-epoch observation cost)
run.sh: R1-BOUNDARY-3: exit 1 (bug present)
```

The reviewer re-ran it four times with the same output and exit 1. The reviewer also ran a scratch copy of
`crisium.lua` whose `get_seal` uses a fresh history filtered by `abi:topics("EpochSealed", number)`. With that copy
the test printed 1 fetched and 1 decoded in both phases for both E, and exited 0. So the test fails because of the
defect and passes once it is fixed. All agents ran on Opus 5.5; no fallback was used.

### Trigger and reachability

No adversary is needed. The passage of time triggers it: every sealed epoch adds at least an `EpochStaged` and an
`EpochSealed` log, and sentry claims add `SentryClaim` logs. Every relaunch pays for the whole history once, and every
epoch opened afterwards decodes it again. Memory grows for the life of the process. Every deployment reaches this
state after enough epochs.

### Rating

1. Out of scope: no. The trigger is the normal sealing of epochs. None of the exclusions applies. The entry "Average-case
   performance that does not change the worst-case cost of any operation listed in R12" does not cover it. The
   operator-work clause of R12 is a separate requirement, and the defect makes the worst-case cost of a restart and of
   an epoch opening grow with age without bound.
2. Role: Support. Per AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support". Section 3: "A defect that
   only a support component shows is Medium when it would rate High or Critical in the role the component stands in
   for, such as ... the honest operator for an implementation of an operator". crisium.lua is "an implementation of
   an operator that no deployment runs", so it stands in for the honest operator. This clause covers the component.
   No component in another role in scope shares the defect (validator nodes are out of scope per AUDIT.md).
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." It applies
   if the defect would rate High or Critical in the honest-operator role. In that role, the High case "multiply the
   worst-case cost of an operation listed in R12 by a constant factor" does not fit, because the growth is unbounded
   in the number of past epochs, not a constant factor. Step 4 then applies to the stand-in role.
4. Critical (in the stand-in role): "violating any rule or obligation at a reachable state, or anywhere on the honest
   operator's path, is critical". The honest operator's path includes "Observing the chain" and "Restarting after a
   stop" (section 2). R12 says the operator's own work "must not grow with the application's age, with the number of
   past epochs". So the defect is Critical for the honest operator, which makes it **Medium** for this support
   component.

Two readings. R12 has no materiality threshold. The preferred reading takes its "must not grow" literally: the
stand-in rating is Critical, so the support rating is Medium. Another reading would treat growth of a few hundred
bytes and a few decodes per past epoch as no real threat to the operator's provisioned resources, so it would not
rate High or Critical even for a real operator. The defect would then be Low. What would decide is whether R12's
operator-work clause allows growth that is linear in the age but small per epoch. Its text says it does not.

### Possible solution and risks

In `get_seal`, fetch only the needed log: filter the query by `abi:topics("EpochSealed", number)`. Alternatively,
keep a seal history whose start block moves to the previous seal's block, and drop logs older than the oldest open
epoch. In either case the process should not keep logs of finished epochs. Risks:

- The filtered query must keep the reorg handling of `prt-log-history`, with the history keyed per epoch number.
- `first_input_block` is derived from `previous_seal.log.blockNumber`, so the returned event must still carry its
  log.
- An RPC node still scans its index from the deployment block for a topic-filtered query. That is node-side cost, not
  the operator's own records.

### Risk of not fixing it

The player is a reference implementation that no deployment runs. Anyone who models a production node on it inherits
observation work and memory that grow with the application's lifetime, and restarts that slow down with age. That
would eventually conflict with A7 sizing for a long-lived application. No adversary can accelerate it beyond the rate
at which epochs are sealed and sentry claims are posted. No option of the player mitigates it: `--first-epoch` does not
change where `get_seal` starts, which is always the deployment block.
