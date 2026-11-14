## R3-VARSCHED-1

**Title.** The PRT bridge preflights a job at the tip's block, though it treats the job as due for the next block, so a timeout or inner-tournament win that becomes valid at block `first` reverts, lands one block late, and is never sent when its window is one block long.

**Severity.** Medium

### Problem

`methods:submit` of the PRT transaction journal treats a job as includable when the next block can include it
(`tip + 1 >= intent.first`), and `methods:tick` of the bridge wakes up at `tip = first - 1` for the same reason. The
preflight runs at a different block, though. `eth_call` (`chain:simulate`) runs at `{ blockHash = latest.hash }` and
`eth_estimateGas` runs at `latest.number`. A node executes both calls with `block.number = tip`, not `tip + 1`. The
part of the test that runs on anvil shows this.

Some actions only become valid at a block. Two examples are `winMatchByTimeout`, which becomes valid at the
opponent's `responderDeadline` (Dave's `Clock.deadline` is "the first inclusive instant at which a running clock has
timed out"), and `winInnerTournament`, which becomes valid at `resultAt`. These actions revert in the preflight at
`tip = first - 1`. `attempt` then marks the job rejected for that tip, and the bridge sends it at `tip = first` at
the earliest. It lands in block `first + 1`, one block late.

The honest timeout winner's window is `[responderDeadline, responderDeadline + A)`, where `A` is the winner's paused
allowance. Dave's `_classifySoleSurvivorAt` needs `remaining > overdue`, and `eliminableAt` is
`responderDeadline + allowance`. When `A = 1`, the window is `[D, D + 1)` and the bridge never sends the win. At
`tip = D` the win is no longer due, and the bridge's next transaction is its own cleanup, `eliminateMatchByTimeout`,
of the honest match. Block `D + 1`, which includes it, is the match's `eliminableAt`. The honest claim is then
eliminated, even though a transaction sent at `tip = D - 1` would have been included in block `D` and would have won.
This is the completeness failure of section 1: "The honest operator ... cannot respond in time. If the honest claim
is eliminated, a dishonest claim can win."

### Component, role and area

The PRT bridge and transaction journal in `doc/recipes`. AUDIT.md assigns them this role: "The PRT player and bridge
in `doc/recipes` ... | Support. No production deployment runs the player, the bridge or the CLI." They stand in for
the honest operator's "Submitting transactions" (section 2, honest operator's path). The area is transaction
scheduling and preflight.

### Location

- `doc/recipes/prt-transactions.lua`, `methods:submit`:
  - the window check at `tip + 1` (`if intent and (tip + 1 < intent.first or tip + 1 >= intent.last)`);
  - the preflight `self.chain:simulate(signer, to, data, value, { blockHash = block.hash, requireCanonical = true })`;
  - `eth_estimateGas` at `block.number`.
- `doc/recipes/prt-bridge.lua`:
  - `methods:jobs` sets `first = first_timeout` for `winMatchByTimeout` and `first = result_at` for
    `winInnerTournament` and `stageTournamentResult`;
  - `methods:attempt` records `self.rejected[job.key] = snapshot.tip_hash` when the preflight reverts;
  - `methods:tick` treats a job as due at `snapshot.tip + 1 >= job.first`, and schedules the wake-up at
    `job.first - 1`.
- Pinned Dave v3.0.0-alpha.7, `prt/contracts/src/tournament/libs/MatchClocks.sol` (`bisectionSchedule`,
  `_classifySoleSurvivorAt`), `libs/Clock.sol` (`deadline`, `overdueByAt`), `Time.currentTime() = block.number`.

### Evidence and test

`bugs/R3-VARSCHED-1/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R3-VARSCHED-1`. It takes about
1 s. Set `VARSCHED_PORT=<port>` if 28631 is taken. The test checks that the port is free and stops its anvil at the
end.

1. **Real node.** A private anvil runs a 13-byte contract whose call reverts while `block.number < 10`, with the tip
   at block 9. The real journal (`prt-transactions.lua`), RPC client (`prt-rpc.lua`) and signer (`prt-signer.lua`,
   with a cast keystore) submit a job with window `[10, 11)`. **Required:** a transaction is published, and block 10
   includes it with status 1. **Control** (exit 2 if it fails): at the same tip, another account sends the same call
   as a transaction, and block 10 includes it with status 1.
2. **Bridge.** The real `tick`, `attempt` and `jobs` and the real journal run over a mock chain. The mock evaluates
   `eth_call` and `eth_estimateGas` at the requested block's number (`"pending"` is `tip + 1`), the semantics that
   part 1 shows on anvil, and it includes every published nonce in the next block. Only `refresh` and `prepare` are
   stubbed. The honest claim is commitment two, and the opponent is on turn with `responderDeadline` 20.
   **Required (B):** with the one-block window `[20, 21)`, the honest `winMatchByTimeout` lands in block 20.
   Scenario A, with window `[20, 26)`, is printed for information only.

On audit/prt2 it exits 1 deterministically. The reviewer ran it twice and got exit 1 both times. It prints:

```
part 1 (anvil): gated call valid from block 10; journal submit at tip 9 for window [10, 11):
  journal returned rejected (preflight revert code 3: execution reverted), nothing sent
  control: the same call sent as a transaction at tip 9 is included in block 10 with status 1
part 2 (bridge over mock chain):
A (informational): next-block inclusion, window [20, 26):
  tip 19: winMatchByTimeout preflight reverted
  tip 20: published winMatchByTimeout at nonce 0
  honest winMatchByTimeout valid in blocks [20, 26): lands in block 21
B: next-block inclusion, one-block window [20, 21):
  tip 19: winMatchByTimeout preflight reverted
  tip 20: published eliminateMatchByTimeout at nonce 0
  honest winMatchByTimeout valid in blocks [20, 21): NEVER lands
VIOLATED: R4 (...): a job valid from the next block must be sent so that the next block includes it (part 1 journal on anvil: not sent; part 2 one-block window: never lands, informational window [20, 26): lands in 21)
run.sh: R3-VARSCHED-1: exit 1 (bug present)
```

The reviewer also tested a scratch copy of `prt-transactions.lua` whose two preflight calls run at `"pending"`. It
was placed first on `LUA_PATH`, and the audited file was not changed. With that copy the test exits 0: part 1
publishes and block 10 includes the call, and A and B both land in block 20. `doc/recipes/prt-bridge-test.lua`
still passes with it. Opus 5.5 found, proved and reviewed the issue, with no fallback.

### Trigger and reachability

An adversary holds the claim opposite the honest one and stops answering when it is on turn (section 7: "Post any
number of claims ... and abandon or defend them at will"). The honest operator then needs `winMatchByTimeout` from
block `responderDeadline` on. A window of one block needs the honest claim's paused allowance to be one block. That
state is reachable. `joinTournament` initializes the clock with `initialAllowance - (current - startInstant)`, and
joining is open until `startInstant + allowance`. An honest claim that joins in the last block of the join window,
for example after computing its claim for most of that window, therefore gets an allowance of 1. A claim also reaches
a small allowance by spending its clock on responses (`pauseAfterResponseAt` charges `elapsed - responseBudget`).
No valid template or input sequence rules out these clock values, because they depend on timing, not on the machine
state. The same one-block lateness hits `winInnerTournament` at `resultAt`, and `stageTournamentResult`.
With a wider window, the win lands one block late but in time. The resulting overdue of 1 is a deferred charge that
`pauseWinnerAt` offsets by `responseBudget`.

### Rating

1. Out of scope: no. The trigger is an adversary that abandons a match (section 7), not one of the exclusions of
   section 8. It needs no deep reorganization ("Reorganizations of the chain deeper than the operator's input
   policy"), and no deployment that violates A1 to A8. The validator nodes listed as not in scope in AUDIT.md are not
   the component. The bridge is listed in the component table.
2. Role: the bridge and journal are Support (AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support"). That
   clause covers this component. Section 3: "A defect that only a support component shows is Medium when it would
   rate High or Critical in the role the component stands in for, such as ... the honest operator for an
   implementation of an operator". The bridge implements the honest operator's "Submitting transactions" (section 2).
   Section 8, step 2: "A defect that only a support component shows is never above Medium."
3. High and Medium cases: section 8, Medium: "A defect that only a support component shows, when section 3 rates it
   Medium." This applies, because in the role the bridge stands in for the defect is Critical (step 4).
4. Critical (in the stood-in honest-operator role): R4, "The honest operator observes the chain and submits its
   transactions within the dispute clocks." It is violated at a reachable clock state on the honest operator's path
   ("Submitting transactions"), and section 1 names it a completeness failure: "cannot respond in time. If the honest
   claim is eliminated, a dishonest claim can win." Section 8, Critical: "violating any rule or obligation ...
   anywhere on the honest operator's path, is critical." Stood-in Critical makes Support Medium.

Second reading: **Low**. Under this reading, one block of submission latency is slack that the clocks absorb. The
section 1 premise "the chain includes its transactions within the dispute clocks" and A7 "Sized clocks" leave room for
the honest claim, so an honest claim with a single block left would fall outside what the deployment is sized for.
Two facts decide between the readings. The first is whether a deployment's sizing (A7) promises the honest claim more
than one block of paused allowance at every timeout opportunity, including a join in the last block of the join
window. The second is whether "within the dispute clocks" means every block the contract's window allows. The text
supports the first reading better. The window is a hard on-chain interval, the bridge itself schedules the job for
block `first`, and a correct operator lands it in that block, as the control shows. This finding is distinct from
R1-A8-4, which is about the choice between pending jobs and not about preflight block context. A fix for one does not
fix the other.

### Possible solution and risks

Run the preflight in the context of the block that the transaction targets. One option is `eth_call` and
`eth_estimateGas` at the canonical `latest` hash with a block override of `number = tip + 1` (and `time` if a
contract reads it). Another is to run them at `"pending"`. The `"pending"` variant drops `requireCanonical` and
includes the signer's own pending transaction, which the journal's comment says it means to exclude, so the override
keeps the intended state better. Block overrides are a geth/anvil extension, not standard JSON-RPC, so a node without
them needs the `"pending"` fallback or a separate check. Alternatively, on a preflight revert at `tip = first - 1`,
the bridge could publish anyway when the job's `first` is exactly `tip + 1`, accepting a possible revert at inclusion.
That costs gas and can burn the nonce on a transaction that reverts, if the window was computed wrongly. Re-run
`doc/recipes/prt-bridge-test.lua` and `bugs/R1-A8-4` with any fix.

### Risk of not fixing it

Every timeout win, inner-tournament win and staging that the bridge sends lands at least one block after it becomes
valid. When the honest claim has a single block of allowance at that point, the bridge loses a match that a correct
operator wins, and its own cleanup eliminates the honest match. Any claimant can trigger it by abandoning a match
against such a claim. No production deployment runs the bridge, but a node built on this code would inherit the
defect. A mitigation outside the code is to join early and keep clocks well above one block, which makes the window
longer than one block.
