## R2-DFINPUTCOUNT-2

**Title.** The PRT player fetches epoch 0's inputs only from the DaveConsensus deployment block, but DaveConsensus seals into epoch 0 every input the application already had, so the player crash-loops.

**Severity.** Medium

### Problem

The pinned DaveConsensus seals epoch 0 in its constructor. It computes `inputIndexUpperBound =
_nextInputIndexUpperBound(0)`, which is `min(InputBox.getNumberOfInputs(app), 2^24)`, and emits `EpochSealed(0, 0,
inputIndexUpperBound, ...)`. Every input the application received before the consensus existed therefore belongs to
epoch 0 in the on-chain input record.

`crisium.lua` sets `first_block = getDeploymentBlockNumber()` of the consensus (line 125). In `open_epochs` it opens
epoch 0's listener with `first_input_block = previous_seal and eth.small(previous_seal.log.blockNumber) or
first_block` (line 267). For epoch 0 there is no previous seal, so the listener in `prt-epoch.lua` (`poll`, line 37)
fetches InputAdded logs only from the consensus deployment block on. It never sees inputs in earlier blocks. When it
applies `EpochSealed(0, 0, n)` with `n > 0` inputs it has not seen, the assert `inputIndexUpperBound == input_begin +
#inputs` fails with "sealed input count mismatch" (`prt-epoch.lua:96`). If some inputs were in the deployment block and
some before it, it fails "input stream has a gap or duplicate" (line 73) instead. The error leaves `pass()` and the
process exits. `prt-supervise.sh` relaunches it, and it rebuilds the listener with the same `first_input_block`, so it
fails the same way on every launch. The player never computes or defends epoch 0's claim, nor any later epoch's.

In the role the player stands in for, this is a completeness failure of section 1: the honest operator "cannot respond
in time. If the honest claim is eliminated, a dishonest claim can win." It also breaks R4 directly, because the player
does not assign inputs to epochs as the referee does.

### Component, role and area

The PRT player in `doc/recipes`: `crisium.lua` (how it derives epoch 0's first input block) and `prt-epoch.lua` (the
epoch input and seal listener). AUDIT.md table: "The PRT player and bridge in `doc/recipes`, ... | Support. No
production deployment runs the player, the bridge or the CLI." It stands in for the honest operator. The DaveConsensus
constructor (referee model, deployed referee) behaves as designed and is not the defect.

### Location

- `doc/recipes/crisium.lua`: `first_block` (line 125), `open_epochs` (`first_input_block`, line 267).
- `doc/recipes/prt-epoch.lua`: `methods:poll` (`history:get_logs(address, self.first_input_block, ...)`, line 37; asserts
  at lines 73 and 95-98); `M.new` (`first_input_block = args.first_input_block or args.first_block`, line 167).
- For reference: `cartesi-rollups/contracts/src/DaveConsensus.sol` of Dave v3.0.0-alpha.7, constructor lines 141-145,
  `_nextInputIndexUpperBound` line 470 (identical in `work/dave/released` and `work/dave/patched`).

### Evidence and test

`bugs/R2-DFINPUTCOUNT-2/` contains:

- `test.sh`: the test. It starts a private anvil on a free port from 18640 (never 8545/8546) and stops it at exit. It
  deploys the pinned Dave contracts of `work/dave/patched` (Tournament, CartesiStateTransition, the parameters
  provider, MultiLevelTournamentFactory, InputBox, ApplicationFactory) with permissionless entry points only. In
  scenario A, `ApplicationFactory.newApplication` creates an application whose outputs Merkle root validator is the
  precomputed address of the deployer's next contract creation. Account 1, an untrusted input sender, then adds two
  inputs with `InputBox.addInput` in blocks 10 and 11, and the deployer creates the DaveConsensus at that address in
  block 14, which emits `EpochSealed(0, 0, 2)`. Scenario B, the control, has the same shape, except that both inputs
  are mined in the consensus's own deployment block. The test checks these premises on chain. It then runs the real
  `crisium.lua` in sentinel mode on each application with `--input-policy=0 --status-file=...`. The control must report
  epoch 0 sealed with 2 inputs, or the test exits 2. Scenario A runs twice from the same state directory, a launch and
  a relaunch as `prt-supervise.sh` would do. Each must report epoch 0 sealed with 2 inputs (exit 0). Dying on the
  listener's input-assignment checks, or sealing another count, is a violation (exit 1). Anything else exits 2. The
  300 s wait is a setup timeout, not part of the verdict.
- `make-checkpoint.lua`: stores epoch 0's checkpoint from `configs/baremetal-template` with
  `prt.store_first_epoch_checkpoint`, as `prt-demo.lua` does.
- `README.md`: the description above and the expected output.

Run with `bugs/run.sh R2-DFINPUTCOUNT-2` (about 21 s). The reviewer re-ran it on audit/prt2 and got exit 1. It prints:

```
scenario A: app 0x61c3..., consensus 0xa513... deployed at block 14; inputs 0,1 at blocks 10,11; EpochSealed(0, 0, 2)
scenario B: app 0x23dB..., consensus 0x8A79... deployed at block 18; inputs 0,1 at blocks 18,18; EpochSealed(0, 0, 2)  [control]
== control: crisium on application B (inputs in the consensus deployment block)
control result: sealed 2
== crisium on application A (inputs before the consensus deployment), launch 1 and a relaunch
launch 1: exited 1; error: lua5.4: doc/recipes/prt-epoch.lua:96: sealed input count mismatch
launch 2: exited 1; error: lua5.4: doc/recipes/prt-epoch.lua:96: sealed input count mismatch
VIOLATED: R4 'It assigns inputs to epochs exactly as the referee does': the consensus sealed inputs [0, 2) into epoch 0, but the player fetched epoch 0's InputAdded logs only from block 14 (consensus deployment) and died on every launch (2 of 2) instead of delivering them
run.sh: R2-DFINPUTCOUNT-2: exit 1 (bug present)
```

The prover reports exit 1 on 3 runs, and exit 0 with an uncommitted copy of `crisium.lua` whose epoch-0 fallback is
block 0. The test asserts what a correct player must do (seal epoch 0 with the inputs the consensus assigned), so any
correct fix makes it pass. Found, proved and reviewed on Opus 5.5; no fallback model.

### Trigger and reachability

The deployer chooses the deployment shape, and any input sender supplies the inputs. The shape is an application
created with `ApplicationFactory.newApplication` that names, as its validator, the address at which a DaveConsensus
will be created later (CREATE or CREATE2 address precomputation), with the consensus created in a later block. Between
the two blocks, anyone may add inputs: `InputBox.addInput` only requires that the application has code and is not
foreclosed. The DaveConsensus constructor accepts any `appContract` and deliberately counts all of its pending inputs
into epoch 0. All entry points are public and documented, and the resulting on-chain input record meets A3.

It is not reachable through `DaveAppFactory.newDaveApp`, which creates the application and its consensus in one
transaction. `prt-deploy.lua` uses that path, so the recipe demo does not show the defect. Inputs cannot be sent ahead
to a predicted application address, because `InputBox.addInput` reverts with `ApplicationNotDeployed` while the address
has no code. `Application.migrateToOutputsMerkleRootValidator` is restricted to the application's deployment block
(`onDeploymentBlock`), so migrating to a consensus created in that block cannot trigger it either: the inputs are then
in the consensus deployment block, which the listener fetches (scenario B).

### Rating

1. Out of scope: no. The trigger is a deployment of the pinned referee through public factory and InputBox entry
   points, plus inputs from untrusted senders (section 7: "Send any number of inputs the deployment accepts"). It does
   not "need the deployment to violate one of A1 to A8": A3 holds, since the input record assigns 2 inputs to epoch 0,
   within the limit. No other exclusion (outputs or yields, snapshots, O1 or O2, reorganizations, host faults) is
   involved.
2. Role: the PRT player in `doc/recipes`, Support by AUDIT.md ("Support. No production deployment runs the player").
   Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical in the role
   the component stands in for, such as ... the honest operator for an implementation of an operator". The player is
   an implementation of an operator, so this clause covers it, and the defect is never above Medium.
3. High and Medium cases: section 8, Medium, "A defect that only a support component shows, when section 3 rates it
   Medium." No High case fits in the stand-in role: the crash is caused by the on-chain input record, which the honest
   operator must process, not by data it "may decline".
4. Critical in the stand-in role: R4, "The honest operator defends every epoch whose dispute is open ... It assigns
   inputs to epochs exactly as the referee does, including the input limit per epoch (A3)", and "After a stop, it
   restarts from a directory that O2 guarantees and keeps defending its claim". Section 8, Critical: "violating any rule
   or obligation at a reachable state, or anywhere on the honest operator's path, is critical", and "A crash, hang,
   out-of-bounds read, or unbounded allocation caused by data from other parties that the honest operator must
   process." Capped by step 2: **Medium**.

Second reading: Low, if an application created separately from, and before, its DaveConsensus is not a deployment the
player has to support. The fact that decides is whether the recipes or the manual restrict the player to
`DaveAppFactory` deployments. Neither does: `crisium.lua` says "From its application's address it discovers the
consensus", and the pinned DaveConsensus constructor takes any application and handles its pending inputs. The
threat model defines a deployment as "A referee with its verifiers and dispute constants, the on-chain input record it
reads, and the validator nodes", with no restriction on how the application was created. Medium is the better
supported reading.

Related to R1-A3-1 (the previous-seal branch of the same `first_input_block` expression, for later epochs and backlogs
past the 2^24 cap). This one is the `first_block` branch for epoch 0, with another trigger, and it needs its own fix.

### Possible solution and risks

For epoch 0, start the input fetch at the block where the application could first receive inputs, the application's
`getDeploymentBlockNumber()` (an `IApplication` function in cartesi-rollups-contracts 3.0.0-alpha.10). InputBox rejects
inputs to an address without code, so no input of the application is older. Keep `first_block` (the consensus
deployment) for the consensus and tournament logs. A fetch from block 0 also makes the test pass, but it scans the
whole chain, which R12 forbids ("must not grow ... with chain activity that does not belong to the application").
Risk: a wider first fetch for epoch 0, bounded by the application's lifetime before its consensus. An application
whose `getOutputsMerkleRootValidator` is not an `Application` from this factory needs a fallback, such as InputBox's
own deployment block.

### Risk of not fixing it

A deployment that uses the player and creates its application before its DaveConsensus, in a different block, is
exposed to any party who adds an input in between. The player then crash-loops on epoch 0 and never defends a claim,
so a dishonest claim can win epoch 0 by timeout. Mitigation outside the code: deploy through
`DaveAppFactory.newDaveApp`, or create the consensus in the application's deployment block. No production deployment
runs the player, but a node that copies its epoch-0 logic inherits the failure.
