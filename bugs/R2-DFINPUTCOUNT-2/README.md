# R2-DFINPUTCOUNT-2: PRT player misses epoch 0's inputs added before the DaveConsensus deployment

## What is asserted

The pinned DaveConsensus seals epoch 0 in its constructor as `[0, _nextInputIndexUpperBound(0))`, so every input
the application received before the consensus existed belongs to epoch 0. `doc/recipes/crisium.lua` opens epoch
0's listener with `first_input_block = previous_seal and ... or first_block`, where `first_block` is
`getDeploymentBlockNumber()` of the consensus. `doc/recipes/prt-epoch.lua` therefore fetches InputAdded logs only
from the consensus deployment block. When it applies `EpochSealed(0, 0, 2)` it raises
`prt-epoch.lua:96: sealed input count mismatch`, and every relaunch fails the same way.

`test.sh` runs everything end to end on a private anvil (a free port from 18640, never 8545/8546), using the
pinned Dave build `work/dave/patched` (the recipe build; the DaveConsensus constructor is the same in the released
build). It uses only permissionless, documented entry points:

- It deploys Tournament, CartesiStateTransition, the parameters provider, MultiLevelTournamentFactory, InputBox and
  ApplicationFactory.
- **Scenario A (defect):** `ApplicationFactory.newApplication` creates an application whose outputs Merkle root
  validator is the precomputed address of the deployer's next contract creation. Account 1, an untrusted input
  sender, then adds two inputs through `InputBox.addInput` in blocks 10 and 11. The deployer creates the
  DaveConsensus at that address in block 14, which emits `EpochSealed(0, 0, 2)`.
- **Scenario B (control):** the same shape, but both inputs are mined in the consensus's own deployment block.

The test checks these premises on chain: the application names the consensus, the consensus names the
application, epoch 0 is sealed with upper bound 2, and the inputs sit in the expected blocks. It then runs the real
`crisium.lua` in sentinel mode (honest claims, no keystore) on each application, from an epoch-0 checkpoint built
from the harness bare-metal rolling template (`configs/baremetal-template`). The checkpoint is made by
`make-checkpoint.lua`, the same way `prt-demo.lua` makes one. crisium runs with `--input-policy=0` and
`--status-file`.

- The control must reach status `epochs["0"] = {sealed = true, inputs = 2}`. Otherwise the test exits 2.
- Scenario A runs twice: a launch, then a relaunch from the same state directory, as `prt-supervise.sh` would do.
  Each launch must reach epoch 0 sealed with the 2 inputs the consensus assigned to it (exit 0). A launch that dies
  on the listener's input-assignment check (`sealed input count mismatch` or `input stream has a gap or
  duplicate`), or that seals epoch 0 with another input count, counts as a violation (exit 1). Any other outcome
  exits 2.

The verdict uses no wall-clock thresholds. The 300 s wait per crisium run is only a setup timeout.

As a sanity check, a copy of `crisium.lua` whose epoch-0 fallback is block 0 instead of `first_block` made the
same test exit 0. That run used `RECIPES_DIR` pointed at the copy and was not committed.

## Requirement

THREAT_MODEL.md R4: "The honest operator defends every epoch whose dispute is open, including while it processes
the inputs of later epochs. It assigns inputs to epochs exactly as the referee does, including the input limit per
epoch (A3)." Section 8, Critical: "A crash, hang, out-of-bounds read, or unbounded allocation caused by data from
other parties that the honest operator must process." Component: the PRT player in `doc/recipes` (crisium.lua,
prt-epoch.lua), which is Support (AUDIT.md) and stands in for the honest operator.

Whether this deployment shape counts as supported is for the reviewer to decide. In this shape the application is
created by ApplicationFactory, and its DaveConsensus is created later, at a precomputed address.
`DaveAppFactory.newDaveApp` creates both in one transaction and cannot reach this state.

## How to run

```sh
bugs/run.sh R2-DFINPUTCOUNT-2
```

It takes about 20 s. It needs `work/dave/patched` (or set `DAVE_DIR`), `configs/baremetal-template`, anvil, cast
and jq. It starts and stops its own anvil, and it removes its temporary directory.

## Expected output on audit/prt2

```
scenario A: app 0x61c3..., consensus 0xa513... deployed at block 14; inputs 0,1 at blocks 10,11; EpochSealed(0, 0, 2)
scenario B: app 0x23dB..., consensus 0x8A79... deployed at block 18; inputs 0,1 at blocks 18,18; EpochSealed(0, 0, 2)  [control]
== control: crisium on application B (inputs in the consensus deployment block)
control result: sealed 2
== crisium on application A (inputs before the consensus deployment), launch 1 and a relaunch
launch 1: exited 1; error: lua5.4: doc/recipes/prt-epoch.lua:96: sealed input count mismatch
launch 2: exited 1; error: lua5.4: doc/recipes/prt-epoch.lua:96: sealed input count mismatch
VIOLATED: R4 'It assigns inputs to epochs exactly as the referee does': ...
run.sh: R2-DFINPUTCOUNT-2: exit 1 (bug present)
```
