# R8-GOALEPOCH-2: the deployed referee refuses outputs the valid template commits to until epoch 0 is accepted

Component: Dave v3.0.0-alpha.7 `cartesi-rollups/contracts` `DaveConsensus` (constructor, `isOutputsMerkleRootValid`,
`acceptStagedTournamentResult`), with `cartesi-rollups-contracts` 3.0.0-alpha.10 `Application.validateOutput`
(released build of the shared harness, `bugs/harness/work/dave/released`). Role: Referee model, as the deployed referee.

`DaveConsensus` writes `_outputsMerkleRoots` only in `acceptStagedTournamentResult`. The constructor seals epoch 0 from
the template hash and emits `EpochSealed(0, ..., bytes32(0), ...)`, but it never registers the template's outputs
Merkle root. So `isOutputsMerkleRootValid` is false for that root, and `Application.validateOutput` /
`executeOutput` revert with `InvalidOutputsMerkleRoot` for every output the template commits to. Meanwhile
`Application._getLastFinalizedMachineMerkleRoot` falls back to the template hash, which treats the template as the
finalized state.

## Requirement

THREAT_MODEL.md section 2, "Valid template": "Its tx buffer holds the outputs Merkle root of every output that the
application accepted before it, which at genesis is the root of the empty outputs tree."

A5: "An outputs Merkle root is defined only for a settled canonical state that waits at a manual yield with the
accepted reason. A valid template is such a state." and "Conversely, the referee accepts every output that the
settled state commits to, whenever its valid proof is presented. No party can make it stop accepting them."

## What the test does

1. **Emulator (Lua API).** It creates a machine from a configuration, using the harness's bare-metal `emit-output`
   guest, and runs it to its genesis accept, which holds the empty outputs root. It then delivers one advance input,
   which the guest emits as output 0 before it accepts with the updated root R. The result is a valid template:
   - a reproducible machine with keccak256 hashes;
   - at an mcycle boundary, with the uarch reset;
   - waiting at an accepted manual yield;
   - with R in its tx buffer.

   The test checks R against a host outputs frontier and computes the proof of output 0 against R. From the machine
   it takes the template hash T (root hash) and the machine validity proof of T: the `iflags_Y`, `htif_tohost` and
   tx-buffer words with their 59 siblings. It writes all of these into a generated Solidity fixture in a temp file.
2. **Dave (forge).** `dave.sh` copies the released build to a temp dir, adds `GenesisOutputs.t.sol` and the fixture,
   and runs `forge test`. Each test deploys with `DaveAppFactory.newDaveApp(T, 50, no sentries, zero withdrawal
   config)` and the same tournament parameters as Dave's own `DaveAppFactory.t.sol`.
   - Controls, which must pass or the test exits 2:
     - `testControlFixtureConsistent`: the output proof folds to R, and the tx-buffer word is R.
     - `testControlAcceptedOnceEpoch0Accepted`: epoch 0 has no inputs, so its honest final state is T. The test
       joins with T, lets the tournament finish, and calls `stageTournamentResult(0, <emulator's machine validity
       proof of T>)`. The referee itself derives R from T, and that is the staged root. After the staging period it
       accepts. `validateOutput(output 0, proof)` then passes, and a tampered output is refused.
   - Requirement, A5:
     - `testTemplateOutputAcceptedAtDeployment`: `validateOutput(output 0, proof)` right after deployment must not
       revert.
     - `testTemplateOutputAcceptedThroughoutEpoch0`: the proof must be accepted at five checkpoints before
       `acceptStagedTournamentResult(0)`: at deployment, after the honest join, once the tournament is finished,
       once the result is staged, and on the last block of the staging period.

Exit status: 1 if a requirement test fails while the controls pass, 0 if both requirement tests pass, 2 on setup
errors. Those cover a missing build, a failed compile, a failed control, and a fix that changes the `newDaveApp`
signature, which would break this test's compile. The test does not use guardian foreclosure, because the guardian is
a trusted deployment role. It shows only the refusal at the deployment's initial settled state and how long the
refusal lasts.

## Run

```sh
bugs/run.sh R8-GOALEPOCH-2                  # about 20 s once the released Dave build exists
SIMULATE_FIX=1 bugs/run.sh R8-GOALEPOCH-2   # self-check: registers R in the constructor of the temp copy -> exit 0
```

Needs `bugs/harness/work/dave/released` (`bugs/harness/chain/build-dave.sh released`), forge, and the bare-metal
`emit-output.bin` (`bugs/harness/baremetal/build.sh`). No chain is started.

## Expected output on audit/prt2

```
valid template: emit-output guest after one accepted input, mcycle 8589303
  template hash T          0xed4ccd4dc89cc5c7f5c5fb87d4a8978a8aba283823e117920cc463815e86735d
  outputs Merkle root R    0x5d8e4184de33c046791cf34401016c2fd69c7415f2241273f35994af034b1d8d (tx buffer; 1 output, 356 bytes)
controls: fixture consistent; once epoch 0 (no inputs) is accepted on T, stageTournamentResult derived R from T ...
  forge: [PASS] testControlAcceptedOnceEpoch0Accepted() ...
  forge: [PASS] testControlFixtureConsistent() ...
  forge: [FAIL: A5: valid proof of a template output refused at deployment] testTemplateOutputAcceptedAtDeployment() ...
  forge:   isOutputsMerkleRootValid(template root) at deployment: false
  forge:   validateOutput(template output 0) at deployment: REFUSED
  forge: [FAIL: A5: valid proof of a template output refused while epoch 0 is pending: 5 != 0] testTemplateOutputAcceptedThroughoutEpoch0() ...
  forge:   checkpoints (of 5) before epoch 0 is accepted at which the proof is refused: 5
  forge:   blocks from deployment to the last checkpoint: 224
  forge:   after acceptStagedTournamentResult(0): accepted
Dave: validateOutput(template output 0, valid proof) right after newDaveApp(T): REFUSED (InvalidOutputsMerkleRoot(R))
Dave: accepted at every epoch-0 checkpoint before acceptStagedTournamentResult(0): NO
VIOLATION (A5): the referee refuses a valid proof of an output the valid template commits to until epoch 0 is accepted
VIOLATED: A5: ...
run.sh: R8-GOALEPOCH-2: exit 1 (bug present)
```

The 224 blocks come from the test's parameters: the root allowance of the canonical provider at one-minute blocks,
plus a staging period of 50 blocks. In a deployment the refusal lasts at least epoch 0's tournament plus its claim
staging period.

Files:
- `test.lua`: emulator part, fixture generation, verdict.
- `GenesisOutputs.t.sol`: forge tests.
- `dave.sh`: temp copy of the released build and the forge run, with the optional `SIMULATE_FIX` self-check.
