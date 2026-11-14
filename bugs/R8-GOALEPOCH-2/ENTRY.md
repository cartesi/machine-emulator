## R8-GOALEPOCH-2

**Title.** The deployed referee (`DaveConsensus` with `Application`) never registers the valid template's outputs Merkle root, so it refuses valid proofs of the outputs a non-genesis template commits to until epoch 0 is accepted.

**Severity.** Critical (preferred reading: A5 makes the valid template a settled state whose outputs are accepted "whenever"). Low under the alternative reading, in which "settled state" means only the last leaf of a winning claim (see Rating).

### Problem

`DaveConsensus` writes `_outputsMerkleRoots` in one place only, `acceptStagedTournamentResult`. Its constructor seals
epoch 0 from `initialMachineStateHash`, which is the template hash T, and emits
`EpochSealed(0, 0, upper, initialMachineStateHash, bytes32(0), tournament)`. It never registers the outputs Merkle root
R that the template's tx buffer holds. So `isOutputsMerkleRootValid(app, R)` is false, and `Application.validateOutput`,
`validateOutputHash` and `executeOutput` revert with `InvalidOutputsMerkleRoot(R)` for every output the template commits
to. The refusal lasts from deployment until `acceptStagedTournamentResult(0)`, which comes after epoch 0's whole
tournament and its claim staging period. Meanwhile `Application._getLastFinalizedMachineMerkleRoot` falls back to
`TEMPLATE_HASH`, so the same contract set treats the template as the finalized state.

If epoch 0 accepts inputs that emit outputs, the root of epoch 0's final state differs from R, and R is never
registered. Valid proofs against R are then refused for good. A correctly designed application re-commits the template's
outputs in every later root ("That includes the outputs its template already commits to"), so the same outputs can be
accepted with a new proof against a later root. That path was not tested.

The goal of section 1 forbids settling a wrong state or accepting an output that the settled state does not commit to.
This defect breaks neither. It violates the completeness clause of A5: "the referee accepts every output that the
settled state commits to, whenever its valid proof is presented. No party can make it stop accepting them." A5 says that
a valid template is a settled state. The effect is that outputs carried over by a non-genesis template, such as
withdrawals migrated from an earlier application, cannot be validated or executed during epoch 0.

The manual's referee model behaves the same way. `wait_for_outputs` in `doc/recipes/prt.lua` (shown in
`doc/README.md`) extracts outputs only from `winner.final_state_hash`. The manual and Dave agree, so under section 3
the manual's model is the defect: "unless the manual's model itself violates one of A1 to A8; then the manual is the
defect, rated as a defect of the referee model". The class is the same either way.

### Component, role and area

Dave v3.0.0-alpha.7 `cartesi-rollups/contracts` `DaveConsensus` (output validation side), with
`cartesi-rollups-contracts` 3.0.0-alpha.10 `Application` (output validation). AUDIT.md role: "Dave [v3.0.0-alpha.7]
(`prt/contracts`, `cartesi-rollups/contracts`, with `machine/step` replaced by the regenerated step), and the
`cartesi-rollups-contracts` 3.0.0-alpha.10 it pins (input box, output validation) | Referee model, as the deployed
referee. Audit the released constants". The clause names output validation, so it covers this component. The audited
build is `bugs/harness/work/dave/released` (Dave commit 7eb6c6b; only `machine/step` is replaced).

The manual's own model in `doc/recipes/prt.lua` (`wait_for_outputs`, `run_referee`) shows the same behavior. Its role is
"The PRT referee model in `doc/recipes` | Referee model".

### Location

- `bugs/harness/work/dave/released/cartesi-rollups/contracts/src/DaveConsensus.sol`:
  - constructor (l.116-146), with `emit EpochSealed(0, 0, ..., bytes32(0), tournament)` at l.145 and no registration of R;
  - `stageTournamentResult` (l.167), where `_validateMachine` (l.184, 462) derives an outputs root from a machine
    validity proof;
  - `acceptStagedTournamentResult` (l.246), with the only write `_outputsMerkleRoots[outputsMerkleRoot] = true` at l.272;
  - `isOutputsMerkleRootValid` (l.398-406).
- `.../dependencies/cartesi-rollups-contracts-3.0.0-alpha.10/src/dapp/Application.sol`:
  - `validateOutputHash` (l.337-350), which reverts `InvalidOutputsMerkleRoot` at l.349;
  - `executeOutput` (l.163);
  - `_getLastFinalizedMachineMerkleRoot` (l.600-611), which falls back to `TEMPLATE_HASH`.
- `doc/recipes/prt.lua`: `wait_for_outputs` (l.774-802), called only with `winner.final_state_hash` (l.823).

### Evidence and test

`bugs/R8-GOALEPOCH-2/` contains:

- `test.lua`: the emulator part, fixture generation and verdict.
- `GenesisOutputs.t.sol`: the forge tests.
- `dave.sh`: copies the released Dave build to a temp dir, adds the test and the generated fixture, and runs
  `forge test --offline`. It has an optional `SIMULATE_FIX=1` self-check.
- `README.md`: describes the test.

Run it with `bugs/run.sh R8-GOALEPOCH-2` (about 30 s once the released Dave build exists; no chain is started).
`test.lua` builds a real valid template with the emulator's Lua API. It uses the harness bare-metal `emit-output`
guest, which accepts at genesis with the empty outputs root, delivers one advance input that the guest emits as
output 0, and lets the guest accept with root R. The machine is reproducible, uses keccak256, sits at an mcycle boundary
with a reset uarch and an accepted manual yield, and holds R in its tx buffer. The test checks R against a host
outputs frontier, and takes T (the root hash) and the machine validity proof of T (the `iflags_Y`, `htif_tohost` and
tx-buffer words with their 59 siblings). It writes them, with output 0 and its proof, into a Solidity fixture.

The forge tests deploy with `DaveAppFactory.newDaveApp(T, 50, no sentries, zero withdrawal config)`, using the
tournament parameters of Dave's own `DaveAppFactory.t.sol`. Two controls must pass or the test exits 2:

- `testControlFixtureConsistent`: the output proof folds to R and the tx-buffer word is R.
- `testControlAcceptedOnceEpoch0Accepted`: epoch 0 has no inputs, so its honest final state is T. The test joins with T,
  finishes the tournament, and calls `stageTournamentResult(0, <machine validity proof of T>)`. The referee itself derives
  R from T. After the staging period it accepts, `validateOutput` accepts the proof, and a tampered output is refused.

Two requirement tests assert A5:

- `testTemplateOutputAcceptedAtDeployment`: `validateOutput(output 0, proof)` right after deployment must not revert.
- `testTemplateOutputAcceptedThroughoutEpoch0`: the proof must be accepted at five checkpoints before
  `acceptStagedTournamentResult(0)` (deployment, after the join, tournament finished, result staged, last block of the
  staging period).

On audit/prt2 it prints the following and exits 1 (ran twice by the reviewer, exit 1 both times; `SIMULATE_FIX=1`, which
registers R in the constructor of the temp copy, exits 0):

```
valid template: emit-output guest after one accepted input, mcycle 8589303
  template hash T          0xed4ccd4dc89cc5c7f5c5fb87d4a8978a8aba283823e117920cc463815e86735d
  outputs Merkle root R    0x5d8e4184de33c046791cf34401016c2fd69c7415f2241273f35994af034b1d8d (tx buffer; 1 output, 356 bytes)
controls: fixture consistent; once epoch 0 (no inputs) is accepted on T, stageTournamentResult derived R from T ...
  forge: [PASS] testControlAcceptedOnceEpoch0Accepted() (gas: 5191505)
  forge: [PASS] testControlFixtureConsistent() (gas: 18332)
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
VIOLATED: A5: the referee accepts every output the settled state (the valid template) commits to, whenever its valid proof is presented
run.sh: R8-GOALEPOCH-2: exit 1 (bug present)
```

The 224 blocks come from the test's parameters (the tournament's root allowance at one-minute blocks plus a staging
period of 50 blocks). The test does not use guardian foreclosure, because the guardian is a trusted deployment role. It
shows the refusal at the deployment's initial state and how long it lasts.

Limitations of the test: it exits 0 only for a fix that keeps the `newDaveApp` signature and accepts the proof without an
extra call. A fix that adds a permissionless registration call still exits 1 until the test makes that call. A fix that
changes the `newDaveApp` signature makes the test exit 2 (compile error). The test needs the released Dave build
(`bugs/harness/chain/build-dave.sh released`), forge, and `emit-output.bin` (`bugs/harness/baremetal/build.sh`).

Found by the GOALEPOCH and GOALOUTPUT hunters, proved by the prover, and reviewed on Opus 5.5 (`claude-opus-5-5`), with
no fallback.

### Trigger and reachability

No adversary is needed. It is enough that an application is deployed from a valid template whose tx buffer commits to
outputs, and that anyone presents a valid output proof against R before `acceptStagedTournamentResult(0)`.

Section 2 allows such templates: "Its tx buffer holds the outputs Merkle root of every output that the application
accepted before it, which at genesis is the root of the empty outputs tree." The manual documents how to make them
("For a non-genesis template, use `--assert-rolling-template=outputs_merkle_root:<filename>`", doc/README.md, "Rolling
Cartesi Machine templates"). `DaveAppFactory.newDaveApp` and `DaveConsensus` accept any template hash. The test builds
the state with documented operations only: creation from a configuration, running, and one input delivery. For a
genesis template R is the empty-tree root, which commits to no output, so nothing is lost. The state is the
deployment's initial state, so it is reachable by definition.

### Rating

1. Out of scope: no. The trigger needs no deliberate API state change, no untrusted API caller and no snapshot outside
   the valid-template conditions. The template is valid and its guest follows the rollup interface, so "An application
   that is not correctly designed" does not apply. The exclusion "Defects that need the deployment to violate one of A1
   to A8, unless the emulator's own behavior is what makes the obligation fail ... or unless an implementation of the
   referee model is what violates it (section 3)" does not exclude it: an implementation of the referee model (Dave, and
   the manual's model) is what violates A5. The foreclosure variant (permanent refusal) would need the guardian, a
   trusted deployment role, and is not relied on.
2. Role: Referee model, as the deployed referee (AUDIT.md component table, quoted under "Component, role and area"). That
   clause names Dave's `cartesi-rollups/contracts` and the pinned output validation, so it covers `DaveConsensus` and
   `Application`. Section 3: "A defect in what it accepts or derives is rated as if a deployed referee had it." Which
   output proofs it accepts is what it accepts. The clause "A defect that only changes how long a claim may take to
   respond ... is rated as support" is about claim response times, not about which outputs are accepted, and does not
   apply.
3. High and Medium cases: none fits. It is not a verifier misbehaving on unreachable before-states, not trailing data,
   not shown only by a support component, and not a hash-integrity or persistence case.
4. Critical: A5, "An outputs Merkle root is defined only for a settled canonical state that waits at a manual yield with
   the accepted reason. A valid template is such a state." and "Conversely, the referee accepts every output that the
   settled state commits to, whenever its valid proof is presented. No party can make it stop accepting them." The
   violation is at the deployment's initial state, which is reachable. Section 8: "violating any rule or obligation at a
   reachable state ... is critical."

Two readings give different classes.

- **Reading A, preferred: Critical.** "A valid template is such a state" refers to "a settled canonical state that waits
  at a manual yield with the accepted reason". The sentence therefore calls the valid template a settled state. If
  settled meant only "the last leaf of a winning claim", that sentence would add nothing, because the last leaf of a
  winning claim already qualifies. Other text agrees. A1 names "the canonical hash that the epoch starts from, as
  settled on-chain". The manual (doc/README.md, `vg.lua` referee) says "The state an epoch starts from is settled. It is
  either the stored template hash at genesis or the settled state hash of the previous epoch." And the deployed
  contracts themselves treat the template as the finalized state (`_getLastFinalizedMachineMerkleRoot` falls back to
  `TEMPLATE_HASH`). With the template settled from deployment, "whenever" leaves no window in which its outputs may be
  refused.
- **Reading B: Low.** "The settled state is the last leaf of the winning claim, authenticated as in A2" defines the only
  state the "Conversely" sentence covers, and "A valid template is such a state" only says that a template's root is
  defined (for example when epoch 0 has no inputs and the winning claim's last leaf is the template). A
  correctly designed application re-commits the template's outputs in every later root, so they become acceptable once
  epoch 0 settles. Under this reading no rule is violated: the effect is a delay, and the goal holds. It would also be
  Low if PRT deployments were taken to start only from genesis templates. The campaign's rating of R2-DFOUTPUT-1 took
  the other view, that non-genesis templates are valid, and section 2 supports it.

The deciding facts are whether the threat model means the valid template to be a settled state whose outputs the referee
must accept before any tournament settles (the text of A5, A1 and the manual favor yes), and whether a refusal for
epoch 0's duration, or for good when epoch 0 changes the outputs root, counts as the referee making it "stop
accepting" them.

### Possible solution and risks

Register the template's outputs root without trusting anyone, in one of these ways:

- Have the constructor or `DaveAppFactory.newDaveApp` take a `MachineValidityProof` of the template. It would run
  `_validateMachine(initialMachineStateHash, proof)`, set `_outputsMerkleRoots[root] = true`, and report the root in
  `EpochSealed(0, ...)`.
- Add a permissionless `proveTemplateOutputsMerkleRoot(MachineValidityProof)` that does the same once against the stored
  template hash.

The proof must be checked against T and never taken as a bare root, or the fix breaks A5's soundness side. A required
constructor proof changes the factory interface and deployment tooling, and a genesis deployment has to supply a proof
of the empty root. The manual's referee model (`wait_for_outputs`) and its text need the same change, or the manual
should state explicitly that template outputs are accepted only after epoch 0 settles, which would also settle the
reading.

### Risk of not fixing it

An application deployed from a non-genesis template cannot validate or execute the outputs its template carries over for
at least epoch 0's tournament plus the claim staging period. If epoch 0 changes the outputs root, proofs against the
template's own root are never accepted, and those outputs need new proofs against a later root. A guardian foreclosure
before epoch 0 is accepted would make them unexecutable, but the guardian is trusted. No adversary is needed and no funds
are mis-sent. The exposure is a delay in executing carried-over outputs. Outside the code, deployers can use genesis
templates, or wait for epoch 0 to settle (ideally with no inputs) before relying on carried-over outputs.
