## R8-GOALEPOCH-2

**Title.** The deployed referee (DaveConsensus with Application) never registers the valid template's outputs Merkle
root, so it refuses valid proofs of the outputs a non-genesis template commits to until epoch 0 is accepted.

**Severity.** Critical under the literal reading of A5, which the reviewer prefers. Low under the alternative reading
(see Rating).

### Problem

`DaveConsensus` writes `_outputsMerkleRoots` in one place only, `acceptStagedTournamentResult`. The constructor seals
epoch 0 from `initialMachineStateHash`, which is the template hash T. It emits
`EpochSealed(0, 0, upper, initialMachineStateHash, bytes32(0), tournament)`, but it never registers the outputs
Merkle root R that the template's tx buffer holds. So `isOutputsMerkleRootValid(app, R)` is false, and
`Application.validateOutput` / `validateOutputHash` / `executeOutput` revert with `InvalidOutputsMerkleRoot(R)` for
every output the template commits to. This lasts from deployment until `acceptStagedTournamentResult(0)`, which is at
least epoch 0's whole tournament plus its claim staging period. Meanwhile `Application._getLastFinalizedMachineMerkleRoot`
falls back to `TEMPLATE_HASH`, so it treats the template as the finalized state.

If epoch 0 contains an accepted input, R is never registered at all. The proofs of the template's outputs against R
are then refused forever. A correctly designed application still re-commits those outputs in every later root, so
they can be accepted with a new proof against the epoch-0 root (not tested).

The goal of section 1 forbids settling a wrong state or accepting an output that the settled state does not commit
to. This defect breaks neither. It still violates A5's completeness clause: "Conversely, the referee accepts every
output that the settled state commits to, whenever its valid proof is presented". A5 makes the template such a
settled state ("A valid template is such a state"). The effect is a delay: outputs carried over by a non-genesis
template, such as withdrawals migrated from an earlier application, cannot be executed during epoch 0.

The manual's own referee model has the same behavior. Its `wait_for_outputs` in `doc/recipes/prt.lua` (shown in
`doc/README.md`) extracts outputs only from `winner.final_state_hash`. Dave and the manual therefore agree. Under
section 3, the defect is then the manual's model violating A5, rated as a defect of the referee model.

### Component, role and area

The component is Dave v3.0.0-alpha.7 `cartesi-rollups/contracts` `DaveConsensus` (output validation side), with
`cartesi-rollups-contracts` 3.0.0-alpha.10 `Application` (output validation).

The AUDIT.md table gives its role as "Referee model, as the deployed referee". The shared harness build
`bugs/harness/work/dave/released` is at commit 7eb6c6be, and only `machine/step` is changed in it. Its `DaveConsensus`
is the released source.

The manual's referee model in `doc/recipes/prt.lua` (`wait_for_outputs`, `run_referee`) shows the same behavior. Its
role is "Referee model".

### Location

- `bugs/harness/work/dave/released/cartesi-rollups/contracts/src/DaveConsensus.sol`:
  - constructor (l.116-146), which emits `EpochSealed(..., bytes32(0), ...)` at l.145 without registering R;
  - `stageTournamentResult` (l.167), the only place where `_validateMachine` derives an outputs root;
  - `acceptStagedTournamentResult` (l.246), with the only write `_outputsMerkleRoots[outputsMerkleRoot] = true` at
    l.272;
  - `isOutputsMerkleRootValid` (l.398-406).
- `.../dependencies/cartesi-rollups-contracts-3.0.0-alpha.10/src/dapp/Application.sol`:
  - `validateOutputHash` (l.337-350), which reverts `InvalidOutputsMerkleRoot`;
  - `executeOutput` (l.163);
  - `_getLastFinalizedMachineMerkleRoot` (l.600-611), which falls back to `TEMPLATE_HASH`.
- `doc/recipes/prt.lua`: `wait_for_outputs` (l.774-802), called only with `winner.final_state_hash` (l.823).

### Evidence and test

`bugs/R8-GOALEPOCH-2/` contains these files:

- `test.lua`: the emulator part, fixture generation and the verdict.
- `GenesisOutputs.t.sol`: the forge tests.
- `dave.sh`: copies the released Dave build to a temp dir, adds the test and the generated fixture, and runs
  `forge test --offline`. It also has an optional `SIMULATE_FIX=1` self-check.
- `README.md`: describes the test.

`test.lua` builds a real valid template with the emulator's Lua API:

- It uses the harness bare-metal `emit-output` guest, which accepts at genesis with the empty outputs root.
- It delivers one advance input, which the guest emits as output 0. The guest then accepts with root R.
- The machine is reproducible and uses keccak256. It is at an mcycle boundary with a reset uarch, at an accepted
  manual yield, and holds R in its tx buffer.
- The test checks R against a host outputs frontier. It then writes a Solidity fixture with T, R, output 0 and its
  proof, and the machine validity proof of T (the `iflags_Y`, `htif_tohost` and tx-buffer words).

The forge tests deploy with `DaveAppFactory.newDaveApp(T, 50, no sentries, zero withdrawal config)`. They use the
tournament parameters of Dave's own `DaveAppFactory.t.sol`. These controls must pass, or the test exits 2:

- `testControlFixtureConsistent`: the output proof folds to R.
- `testControlAcceptedOnceEpoch0Accepted`: the honest claim T joins and the tournament finishes.
  `stageTournamentResult(0, <machine validity proof of T>)` derives R from T itself. After the staging period,
  `validateOutput` accepts the same proof and refuses a tampered output.

These requirement tests assert A5:

- `testTemplateOutputAcceptedAtDeployment`: the proof must be accepted right after deployment.
- `testTemplateOutputAcceptedThroughoutEpoch0`: the proof must be accepted at five checkpoints before epoch 0 is
  accepted.

To run it:

```sh
bugs/run.sh R8-GOALEPOCH-2                  # ~30 s once the released Dave build exists; exit 1 on audit/prt2
SIMULATE_FIX=1 bugs/run.sh R8-GOALEPOCH-2   # registers R in the constructor of the temp copy; exit 0
```

On audit/prt2 the test prints the following (excerpt; the full output also has the control summary line and a
"VIOLATION (A5)" line). The reviewer re-ran it twice, with exit 1 both times, and `SIMULATE_FIX=1` exits 0. No chain
is started; forge runs in a throw-away copy of `bugs/harness/work/dave/released`.

```
valid template: emit-output guest after one accepted input, mcycle 8589303
  template hash T          0xed4ccd4dc89cc5c7f5c5fb87d4a8978a8aba283823e117920cc463815e86735d
  outputs Merkle root R    0x5d8e4184de33c046791cf34401016c2fd69c7415f2241273f35994af034b1d8d (tx buffer; 1 output, 356 bytes)
  forge: [PASS] testControlAcceptedOnceEpoch0Accepted() ...
  forge: [PASS] testControlFixtureConsistent() ...
  forge: [FAIL: A5: valid proof of a template output refused at deployment] testTemplateOutputAcceptedAtDeployment() ...
  forge:   isOutputsMerkleRootValid(template root) at deployment: false
  forge: [FAIL: A5: valid proof of a template output refused while epoch 0 is pending: 5 != 0] testTemplateOutputAcceptedThroughoutEpoch0() ...
  forge:   checkpoints (of 5) before epoch 0 is accepted at which the proof is refused: 5
  forge:   blocks from deployment to the last checkpoint: 224
  forge:   after acceptStagedTournamentResult(0): accepted
Dave: validateOutput(template output 0, valid proof) right after newDaveApp(T): REFUSED (InvalidOutputsMerkleRoot(R))
VIOLATED: A5: the referee accepts every output the settled state (the valid template) commits to, whenever its valid proof is presented
run.sh: R8-GOALEPOCH-2: exit 1 (bug present)
```

The test has one limitation. It exits 0 only for a fix that keeps the `newDaveApp` signature and accepts the proof
without an extra call. A fix that adds a permissionless registration call would still exit 1 until the test is adapted
to make that call. A fix that changes the `newDaveApp` signature makes the test exit 2.

The finding was found by the GOALEPOCH and GOALOUTPUT hunters, proved by the prover, and reviewed on Opus 5.5
(`claude-opus-5-5`), with no fallback.

### Trigger and reachability

Nobody needs to act adversarially. It is enough for an application to be deployed from a non-genesis valid template,
one whose tx buffer commits to outputs, and for anyone to present a valid output proof against R before
`acceptStagedTournamentResult(0)`.

Section 2's valid template expressly allows such templates: "Its tx buffer holds the outputs Merkle root of every
output that the application accepted before it, which at genesis is the root of the empty outputs tree". The manual
documents how to build them: `--assert-rolling-template=outputs_merkle_root:<filename>` is described as being "for a
non-genesis template".

The test builds the trigger state with documented operations only: creation from a configuration, running, and one
input delivery. With a genesis template, R is the empty root, which commits to no outputs, so nothing is lost.

The test does not use guardian foreclosure, which would make the refusal permanent, because the guardian is a trusted
deployment role.

### Rating

1. **Out of scope.** No exclusion applies.
   - The trigger needs no deliberate API state change, no untrusted API caller, and no snapshot outside the
     valid-template conditions.
   - It does not need an application that is not correctly designed. The template is valid and the guest follows the
     rollup interface.
   - The deployment-obligation exclusion does not apply: "Defects that need the deployment to violate one of A1 to A8,
     unless ... an implementation of the referee model is what violates it (section 3)". Here an implementation of
     the referee model is what violates A5.
2. **Role.** `DaveConsensus` and `Application` play "Referee model, as the deployed referee" (AUDIT.md). Section 3
   covers this component: "A defect in what it accepts or derives is rated as if a deployed referee had it." What
   output proofs it accepts is exactly that.

   The manual's model behaves the same way. Section 3 also covers that case: "unless the manual's model itself
   violates one of A1 to A8; then the manual is the defect, rated as a defect of the referee model". The class is the
   same either way.

   This is not "A defect that only changes how long a claim may take to respond". That clause is about the time a
   claim may take to respond, not about which outputs the referee accepts.
3. **High and Medium cases.** None fits.
   - It is not a verifier misbehaving on unreachable before-states.
   - It is not trailing data.
   - It is not shown only by a support component.
   - It is not a hash-integrity or persistence case.
4. **Critical.** The defect violates A5 at a reachable state (the deployment's initial, valid-template state). A5
   says: "An outputs Merkle root is defined only for a settled canonical state that waits at a manual yield with the
   accepted reason. A valid template is such a state." It also says: "Conversely, the referee accepts every output
   that the settled state commits to, whenever its valid proof is presented."

   A1 calls the epoch's starting hash "settled on-chain". The manual (doc/README.md, the vg.lua referee) says: "The
   state an epoch starts from is settled. It is either the stored template hash at genesis or the settled state hash
   of the previous epoch."

   So the template is a settled state from deployment, and the referee refuses its outputs' valid proofs throughout
   epoch 0. Section 8 says: "violating any rule or obligation at a reachable state ... is critical".

**Two readings.**

- **Reading A (preferred): Critical.** "A valid template is such a state" makes the template a settled canonical
  state in its own right. That sentence would add nothing otherwise, because the valid-template definition already
  requires the accepted manual yield. "whenever" then allows no window in which the template's outputs are refused.
- **Reading B: Low.** "The settled state is the last leaf of the winning claim, authenticated as in A2" defines the
  only state whose outputs the "Conversely" sentence covers. "A valid template is such a state" would then only make
  the template's root defined for the case where the template is that last leaf, as in an epoch 0 with no accepted
  input. The correctly-designed-application definition fits this reading: later roots re-commit the template's
  outputs ("That includes the outputs its template already commits to"). Template outputs then become acceptable
  once epoch 0 settles. Under this reading no rule is violated. The defect does not break the goal, and it is a delay
  only.

The deciding fact is whether the threat model means the valid template to be a "settled state" whose outputs the
referee must accept before any tournament settles.

### Possible solution and risks

Register the template's outputs root without trusting anyone, in one of these ways:

- Have the constructor or `DaveAppFactory.newDaveApp` take a `MachineValidityProof` of the template and run
  `_validateMachine(initialMachineStateHash, proof)`. It would then set `_outputsMerkleRoots[root] = true` and emit
  the root in `EpochSealed(0, ...)`.
- Add a permissionless `proveTemplateOutputsMerkleRoot(MachineValidityProof)` that does the same once, against the
  stored template hash.

In both cases, the proof must be checked against T, never taken as a bare root, or the fix would break A5's soundness
side. A required constructor proof changes the factory interface and deployment tooling, and a genesis deployment
would have to supply a proof of the empty root.

The manual's referee model (`wait_for_outputs`) and its text would need the same change, or the manual should say
explicitly that template outputs are accepted only after epoch 0 settles. That would also settle the reading.

### Risk of not fixing it

An application deployed from a non-genesis template cannot validate or execute the outputs its template carries over
for at least epoch 0's tournament plus the claim staging period. If epoch 0 accepts an input, proofs against the
template's own root are never accepted. Those outputs then need new proofs against a later root.

A guardian foreclosure before epoch 0 is accepted would make them permanently unexecutable. The guardian is trusted,
though.

No adversary is needed and no funds are mis-sent. The only exposure is a delay in executing carried-over outputs. To
mitigate it outside the code, deploy from genesis templates, or wait for epoch 0 to settle (ideally with no inputs)
before relying on carried-over outputs.
