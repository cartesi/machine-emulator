## R7-MANTOURN-1

**Title.** When a match is sealed at divergence leaf 0, both referees accept any agreed-state proof. Dave's
`Match._requireAgreeState` (released v3.0.0-alpha.7, through `Tournament.sealLeafMatch` and
`sealInnerMatchAndCreateInnerTournament`) and the PRT referee model's `validate_seal_response` (`doc/recipes/prt.lua`)
never read the proof argument there. The same proof with a surplus sibling is refused past leaf 0.

**Severity.** Medium (preferred reading). Low under the reading that the Medium trailing-data case and R3 cover only
the verifiers of transition logs, not the tournament's computation-hash proof checks (see Rating).

### Problem

At height one, a seal reveals the two leaves where the claims diverge and proves the agreed state just before them
against the claim on turn. At leaf 0 the agreed state is the tournament's initial hash, which the referee already
holds. The manual says so: "At leaf zero, the agreed state is the tournament's initial state hash, which the referee
already knows". The proof slot then has nothing to hold, and the only valid proof is an empty one.

Neither referee checks that. Dave returns from the leaf-0 branch of `_requireAgreeState` after checking
`agreeState == initialHash`, without looking at `agreeStateProof`:

```solidity
if (divergencePosition == 0) {
    require(agreeState.eq(args.initialHash), ITournament.IncorrectAgreeState(args.initialHash, agreeState));
    return;
}
revealingCommitment.requireState(args.height, divergencePosition - 1, agreeState, agreeStateProof);
```

Past leaf 0, `requireState` demands exactly `height` siblings (`CommitmentProofWrongSize`). The recipe model checks
`response.agreed_state_hash_proof` only under `if leaf_index ~= 0`, where it also demands
`#proof.sibling_hashes == tournament.height`. At leaf 0 it ignores the field, whatever table it holds.

So a seal at leaf 0 carrying a non-empty, junk proof is accepted. The sealed result is unchanged: the agreed state is
still the initial hash, and the contested leaves are the same. The junk is data the referee accepts and ignores. That
is trailing data, which R3 makes a validity condition: "Conditions on the log are validity conditions. A log that
fails one must be rejected. Examples are wrong order, wrong address, wrong size, duplicate, missing, or trailing
data". Section 4 adds: "A verifier must assume that every count, index, address, size, and hash it receives was chosen
to fool it". The security goal of section 1 is not broken, because the decision does not change. The rule is still
violated, in the deployed referee and in the model alike.

### Component, role and area

- Dave v3.0.0-alpha.7 `prt/contracts`, the seal of a match (`Match.sealDivergence` → `_requireAgreeState`). The
  AUDIT.md table gives it the role "Referee model, as the deployed referee".
- The PRT referee model in `doc/recipes`, the seal validation (`validate_seal_response`). Role: "Referee model".

Area: the proof of the agreed state in a seal. This is a computation-hash proof whose index and height are referee
parameters (section 2).

### Location

- `bugs/harness/work/dave/released/prt/contracts/src/tournament/libs/Match.sol`: `_requireAgreeState` (lines
  290-308), called from `sealDivergence` (lines 130-180). This is the pinned Dave source.
- `bugs/harness/work/dave/released/prt/contracts/src/tournament/Tournament.sol`: `sealLeafMatch` (line 528) and
  `sealInnerMatchAndCreateInnerTournament` (line 677).
- `doc/recipes/prt.lua`: `validate_seal_response` (lines 310-339). The manual quotes the same function
  (`doc/README.md`, around line 10692).

### Evidence and test

`bugs/R7-MANTOURN-1/` contains the following files.

- `test.lua`, run by `bugs/run.sh R7-MANTOURN-1` (about 8 s, no chain needed). It runs two parts.
  - Part 1 builds a height-1 match in `prt.lua` and calls `validate_seal_response`. It checks three controls. A
    leaf-0 seal without a proof is accepted. A leaf-1 seal with the honest proof is accepted. A leaf-1 proof with a
    surplus sibling is refused. It then asserts that a leaf-0 seal carrying a junk proof table is refused. The table
    has 3 junk siblings, a wrong address and wrong sizes.
  - Part 2 runs `dave.sh`.
- `dave.sh` copies the harness's released Dave build (`bugs/harness/work/dave/released`, with the regenerated step)
  to a temporary directory. It never touches the shared build. It runs `forge test --offline` on
  `SealLeafZeroProof.t.sol` there.
- `SealLeafZeroProof.t.sol` is built on Dave's own `SmallSingleLevelTournament` fixture: the real `Tournament`/`Match`
  code with a height-3, single-level geometry. Two claims bisect down to height 1 at position 0. The test checks three
  controls. A leaf-0 seal with an empty proof is accepted. A leaf-1 seal with the honest 3-sibling proof is accepted.
  The same leaf-1 proof plus one trailing word is refused. It then asserts that `sealLeafMatch` at leaf 0 refuses a
  1-word junk proof and a 64-word junk proof.
- `README.md` describes the test.

The test exits 1 if either referee accepts the junk proof at leaf 0, 0 if both refuse it, and 2 if a control fails or
the setup is missing. On audit/prt2 the reviewer re-ran it twice, and the prover reports three runs. Every run exited
1 with this output:

```
model controls: leaf-0 seal without proof accepted; leaf-1 honest proof accepted; leaf-1 proof with a surplus sibling refused
model: leaf-0 seal with a junk agreed-state proof (3 junk siblings): ACCEPTED, divergence at leaf 0
Dave controls: leaf-0 seal with empty proof accepted; leaf-1 honest proof accepted; leaf-1 proof with a trailing word refused (CommitmentProofWrongSize)
Dave: sealLeafMatch at leaf 0 with a 1-word junk agreed-state proof: ACCEPTED
Dave: sealLeafMatch at leaf 0 with a 64-word junk agreed-state proof: ACCEPTED
VIOLATION (R3 trailing data): prt.lua validate_seal_response accepts a junk proof at leaf 0
VIOLATION (R3 trailing data): Dave sealLeafMatch accepts a 1-word junk proof at leaf 0
VIOLATION (R3 trailing data): Dave sealLeafMatch accepts a 64-word junk proof at leaf 0
VIOLATED: R3: a seal at leaf 0 must refuse an agreed-state proof that carries data
run.sh: R7-MANTOURN-1: exit 1 (bug present)
```

The prover tried each fix in a scratch copy, and each turned its part to "refused". The Dave fix was
`require(agreeStateProof.length == 0)` in the leaf-0 branch. The model fix was
`assert(response.agreed_state_hash_proof == nil)` in the leaf-0 branch. Found, proved and reviewed on Opus 5.5
(`claude-opus-5-5`). No fallback model was used.

### Trigger and reachability

Any claimant can trigger it, because section 4 lists "dishonest claimants (any number, any logs, any proofs, any
timing)" as untrusted. The claimant seals a match whose first divergent leaf is 0 and attaches a non-empty
agreed-state proof. Leaf 0 diverges whenever a claim contradicts the other at its first sampled state. In a uarch-level
tournament this is the dispute over the first uarch step, which is common. The adversary can also force it, since
section 7 lets it "Steer the dispute to any position of the honest computation". No unreachable state is involved.

The honest players never send such a proof. `prt.lua` `seal_divergence` attaches a proof only when
`leaf_index ~= 0`, and `prt-bridge.lua` then sends `initialHash` and an empty sibling list.

### Rating

1. Out of scope: no. The trigger is a claimant's seal transaction, which section 4 makes adversarial. Three
   exclusions were checked. The exclusion "Defects that need the deployment to violate one of A1 to A8, unless ... an
   implementation of the referee model is what violates it" does not apply: the referee itself shows the defect. The
   defect needs no direct use of the machine API by an untrusted party, no untrusted snapshot, and no host fault.
2. Role: Dave is "Referee model, as the deployed referee", and `doc/recipes` is "Referee model" (AUDIT.md table).
   Section 3, Referee model: "A defect in what it accepts or derives is rated as if a deployed referee had it". This
   clause covers both components. The defect is in what they accept, not in a copy of a verifier they call: the check
   is in `Match.sol` and in `validate_seal_response` themselves. The settled readings agree: the clause "covers every
   message the model accepts".
3. High and Medium cases: section 8 Medium: "A referee verifier that accepts trailing data that does not affect its
   result (R3)". It fits, rated as a deployed referee. The seal's agreed-state check is a proof verifier of the deployed
   referee. Section 1 counts proof verifiers among verifiers ("a proof verifier accepts a node that the committed tree
   does not hold at the stated index and height"). Its index and height are referee parameters (section 2: "The tree
   index and height at which each node of a computation-hash proof ... is authenticated"). The junk does not change
   the sealed divergence. No High case fits: the before-state is reachable, and no wrong or second result is accepted.
4. Critical: not reached. R3 is violated at a reachable state, but the listed Medium case caps it.

Two readings give different classes.

- **Medium (preferred).** R3's validity conditions and the Medium trailing-data case apply to every proof that a
  referee verifies, computation-hash proofs included. This matches section 1, section 4 ("Logs and proofs are
  adversarial") and the referee parameters of section 2. It also matches Dave's own design, which refuses one
  trailing sibling past leaf 0.
- **Low (alternative).** R3 ("Every log that a verifier accepts must then yield the same after-hash") and the Medium
  case speak only of transition-log verifiers. Under that reading, the tournament's commitment-proof checks fall
  under no rule, and an ignored argument violates nothing.

The deciding fact is whether "verifier" in R3 and in the Medium case includes the referee's computation-hash proof
checks. The threat model never says explicitly. A sibling finding, R1-R3-3 (the model accepts superfluous logs in
state-transition proofs), was confirmed Medium under the same split.

### Possible solution and risks

- Dave: in the leaf-0 branch of `_requireAgreeState`, add `require(agreeStateProof.length == 0, ...)` (for example
  `CommitmentProofWrongSize`). This covers both `sealLeafMatch` and `sealInnerMatchAndCreateInnerTournament`.
- Model: in `validate_seal_response`, assert that `response.agreed_state_hash_proof == nil` when `leaf_index == 0`.

Risk: a node that sends a non-empty proof at leaf 0 would then fail to seal, and its claim could time out. The honest
recipe player and bridge send none. Other node implementations must be checked before the contract change is
deployed. The sling node is out of this campaign's scope. Changing the contract also changes the deployed referee
code, so it needs a new release (A6, R13).

### Risk of not fixing it

The decision of the match is not affected. A deployment left unfixed accepts proofs with meaningless content at one
seal position, contrary to R3. Any claimant can put arbitrary calldata into a valid seal at its own gas cost. The
refund is a fixed estimate (`refundable(Gas.SEAL_LEAF_MATCH, 0)`), so the junk is not reimbursed. Tools that index or
replay seals must tolerate it. The model and Dave keep their checks asymmetric between leaf 0 and the other leaves.
That leaves room for later changes that start reading the proof at leaf 0 to rely on unvalidated data. There is no
mitigation outside the code. Off-chain tools should ignore the proof argument at leaf 0.
