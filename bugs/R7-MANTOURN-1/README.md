# R7-MANTOURN-1: a seal at leaf 0 accepts any agreed-state proof

When a match bisects down to divergence leaf 0, the seal's agreed state is the tournament's initial hash, so the
agreed-state proof should be empty. Both referees ignore the proof argument there and accept a seal whatever
it carries:

- Dave v3.0.0-alpha.7 (released `prt/contracts`), `Match._requireAgreeState`: when `divergencePosition == 0`
  it checks `agreeState == initialHash` and returns without reading `agreeStateProof`. Past leaf 0,
  `Commitment.getRoot` requires exactly `height` siblings (`CommitmentProofWrongSize`). The function is reached
  from `Tournament.sealLeafMatch` and `sealInnerMatchAndCreateInnerTournament`.
- `doc/recipes/prt.lua` `validate_seal_response`: checks the proof only when `leaf_index ~= 0`. At leaf 0,
  `response.agreed_state_hash_proof` is ignored, whatever table it holds.

## What is asserted

The requirement is THREAT_MODEL R3: "Conditions on the log are validity conditions. A log that fails one must
be rejected. Examples are wrong order, wrong address, wrong size, duplicate, missing, or trailing data". Section
4 adds "A verifier must assume that every count, index, address, size, and hash it receives was chosen to fool
it". Section 8 has the Medium case "A referee verifier that accepts trailing data that does not affect its
result (R3)".

1. **Referee model** (`prt.validate_seal_response`, a height-1 match). Three controls must hold. A leaf-0 seal
   with no proof is accepted. A leaf-1 seal with the honest proof is accepted. A leaf-1 proof with a surplus
   sibling is refused. The test then asserts that a leaf-0 seal carrying a junk proof table (3 junk siblings,
   wrong address and sizes) is refused.
2. **Dave, the deployed referee.** `SealLeafZeroProof.t.sol` is a forge test on Dave's own
   `SmallSingleLevelTournament` fixture, which is the real `Tournament`/`Match` code with a height-3,
   single-level geometry. `dave.sh` runs it in a temporary copy of the harness build
   `bugs/harness/work/dave/released`, which has the regenerated step. The copy has the same relative layout,
   and its forge cache makes the compile incremental (about 6 s). The shared build is never touched. Three
   controls must pass. A leaf-0 seal with an empty proof is accepted. A leaf-1 seal with the honest 3-sibling
   proof is accepted. The same leaf-1 proof plus one trailing word is refused. The test then asserts that
   `sealLeafMatch` at leaf 0 refuses a proof of 1 junk word and a proof of 64 junk words.

Exit 1 if either referee accepts the junk proof at leaf 0. Exit 0 if both refuse it. Exit 2 if a control fails
or the setup is missing. Both fixes were checked in scratch copies, and each turns its part to "refused":
`require(agreeStateProof.length == 0)` in the leaf-0 branch of `_requireAgreeState`, and
`assert(response.agreed_state_hash_proof == nil)` in the leaf-0 branch of `validate_seal_response`.

## Run

```sh
bugs/run.sh R7-MANTOURN-1
```

This needs the in-tree emulator, `forge` from the harness and the released Dave build
(`bugs/harness/chain/build-dave.sh released`). It takes about 8 s and needs no chain.

## Expected output on audit/prt2

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

The sealed divergence itself is unchanged: the agreed state is still the initial hash, and the contested leaves
are the same. The junk proof does not change the result. It is trailing data.
