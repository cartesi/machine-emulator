# R8-GOALTIMEOUT-1: released Dave response budget is shorter than Ethereum finality

Component: Dave v3.0.0-alpha.7 (`prt/contracts`), released clock constants (`script/Deployment.s.sol`
`_getInclusionBudget` = 5 minutes on every chain, `ClockBudgets`, `Clock.pauseAfterResponseAt`), built by the shared
harness at `bugs/harness/work/dave/released`.

## Requirement

THREAT_MODEL.md:

- A7: "The dispute constants and clocks leave room for the honest claim to play the logarithmic number of matches
  that a tournament forces on it ... No rule of the referee may make the honest claim lose by timeout while it acts
  within its own clock."
- R4: "The honest operator observes the chain and submits its transactions within the dispute clocks."
- Section 4: "The honest operator acts only on history that its policy treats as final, such as finalized blocks."

## What the test does

`dave.sh` copies the released Dave build into a temp directory, adds `FinalityLagTimeout.t.sol` and runs it with
`forge test` (a few seconds; only the test file is compiled). The test deploys the released bytecode from the build's
own artifacts: `Tournament`, `MultiLevelTournamentFactory`, and `CanonicalTournamentParametersProvider` with the
constructor arguments that the released deployment script computes for Sepolia (chain id 11155111: 12 s blocks,
8 h censorship, 5 min inclusion). That gives root height 54, response budget G = 25 blocks and root allowance
A = 3100 blocks. A stub state transition is used because no leaf match is reached. Block numbers advance with
`vm.roll`.

The setup has seven root claims: the honest one and six Sybils (ceil(log2 7) = 3 rounds). Using only joins before
closure and Dave's own timeout re-pairing, the Sybils force three successive matches on the honest claim. Two Sybil
pairs are parked, and their survivors re-enter while the honest claim is busy. Each Sybil answers in the next block
and abandons on its last turn, so the honest claim never has to seal.

The honest operator acts `LAG` blocks after the block that enables each action, and its transaction lands one block
later. Those actions are: joining once the root's creation is final, answering each bisection turn once that turn is
final, and claiming each timeout once the expiry is final.

- `testControlShallowDepthHonestWins`: LAG = 4, which is below G. The same choreography ends with the honest claim
  winning all 3 forced matches and the root, and it is never charged. This test must pass, or the run exits 2.
- `testFinalizedHonestSurvivesForcedMatches`: LAG = 64. That is the shortest delay after which an Ethereum block can be
  finalized: two 32-slot epochs with every slot filled. The test asserts that the honest claim wins every forced match
  and the root.

## Run

```sh
bugs/run.sh R8-GOALTIMEOUT-1
```

Exit codes:

- 1: the honest claim lost by timeout (the bug).
- 0: the honest claim wins.
- 2: setup error, for example the released build is missing, the control fails or the choreography breaks.

## Expected output on audit/prt2

Exit 1. Each honest response lands 65 blocks after its turn opened, and the clock is charged 65 - 25 = 40 blocks for
it. Each honest timeout claim is charged 64 - 25 = 39 blocks. Nothing refunds these charges.

```
honest acts LAG = 64 blocks after each enabling block; joined with allowance 3035
  match 1, honest response 1 at +65 blocks: allowance 2995
honest won forced match 1 by timeout; allowance after: 1956
honest won forced match 2 by timeout; allowance after: 877
  match 3, honest response 21 at +65 blocks: allowance 37
Sybil won the match against the honest claim by timeout
root tournament finished, winner final state 0x6f99... = a FABRICATED (Sybil) final state
[FAIL: R8-GOALTIMEOUT-1 (A7/R4): honest advanceMatch refused (CannotAdvanceTimedOutClock) in forced match 3 at honest response 22]
VIOLATED: A7/R4: ...
```

The control passes: honest allowance stays at 3095 and the honest claim wins the root.

To check the test against a fix, the same test was run with the provider's inclusion budget raised to 15 minutes
(G = 75 blocks, more than the finality delay). Both tests then pass, so the run would exit 0. That variant is not
part of the test.

## Scope notes

- The test covers Sepolia's released constants (C = 8 h). With mainnet constants (C = 1 week, A = 51,100 blocks) the
  same per-response charge needs about 47 forced matches at LAG 64-65, according to the hunter's arithmetic. This test does not reproduce that.
- With LAG below 62 blocks, three forced matches would not exhaust the Sepolia clock, and more Sybil matches would be
  needed. The test fixes LAG = 64, the minimum finalization delay with no missed slots.
- No reorg, no censorship and no invalid proof is involved. The Sybils spend only their bonds.
