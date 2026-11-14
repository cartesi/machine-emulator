## R8-GOALTIMEOUT-1

**Title.** Released Dave response budget (G = 5 minutes, 25 Ethereum blocks) is shorter than Ethereum finality, so an
honest claim that acts only on finalized history is charged on every response and loses by timeout to a few Sybils.

**Severity.** Medium (preferred: section 3 rates referee-model response-time defects as support; Critical in the
stood-in role). Critical under the reading that Dave's clock sizing is part of what the deployed referee derives. Low
under the reading that a confirmation depth shorter than G is an acceptable "final" policy (see Rating).

### Problem

Dave forgives each response of a claim only one response budget G. `Clock.pauseAfterResponseAt` stores
`allowance - max(elapsed - G, 0)`, and nothing refunds the excess. Once the allowance is at or below the elapsed time,
`advanceMatch` reverts with `CannotAdvanceTimedOutClock`. The released deployment script fixes G at 5 minutes on every
chain (`_getInclusionBudget`), which is 25 blocks on Ethereum and Sepolia. The root allowance is
A = C + 2G + (T + 2G), with C = 8 hours on testnets (A = 3,100 blocks on Sepolia) and 1 week on mainnets.

Ethereum finalizes a block at least 64 slots after it is produced. The threat model's honest operator "acts only on
history that its policy treats as final, such as finalized blocks", and "acting on history before it is final ... is
outside this model" (section 4). Such an operator cannot answer a bisection turn until the opponent's move is
finalized, so each response lands at least 65 blocks after the turn opened and is charged at least 40 blocks. Dave's
own design note (`docs/dimensioning.md`, "One delay ledger") says the budget holds because "a joined match's
responses ... read latest", that is, it is sized for an operator that acts on non-final history, which the model
excludes.

The adversary chooses how many charged responses the honest claim must make. Six Sybil root claims (bonds only, seven
claims in all, ceil(log2 7) = 3 rounds) force three root matches on the honest claim. On the Sepolia constants the
third exhausts the honest clock. A Sybil then wins that match by timeout, and a fabricated final state wins the root.
That breaks the goal of section 1 (a completeness failure: the honest operator "cannot respond in time") and violates
A7 and R4.

### Component, role and area

Dave v3.0.0-alpha.7 `prt/contracts`, its released clock constants and clock rules. The AUDIT.md table gives its role:
"Referee model, as the deployed referee. Audit the released constants, not `doc/recipes/prt-contracts.patch`." The
area is clock sizing: the response budget relative to the chain's finality, and how response time is charged.

### Location

Under `bugs/harness/work/dave/released/prt/contracts/`:

- `script/Deployment.s.sol`: `_getInclusionBudget` (5 minutes "on every chain"), `_registerChainKinds` (MAINNET
  1 week, TESTNET 8 hours), `_registerChain` (Ethereum chain 1 and Sepolia 11155111 at 12,000 ms blocks).
- `src/arbitration-config/ClockBudgets.sol`: `responseBudget`, `refill`, `maxAllowance`.
- `src/tournament/libs/Clock.sol`: `pauseAfterResponseAt` (charges `elapsed - responseBudget`, reverts
  `CannotAdvanceTimedOutClock`), `initializePausedAt` (deducts lateness at join), `pauseWinnerAt`.
- `src/tournament/Tournament.sol`: `advanceMatch`, `winMatchByTimeout`, and the join pairing.
- Design statement: `bugs/harness/work/dave/released/docs/dimensioning.md`, "One delay ledger".

### Evidence and test

`bugs/R8-GOALTIMEOUT-1/` contains:

- `test.lua`: the entry point run by `bugs/run.sh`. It runs `dave.sh` and parses forge's PASS/FAIL lines. It exits 2
  if the control test fails or the requirement test fails for any other reason.
- `dave.sh`: copies the shared harness's released Dave build (`bugs/harness/work/dave/released`) into a temp
  directory, adds the test file and grants read access to `out/`. It then runs
  `forge test --offline -vv --match-contract FinalityLagTimeoutAuditTest` and removes the copy.
- `FinalityLagTimeout.t.sol`: deploys the released build's own bytecode with `vm.deployCode`: `Tournament`,
  `MultiLevelTournamentFactory`, and `CanonicalTournamentParametersProvider` with the constructor arguments that the
  released `Deployment.s.sol` computes for Sepolia (through Dave's own `test/fixtures/ScriptProviderArguments.sol`).
  It also deploys a stub state transition, because no leaf match is reached. Block numbers advance with `vm.roll`.
  Seven root claims join: the honest one and six Sybils. Two Sybil pairs are parked, and their survivors re-enter by
  Dave's timeout re-pairing while the honest claim is busy, so three matches are forced on the honest claim. Each
  Sybil answers in the next block and abandons on its last turn. The honest operator acts LAG blocks after each
  enabling block (the root's creation, each turn, each expiry), and its transaction lands one block later.
  - `testControlShallowDepthHonestWins`: LAG = 4. It must pass, and it does. The honest claim wins all three matches
    and the root, and its allowance stays at 3,095.
  - `testFinalizedHonestSurvivesForcedMatches`: LAG = 64, the shortest Ethereum finalization delay. It asserts that
    the honest claim wins every forced match and the root.
- `README.md`: the prover's notes.

Run it with `bugs/run.sh R8-GOALTIMEOUT-1`. On audit/prt2 the reviewer ran it twice, and both runs exited 1 (the
prover reports five runs that exited 1). The run takes a few seconds, and nothing in it is random. It prints:

```
released provider (Sepolia): block 12000 ms, censorship 28800 s, inclusion 300 s -> root height 54, response budget G 25 blocks, root allowance 3100 blocks
honest acts LAG = 64 blocks after each enabling block; joined with allowance 3035
  match 1, honest response 1 at +65 blocks: allowance 2995
  ...
honest won forced match 1 by timeout; allowance after: 1956
  ...
honest won forced match 2 by timeout; allowance after: 877
  match 3, honest response 21 at +65 blocks: allowance 37
Sybil won the match against the honest claim by timeout
root tournament finished, winner final state 0x6f99e30b... = a FABRICATED (Sybil) final state
[FAIL: R8-GOALTIMEOUT-1 (A7/R4): honest advanceMatch refused (CannotAdvanceTimedOutClock) in forced match 3 at honest response 22]
VIOLATED: A7/R4: an honest root claim acting on finalized history (lag 64 blocks) must not lose by timeout in the 3 matches that 6 Sybil claims force on it under the released Dave clocks
run.sh: R8-GOALTIMEOUT-1: exit 1 (bug present)
```

The prover reports that with the inclusion budget raised to 15 minutes (G = 75 blocks), both tests pass. That variant
is not part of the test. The reviewer checked the clock facts against the released source (`Clock.sol`,
`ClockBudgets.sol`, `Deployment.s.sol`) and found the test's choreography uses only public entry points of the
released contracts. The reviewer ran on Opus 5.5 (no fallback). A permission prompt refused the reviewer's search of
`AUDIT_REPORT.md` and `BUGS.md` for the earlier ruling on R1-A7-1. That ruling is taken from the campaign's candidate
list instead.

### Trigger and reachability

Any party that can post root claims triggers it. It needs only bonds: no reorg, no censorship and no invalid proof.
It posts Sybil claims that meet the honest claim one after another (a join while the honest claim is dangling, or a
parked Sybil pair whose survivor re-pairs with the honest claim after a timeout). Each Sybil answers its own turns at
once and abandons on its last turn. The honest operator is any operator whose dispute observation waits for Ethereum
finality.

On Sepolia-class testnets (C = 8 hours, registered in the released script for chain 11155111 and others), three
forced root matches suffice at the minimum finality lag. On Ethereum mainnet (C = 1 week, A = 51,100 blocks), the same
per-response charge needs about 47 forced root matches at a 65-block lag, according to the hunter's arithmetic. The
test does not reproduce this. Under a normative bracket that means about 2^47 claims, but Dave's join pairing lets
Sybils meet the honest claim sequentially, about two bonds per match (see the dropped R8-GOALTIMEOUT-2). Inner-level
matches add further charged responses.

### Rating

1. Out of scope: not excluded. The exclusion "Defects that need the deployment to violate one of A1 to A8, unless ...
   an implementation of the referee model is what violates it (section 3)" keeps it, because Dave's own released
   constants violate A7. "Reorganizations of the chain deeper than the operator's input policy" does not apply,
   because no reorg is involved: the honest operator only waits for finality, as section 4 says it does. The manual's
   clock values are not normative (section 5: "neither are its clock values"), so Dave's sizing is judged against A7
   directly.
2. Role: Dave is "Referee model, as the deployed referee" (AUDIT.md). Section 3, referee model: "A defect that only
   changes how long a claim may take to respond, or only crashes or stalls the model ... is rated as support." The
   defect is a response budget too short for the honest operator's response time, which is what that clause
   describes, so the support rule applies: "Medium when it would rate High or Critical in the role the component
   stands in for."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." In the role
   it stands in for (the deployed referee), it would be Critical (step 4), so it is Medium. No High case fits: it is
   not limited to unreachable states, and it is not a constant-factor cost increase within the sizing.
4. Critical (in the stood-in role): A7, "The dispute constants and clocks leave room for the honest claim to play the
   logarithmic number of matches that a tournament forces on it ... No rule of the referee may make the honest claim
   lose by timeout while it acts within its own clock." Three forced matches (seven claims) exhaust the honest clock
   of an operator that acts as soon as finalized history allows. R4: "The honest operator observes the chain and
   submits its transactions within the dispute clocks." Section 1: a completeness failure, "cannot respond in time.
   If the honest claim is eliminated, a dishonest claim can win."

Readings that give other classes:

- Critical. Section 3 also says "Which claim a timeout or an elimination decides is part of what it derives." If the
  released clock sizing counts as what the deployed referee derives, rather than "only how long a claim may take to
  respond", it rates Critical directly by A7. That is the same choice as for R1-A7-1, Dave's leaf commitment budget.
  The deciding fact is whether the clause on response time covers the sizing of the budget that decides the timeout.
- Low. Section 4 makes finality policy-relative: "acts only on history that its policy treats as final, such as
  finalized blocks. A reorganization deeper than that is a failure of the chain." If a confirmation depth under G
  (for example the recipe player's default `--dispute-policy` of 4 blocks, which the control test shows is never
  charged) counts as an acceptable "final" policy, then an honest operator exists that the clocks accommodate, A7
  holds, and the finding is Low. The reviewer prefers the Medium reading for three reasons. Section 4 names
  "finalized blocks" as its example of the honest operator's policy. A7 must leave room for "the honest claim", not
  for some operator with a convenient policy. And Dave's own design note admits its budget assumes responses that read
  "latest", that is, "acting on history before it is final", which the model puts outside. The deciding fact is
  whether A7 must accommodate every policy that section 4 admits, in particular its named example.

### Possible solution and risks

Size the response budget for the chain's finality, not only for one inclusion. For example, make G at least the
finality delay plus one inclusion per chain kind (more than 13 minutes on Ethereum and Sepolia, at least 75 blocks as
the prover's variant shows). Alternatively, raise C so that it covers the per-response finality excess times the
worst-case number of forced responses, under Dave's sequential pairing. Either change lengthens disputes, because a
larger G multiplies every timeout and the maximum allowance. It also changes the deployed constants, so it is a new
deployment version. Documenting a required confirmation depth instead would only move the risk onto pre-finality
reorgs that the operator would have to treat as chain failures.

### Risk of not fixing it

On every Ethereum-timed deployment made with the released script, an operator that defends only on finalized
history can be timed out by an adversary who posts a few Sybil claims: three on Sepolia-class testnets, and a few
dozen sequential ones on mainnet. A fabricated final state then settles, and its outputs become executable. The
mitigation outside the code is for honest operators to answer disputes at a shallow confirmation depth (below
25 blocks), accepting the risk of acting on history that can still be replaced.
