## R1-A8-4

**Title.** The PRT bridge keeps working on a pending cleanup transaction of another match, which has no deadline, instead of sending the honest claim's newly due move, so that move can miss its clock.

**Severity.** Medium

### Problem

`methods:tick` of the PRT bridge sorts the due jobs by expiry, earliest first. When the signer already has a
pending transaction whose job is still due, though, the bridge selects that job, overriding the earliest-expiring one.
It attempts only the selected job ("Keep working on a useful pending action. Do not oscillate between two eligible
actions belonging to the same account.").

Permissionless cleanups have open windows (`last = math.maxinteger`): `eliminateMatchByTimeout`,
`eliminateInnerTournament`, and the bridge's own `tryRecoveringBond` and `stageTournamentResult`. When one of them is
pending and the honest claim then comes on turn, the bridge neither prepares nor attempts the honest move
(`advanceMatch`, a seal, or a leaf proof) until the cleanup is mined. The journal re-prices that cleanup only every
`bump_blocks` (3 blocks, +15%). As a result, the honest move's latency becomes the remaining inclusion time of the
cleanup plus its own inclusion time, instead of its own inclusion time alone.

The deployed Dave clocks provision exactly one inclusion budget `G` per honest response. Lateness beyond that budget
is charged to the non-refillable censorship budget, and the root allowance holds only one inclusion in reserve for
the action in flight. So this self-inflicted delay can make the honest claim's response land after its clock expires,
even though the chain includes every transaction within one inclusion. The honest claim is then eliminated by
timeout, which is a completeness failure under section 1: "cannot respond in time. If the honest claim is
eliminated, a dishonest claim can win."

The adversary can repeat the trigger at every honest turn, each time with a Sybil match of its own. Each repetition
draws up to one more inclusion per response from the honest claim's clock.

### Component, role and area

The PRT bridge in `doc/recipes` schedules the player's transactions over its nonce, using the transaction journal
`doc/recipes/prt-transactions.lua`. The AUDIT.md table gives its role: "The PRT player and bridge in `doc/recipes`
... | Support. No production deployment runs the player, the bridge or the CLI." It stands in for the honest
operator's transaction submission, which the threat model lists among the honest operator's path: "Submitting
transactions."

### Location

- `doc/recipes/prt-bridge.lua`, `methods:tick` (line 692 onwards). The pending-candidate selection at lines 729-735
  (`if job.key == candidate.job then selected = job`) and the `preferred` filter in the attempt loop stop every other
  due job from being attempted.
- `doc/recipes/prt-bridge.lua`, `methods:jobs` (line 348 onwards). It derives the open-ended cleanups:
  `eliminateMatchByTimeout` (line 407), `eliminateInnerTournament` (line 426), `tryRecoveringBond` (line 442).
- `doc/recipes/prt-transactions.lua`, `methods:submit`. A resubmission of the same job waits `bump_blocks`
  (line 188; default 3 at line 306).

### Evidence and test

`bugs/R1-A8-4/` contains `test.lua` and `README.md`. Run it with `bugs/run.sh R1-A8-4`. It takes about a second and
uses no chain and no machine.

The test drives the real `bridge.tick`, `attempt` and `jobs`, and the real journal (nonces, pending candidate, bump
interval, replacement), over a mock chain. Only the bridge's `refresh` and `prepare` are stubbed. One tournament holds
two matches:

- a match of two adversary claims that becomes eliminable by timeout;
- a match of the honest claim `H`, on turn from tip 9 with deadline block 20 (11 blocks on its clock).

The mock chain includes every transaction 6 blocks after its nonce's first publication, so every inclusion fits well
within one inclusion budget. The test asserts R4: the honest `advanceMatch` lands before block 20. The test prints
this on audit/prt2 and exits 1, deterministically (five runs):

```
control (no pending cleanup):
  tip 9: published advanceMatch at nonce 0
  honest advanceMatch due from tip 9, window closes at block 20: first published at tip 9, lands in block 15
pending cleanup, included 6 blocks after publication:
  tip 8: published eliminateMatchByTimeout at nonce 0
  tip 11: published eliminateMatchByTimeout at nonce 0
  tip 14: published advanceMatch at nonce 1
  honest advanceMatch due from tip 9, window closes at block 20: first published at tip 14, lands in block 20
informational: pending cleanup never included:
  ... (eliminateMatchByTimeout re-published at tips 8, 11, 14, 17; advanceMatch never published)
VIOLATED: R4: with every transaction included 6 blocks after publication, the honest advanceMatch must land before its deadline (block 20) although a cleanup of another match is pending (control: published at tip 9, lands in block 15; with the pending cleanup: published at tip 14, lands in block 20)
```

The control (nothing pending) is a setup check that exits 2 if it fails. The third scenario is printed for
information only.

The prover's original version asserted two things that the threat model does not require:

- that the move is published at the same tip as in the control ("no delay");
- that the move is published even when the chain never includes the cleanup.

The reviewer replaced both with the inclusion-window assertion above. With the fix suggested below, applied to a
scratch copy, the test exits 0 (`advanceMatch` replaces the cleanup at nonce 0 at tip 9 and lands in block 14), and
`doc/recipes/prt-bridge-test.lua` still exits 0.

Models: hunted, proved and reviewed on Opus 5.5. No fallback was used.

### Trigger and reachability

The adversary needs a match of two of its own Sybil claims, which section 7 allows: "Post any number of claims
(Sybils) ... and abandon or defend them at will"; "Hold any claim". It times that match so that it becomes
eliminable shortly before the honest claim comes on turn, for example at the block before the adversary's own
`advanceMatch` against the honest claim. The adversary controls both deadlines, because it chooses when its claims
join and when they stop answering. The honest bridge runs with cleanup on by default (`crisium.lua`: `cleanup =
options.cleanup ~= "no"`), so it publishes the elimination. The honest move then waits for that elimination's
inclusion.

The delay is bounded by one pending transaction per honest response. Once the cleanup is mined, nothing is pending,
and expiry order puts the honest move first. The same holds for the honest claim's own open-ended jobs
(`tryRecoveringBond`, `stageTournamentResult`).

The harm needs the honest claim's balance at a turn to be less than two inclusions. That state is reachable within
the deployed model. Dave's root allowance is `C + 2G + (L - 1)(T + 2G)` (`ClockBudgets.maxAllowance`), and an honest
claim that has absorbed censorship up to `C` keeps only the in-flight reserve `G` for its next response. The section
7 adversary may censor within the clocks. Alternatively, the adversary can repeat the trigger at many honest turns
and raise chain activity so that each inclusion approaches `G`. The excess of every honest response is then drawn
from the same ledger.

### Rating

1. Out of scope: no. The trigger is a Sybil match timed by the adversary, an ordinary capability in section 7. It
   needs no machine API access by an untrusted party, no unguaranteed directory, no snapshot or deep chain reorg,
   and no violation of A1 to A8 by the deployment. The pinned Dave clocks follow their own model, and the bridge's
   delay defeats that model.
2. Role: Support. AUDIT.md: "The PRT player and bridge in `doc/recipes` ... | Support. No production deployment runs
   the player, the bridge or the CLI." This clause covers `prt-bridge.lua` and `prt-transactions.lua`. Section 3: "A
   defect that only a support component shows is Medium when it would rate High or Critical in the role the
   component stands in for, such as ... the honest operator for an implementation of an operator ... Any other
   support defect is Low." The bridge stands in for the honest operator's "Submitting transactions."
3. High and Medium cases: "A defect that only a support component shows, when section 3 rates it Medium." This
   applies if the stood-in rating (step 4) is High or Critical. No other listed High or Medium case fits better.
4. Critical, in the stood-in honest-operator role: R4 requires that "The honest operator observes the chain and
   submits its transactions within the dispute clocks." Section 8 says: "violating any rule or obligation at a
   reachable state, or anywhere on the honest operator's path, is critical." The violation happens at a reachable
   state: an honest claim on turn with a balance of more than one inclusion and less than two, while a cleanup is
   pending. Every transaction lands within one inclusion, yet the honest response lands after its clock expires
   (the test: block 20 against deadline 20). That is a completeness failure under section 1. So the defect would be
   Critical in the honest-operator role, and Medium as a support defect.

Two readings:

- (a) Medium, preferred. Dave's dimensioning provisions one inclusion per honest response and charges any excess to
  a non-refillable budget. That makes an adversary-triggered extra inclusion an erosion of the clocks that A7 sizes
  "for the honest claim", and a lost move once the balance is at its reserve.
- (b) Low. The goal's assumption "the chain includes its transactions within the dispute clocks" is read to absorb
  any bounded inclusion latency, so a delay of one extra inclusion per response never breaks R4 unless the clocks
  are sized tighter than two inclusions per response.

What decides between them is whether the threat model's clocks budget one inclusion per honest response, as the
pinned Dave model does, or leave unstated slack for honest self-delay.

### Possible solution and risks

In `methods:tick`, keep the pending job only when it expires no later than the earliest due job. For example:
`if job.key == candidate.job and job.last <= eligible[1].last then selected = job`. Otherwise the earliest-expiring
job replaces the pending candidate at the same nonce, through the existing `obsolete` path.

Risks:

- The replacement must outbid the pending candidate (+15%), so at the fee ceiling it is blocked like any bump.
- The dropped cleanup goes back to the queue. It is permissionless and has no deadline, so the only loss is a later
  cleanup.
- Oscillation between two deadline-bound jobs is still prevented, because the pending job is kept whenever it is
  the earliest.

A further option is to skip bump waiting when the selected job differs from the pending one, which the journal
already does. The other-epoch branch has the same pattern ("Another epoch's pending transaction is left alone until
it is mined") and deserves the same review.

### Risk of not fixing it

The bridge is not run by any production deployment, so no deployed dispute is exposed. Anyone who copies the
reference player's scheduling into a validator node inherits it. An adversary with Sybil claims can then add up to
one inclusion of delay to each honest response, eroding the honest claim's clock and, at its margin, eliminating it
by timeout. The demos and tests built on the bridge can also lose an honest claim under congestion. Running with
`--cleanup=no` avoids the permissionless cleanups, but not the honest claim's own open-ended jobs
(`tryRecoveringBond`, `stageTournamentResult`).
