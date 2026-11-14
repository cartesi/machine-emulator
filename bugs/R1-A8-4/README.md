# R1-A8-4: a pending cleanup of another match delays the honest commitment's deadline-bound move

Component: PRT bridge, `doc/recipes/prt-bridge.lua` `methods:tick` (role: Support, standing in for the honest
operator), with the real transaction journal `doc/recipes/prt-transactions.lua`.

## What is asserted

`test.lua` drives the real `bridge.tick` / `attempt` / `jobs` and the real journal (nonce slots, pending
candidate, bump interval, replacement) over a mock chain. Only the bridge's observation (`refresh`) and calldata
preparation (`prepare`) are stubbed. One tournament holds two matches:

- a match of two adversary claims that becomes eliminable by timeout (permissionless cleanup
  `eliminateMatchByTimeout`, window open to `math.maxinteger`);
- a match of the honest claim `H`, which is on turn: `advanceMatch` due until `responderDeadline` (block 20).

Every transaction the mock chain includes lands 6 blocks after its nonce was first published (the newest
candidate of that nonce lands). The honest claim gets the turn at tip 9 with 11 blocks on its clock (deadline
block 20; a clock expires at equality): more than one inclusion and less than two. Scenarios:

1. control: the cleanup becomes eligible on the same tick as the honest move (tip 9), with nothing pending. The
   bridge publishes `advanceMatch` at tip 9 and it lands in block 15. This is a setup check: exit 2 if it fails.
2. the cleanup became eligible one block earlier (tip 8), so it is pending when the honest move becomes due.
3. informational only, not asserted: the cleanup is never included. A chain that includes none of the honest
   transactions is outside the goal, and a fixed bridge's move would not land there either.

Required in scenario 2 (R4): the honest `advanceMatch` lands before block 20. On audit/prt2 the bridge keeps the
pending cleanup ("Keep working on a useful pending action") and does not attempt `advanceMatch` until the cleanup is
mined. It publishes `advanceMatch` at tip 14 at nonce 1, and that lands in block 20, when the honest clock has
already expired.

Requirement (THREAT_MODEL.md R4): "The honest operator observes the chain and submits its transactions within the
dispute clocks." The deployed Dave clock model provisions one inclusion budget per honest response (Dave
`docs/dimensioning.md`: "every advance ... within `G` of becoming due"; "Lateness beyond a bound is censorship,
drawn from one ledger that nothing refills").

Reviewer note: the prover's original version asserted that `advanceMatch` was published at the same tip as in the
control, and that it was published even when the chain never includes the cleanup. The reviewer replaced both
with the inclusion-window assertion above. "No delay at all" is stricter than R4, and the never-included case
needs a chain that includes no honest transaction.

## Run

```sh
bugs/run.sh R1-A8-4
```

Takes about a second; no chain, no machine.

## Expected output on audit/prt2 (exit 1)

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
  tip 8, 11, 14, 17: published eliminateMatchByTimeout at nonce 0
  honest advanceMatch due from tip 9, window closes at block 20: NEVER published within its window
VIOLATED: R4: with every transaction included 6 blocks after publication, the honest advanceMatch must land before its deadline (block 20) although a cleanup of another match is pending (control: published at tip 9, lands in block 15; with the pending cleanup: published at tip 14, lands in block 20)
```

With a fix that keeps the pending job only when it expires no later than the earliest due job
(`job.key == candidate.job and job.last <= eligible[1].last` in `methods:tick`), `advanceMatch` replaces the cleanup
at nonce 0 at tip 9, lands in block 14, and the test exits 0. With that fix, `doc/recipes/prt-bridge-test.lua` also
exits 0. The reviewer checked both on a scratch copy.
