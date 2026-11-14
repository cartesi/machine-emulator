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

Three scenarios:

1. control: the cleanup becomes eligible on the same tick the honest move becomes due (tip 9) with nothing pending:
   the bridge publishes `advanceMatch` at tip 9 (setup check; exit 2 if not).
2. the cleanup became eligible one block earlier (tip 8), so it is pending when the honest move becomes due, and
   the chain includes it 6 blocks after publication;
3. same, but the cleanup is not included before the honest deadline (congestion, fee ceiling, dropped from the
   pool).

Required in 2 and 3: `advanceMatch` is published at tip 9, as in the control (replacing the cleanup at the same
nonce). On audit/prt2 the bridge keeps the pending cleanup ("Keep working on a useful pending action"), never
attempts `advanceMatch` while the cleanup is pending, and only re-prices the cleanup every `bump_blocks`.

Requirement (THREAT_MODEL.md): R4 "The honest operator observes the chain and submits its transactions within the
dispute clocks." and A8 "Failing to process one match's data, for any reason, must not stop, delay or decide any
other match." (as the standard of the honest operator that the bridge stands in for).

## Run

```sh
bugs/run.sh R1-A8-4
```

Takes about a second; no chain, no machine.

## Expected output on audit/prt2 (exit 1)

```
control (no pending cleanup):
  tip 9: published advanceMatch at nonce 0
pending cleanup, included 6 blocks after publication:
  tip 8: published eliminateMatchByTimeout at nonce 0
  tip 11: published eliminateMatchByTimeout at nonce 0
  tip 14: published advanceMatch at nonce 1
pending cleanup, not included before the honest deadline:
  tip 8, 11, 14, 17: published eliminateMatchByTimeout at nonce 0
  honest advanceMatch ... NEVER published within its window
VIOLATED: A8/R4: a pending cleanup of another match must not delay the honest advanceMatch (control published at tip 9, with the pending cleanup at tip 14)
VIOLATED: R4: the honest advanceMatch must be published within its window although a cleanup is pending (control at tip 9, with a stuck cleanup: never)
```

With a fix that keeps the pending job only when it expires no later than the earliest due job (for example,
`job.key == candidate.job and job.last <= eligible[1].last` in `methods:tick`), the test exits 0 and
`doc/recipes/prt-bridge-test.lua` still passes (checked by the prover on a scratch copy).
