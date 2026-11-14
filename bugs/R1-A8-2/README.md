# R1-A8-2: a leaf-proof check failure in one match crashes the PRT bridge, so no other match is processed

## What is asserted

`doc/recipes/prt-bridge.lua` `methods:attempt` checks a `winLeafMatch` proof twice: natively (`proof_check`
from `prepare`) and by simulating the Solidity call (`chain:simulate`). Two bare asserts follow, outside any
`pcall`:

```lua
assert(not failure or failure.code == 3, "proof simulation RPC failure")
assert(transaction.proof_check.valid == (failure == nil), "native and Solidity transition verification disagree")
```

The error goes up through `tick()`. `crisium.lua` `pass()` calls every epoch's `tick` in one loop, without any
`pcall`, so the error ends the player process. The bridge rebuilds the same job from the chain after a restart,
so it raises the same error again.

The test runs the unchanged bridge, with its real `jobs()`, `tick()` and `attempt()`. It mocks only what lies outside
the bridge, the same way `doc/recipes/prt-bridge-test.lua` does: `observe`, the chain RPC, the journal's `submit` and
`prepare`. The one tournament holds two matches:

- `leaf`: a `LeafMatchSealed` match of the bridge's own commitment, where `winLeafMatch` is due;
- `other`: a match between two other commitments, whose permissionless `eliminateMatchByTimeout` is due.

There are three scenarios for the leaf proof:

1. The native check accepts and the Solidity simulation reverts (code 3).
2. The native check rejects and the simulation accepts.
3. The simulation gets a non-revert RPC error (`-32000`).

In each scenario the bridge is ticked 6 times. The test **requires** that no tick raises and that the other match's
elimination is submitted. A second fresh bridge over the same state stands in for the relaunched player. Its result is
printed and is not asserted separately.

The test does not show that a native/Solidity disagreement can happen at a reachable state. The disagreement is mocked.
The finding is that any such failure, or an RPC error, in one match stops every other match.

## Requirement

THREAT_MODEL.md, A8: "Failing to process one match's data, for any reason, must not stop, delay or decide any other
match." R4: "After a stop, it restarts from a directory that O2 guarantees and keeps defending its claim." The bridge is
Support (AUDIT.md) and stands in for the honest operator.

## Run

```sh
bugs/run.sh R1-A8-2
```

This needs only the in-tree build (no chain). It runs in under a second.

## Expected output on audit/prt2 (exit 1)

```
scenario: native accepts, Solidity simulation reverts (code 3)
  ticks: 6, raised: 6, leaf simulations: 6, submitted: [], anomalies: []
  first error: .../doc/recipes/prt-bridge.lua:632: native and Solidity transition verification disagree
  other match's elimination submitted: false; after a restart (fresh bridge): raised 6, submitted false
  VIOLATION
scenario: native rejects, Solidity simulation accepts
  ... prt-bridge.lua:632: native and Solidity transition verification disagree ... VIOLATION
scenario: proof simulation answered by a non-revert RPC error
  ... prt-bridge.lua:631: proof simulation RPC failure ... VIOLATION
VIOLATED: A8: failing to process one match's leaf proof must not stop the bridge from processing another match
```

A copy of the bridge was patched to mark the job invalid and report an anomaly instead of asserting. The original
file was not changed. With that copy the test exits 0, and all three scenarios submit the other match's elimination.
