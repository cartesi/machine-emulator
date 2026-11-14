# R5-INVBRIDGE-1: a join whose bond exceeds the signer's balance raises instead of being reported

**Component**: `doc/recipes/prt-transactions.lua` `methods:submit` (PRT player and bridge, Support, standing in
for the honest operator), reached by `prt-bridge.lua` `methods:attempt` for `joinTournament`, run by `crisium.lua`.

## What is asserted

`submit` preflights every job with `chain:simulate` (`eth_call` with `from` and `value`) and, on any failure whose
code is not 3 (an EVM revert), does `assert(failure.code == 3, "transaction preflight RPC failure")`
(lines 218-221). An `eth_call` whose `value` exceeds the sender's balance is not a revert: anvil answers code
-32003 "Insufficient funds for gas * price + value". So for a value-bearing job (only `joinTournament`, whose
value is the tournament bond) `submit` raises, and never reaches its own balance check (lines 254-265) that
returns the documented `{ blocked = "insufficient_funds" }`. That graceful branch is only reachable when
`value <= balance < value + gas * max_fee`. `crisium.lua` has no `pcall` around `tick`, so the error ends the
process; it ticks the newest sealed epoch (with its join) before the older epochs (whose jobs include
`tryRecoveringBond`).

The test (`test.sh` starts a private anvil on a random port; `check.lua` drives the unmodified recipe module):

* controls (must be graceful, otherwise exit 2): value 0 at balance 0; value 1 ETH at balance 1 ETH + 1 wei.
  Both return `blocked = "insufficient_funds"` on audit/prt2.
* cases under test: value 1 ETH at balance 1 ETH - 1 wei, and at balance 0. Required: `submit` returns
  `blocked = "insufficient_funds"` without raising and without publishing. Observed: it raises.

The destination is a payable stand-in (code `STOP`) so a funded call would succeed. No transaction is signed.

## Requirement

* `doc/recipes/prt-lua-bridge.md` anomaly table: "`insufficient_funds` | The account cannot pay a transaction's
  gas at its fee cap"; `prt-bridge.lua` `report_blocked`: "Reports a transaction the player cannot publish, once
  each time the reason changes. Observing continues."
* THREAT_MODEL R4 for the stood-in honest operator: it "observes the chain and submits its transactions within
  the dispute clocks" and "defends every epoch whose dispute is open".

## Run

    bugs/run.sh R5-INVBRIDGE-1

Needs anvil/cast from the harness (`bugs/harness/work/foundry/bin`, on PATH via `bugs/env.sh`). A few seconds.

## Expected output on audit/prt2 (exit 1)

    control (a) value 0, balance 0: returned blocked=insufficient_funds needed=126006000000000 available=0
    control (b) value 1 ETH, balance 1 ETH + 1 wei: returned blocked=insufficient_funds needed=... available=1000000000000000001
    case (c) value 1 ETH, balance 1 ETH - 1 wei: RAISED .../doc/recipes/prt-transactions.lua:220: transaction preflight RPC failure
    case (d) value 1 ETH, balance 0: RAISED .../doc/recipes/prt-transactions.lua:220: transaction preflight RPC failure
    preflight eth_call at balance 0: code=-32003 message=Insufficient funds for gas * price + value
    VIOLATED: ... a join whose bond exceeds the balance must be reported as blocked, not raise
    run.sh: R5-INVBRIDGE-1: exit 1 (bug present)

Once `submit` treats this preflight failure as a shortfall (for example by checking the balance against the value
before the preflight, or by mapping the node's insufficient-funds error to `blocked = "insufficient_funds"`), the
cases return the report and the test exits 0.
