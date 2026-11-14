# R3-VARSCHED-2: the PRT journal cannot re-price a pending move at the priority cap

Component: `doc/recipes/prt-transactions.lua`, `methods:fees` (lines 140-154) and `methods:submit` (192-211), the
transaction journal that `prt-bridge.lua` / `crisium.lua` use. AUDIT.md gives it the Support role, standing in for the
honest operator's "Submitting transactions".

## What is asserted

The test runs the real journal against a mock chain. The mock never includes the account's transactions, keeps every
candidate in its pool, and lets the test set the base fee and the node's `eth_maxPriorityFeePerGas`. The journal uses
its defaults (bump every 3 blocks by 15%, priority 1 to 10 gwei, `--max-fee` 100 gwei).

- **A.** The move is first signed with the node suggesting a 10 gwei tip at a 10 gwei base fee. It gets max fee 30
  gwei and priority 10 gwei, which is the cap.
- **B.** The move is first signed at a 1 gwei tip on a 1 gwei base fee. Racing transactions out-tip it, so the
  journal's own 16 bumps raise its priority to 9.358 gwei and its max fee to 28.07 gwei. The next 15% bump would pass
  the cap.

In both scenarios the base fee then rises to 40 gwei. That is above the pending candidate's max fee and well below
`--max-fee`. The test asserts that the next `submit` publishes a replacement at the same nonce (nonce 0) that meets
all of these:

- max fee >= base fee + priority, so the chain can include it;
- max fee <= `--max-fee`;
- both fees at least 10% above the old candidate's, which is the pool's replacement price bump.

The priority cap is deliberately not asserted. A same-nonce replacement must raise the priority, so no fix can keep
a candidate that is already at the cap under it.

On `audit/prt2`, `fees()` returns nil whenever `ceil(prev.priority * 1.15) > max_priority_fee`, even when the needed
max fee fits. `submit` then answers `{ blocked = "fee_ceiling" }`. The honest move stays stuck at its signing-time max
fee, cannot be included while the base fee stays above it, and holds the nonce, which blocks every later move.

## Requirement

THREAT_MODEL.md R4: "The honest operator observes the chain and submits its transactions within the dispute clocks."
Section 7 lets the adversary "Raise activity on the chain that does not belong to the application" and "Race and
reorder transactions within the chain's rules". Whether fee-market non-inclusion within the operator's configured
budget falls under the goal's assumption "the chain includes its transactions within the dispute clocks" is for the
reviewer to decide.

## Run

```sh
bugs/run.sh R3-VARSCHED-2
```

It takes under a second and needs no emulator, chain or network, only `bugs/env.sh`'s Lua paths.

## Expected output on audit/prt2 (exit 1)

```
A: pending candidate at nonce 0: max fee 30.000 gwei, priority 10.000 gwei
A: tip 13, base fee 40 gwei (candidate unincludable; --max-fee 100 gwei leaves room): not re-priced: fee_ceiling -> VIOLATION
B: 16 bumps raised the priority to within 15% of the cap
B: pending candidate at nonce 0: max fee 28.073 gwei, priority 9.358 gwei
B: tip 61, base fee 40 gwei (candidate unincludable; --max-fee 100 gwei leaves room): not re-priced: fee_ceiling -> VIOLATION
VIOLATED: R4 ...
run.sh: R3-VARSCHED-2: exit 1 (bug present)
```

The fix was checked with a patched copy of the journal, loaded first through `LUA_PATH_5_4` without touching the
tracked file. The patch applies the priority cap only to a first candidate. With it, both scenarios re-price (A: max
fee 90 gwei, priority 11.5 gwei; B: max fee 81 gwei, priority 10.76 gwei) and the test exits 0.
