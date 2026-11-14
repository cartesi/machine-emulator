# R9-SUBJOURNAL-2: the PRT journal discards every attempt during which a block arrives

Component: `doc/recipes/prt-transactions.lua`, `methods:submit` (Support: PRT bridge/journal, standing in for
the honest operator's "Submitting transactions"). `submit` reads the latest block when it starts. It then
makes its RPCs (nonce, receipts, priority fee, `eth_call`, `eth_estimateGas`, balance) and signs with two
`cast` processes. At the end it runs

```lua
local _, current_hash = self.chain:head()
if current_hash ~= block.hash or not self.chain:is_canonical(observation.head, observation.hash) then
    return { waiting = true }
end
```

So any new block that arrives during the submit throws away the signed attempt. Nothing is stored or
published, even when the job's window is still open at the new tip and the observation is still canonical.
The bridge (crisium) retries only at the next tip, where the same race happens again. On a chain whose blocks
arrive faster than one submit takes, no move is ever published. `doc/recipes/prt-lua-bridge.md` (A tick, step
5) documents something different: "recheck that the observed block is canonical and the window is open, and
publish at most one transaction". It does not say the attempt is dropped whenever the tip moves.

## What the test asserts

`test.lua` starts a private anvil (port 28693, or `SUBJOURNAL2_PORT`) with manual mining. It runs the real
journal, the RPC client (`prt-rpc.lua`) and the cast signer (`prt-signer.lua`) on a transfer job whose window
`[0, 1000)` stays open for the whole test. To model a block arriving during the submit, the test mines one
empty block at a fixed point inside every submit, so the result does not depend on timing:

- **control**: no block is mined. The journal must publish at the first attempt. If it does not, the test
  reports a setup error and exits 2.
- **A**: one block is mined while the keystore signs. This is the case `prt-transactions-test.lua` already
  exercises, where it asserts the current behavior.
- **B**: one block is mined right after `eth_estimateGas`, before signing.

Required in A and B: within 5 attempts, each with a fresh observation, the job is published at nonce 0, and
the next block includes it with status 1.

Requirement (THREAT_MODEL R4, which section 2 places on the honest operator's path under "Submitting
transactions"): "The honest operator observes the chain and submits its transactions within the dispute
clocks." Section 1 counts an operator that "cannot respond in time" as a completeness failure.

A patched journal was checked with the test (scratch copy, not committed). The patch keeps the attempt when
the sampled block is still canonical, the window is open at the new tip, the nonce is unchanged and the
observation is still canonical. With it, A and B both publish at the first attempt and the test exits 0.

## Run

```sh
bugs/run.sh R9-SUBJOURNAL-2
```

Needs `anvil` and `cast` (the harness foundry in `PATH` through `bugs/env.sh`). Takes about 1 s.

## Expected output on audit/prt2 (exit 1)

```
control: 1 attempt(s): tip 0->0 published; published nonce 0, included in block 1 with status 1
A (block mined while signing): 5 attempt(s): tip 0->1 waiting, tip 1->2 waiting, tip 2->3 waiting, tip 3->4 waiting, tip 4->5 waiting; nothing published
B (block mined after eth_estimateGas): 5 attempt(s): tip 0->1 waiting, tip 1->2 waiting, tip 2->3 waiting, tip 3->4 waiting, tip 4->5 waiting; nothing published
VIOLATED: R4: ... (A, block while signing: never published; B, block after eth_estimateGas: never published)
run.sh: R9-SUBJOURNAL-2: exit 1 (bug present)
```

## Facts for the reviewer

- **Chains the recipe targets.** `prt-lua-bridge.md` says the recipe runs "on a local Anvil chain". It also
  says standalone players default to `finalized` and depth policies, and that "Confirmation delay,
  computation, RPC latency, and inclusion delay must together fit the windows the events give". It does not
  limit the block interval.
- **The test forces a block into every submit.** On a real chain the chance that a submit is dropped is
  about submit latency / block interval. The hunter measured this on a co-located anvil 1.5.1 with
  90 KB-calldata transfers and an average submit of 0.28 s:
  - with 0.25 s blocks, 24 of 30 submits were discarded;
  - with 1 s blocks, 2 of 20 were discarded.

  Remote RPC round trips and the heavier `eth_estimateGas` of a leaf proof make each submit take longer.
