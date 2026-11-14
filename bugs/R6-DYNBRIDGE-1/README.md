# R6-DYNBRIDGE-1: a retired epoch's transaction, resurrected by a shallow reorg, blocks the live epoch's moves

Component: PRT bridge `doc/recipes/prt-bridge.lua` `methods:tick` (retirement check, and the early return on another
epoch's pending candidate), with the real transaction journal `doc/recipes/prt-transactions.lua` (`pending` reads
the nonce at `latest`), run as `doc/recipes/crisium.lua` `pass()` runs it (newest epoch ticks first, finished
bridges dropped). Role: Support, standing in for the honest operator's transaction submission.

## What is asserted

`test.lua` drives two real bridges (epoch 1 settled, epoch 2 live) that share one real, file-backed journal, over
`fakechain.lua`, an in-process scripted node: per-block nonce and state, base fee, a mempool with 10% replacement
rules, reorgs. `prt-rpc.lua`'s own `head`, `is_canonical`, `simulate` and `publish` run on it. Only the bridges'
view of the contracts is scripted (`refresh`, `jobs`, `prepare`). Policies: dispute (observation) depth 4, input
(retirement) depth 8, finality 12 blocks deep.

The block script:

1. Epoch 1 is settled at block 5. Its permissionless post-settlement job (a bond recovery or cleanup) becomes due,
   and the honest copy C is published at tip 13.
2. Block 14 includes another party's identical call. C does not fit (full block). C is mined in block 15, after
   that call, as a no-op.
3. At tip 18 the observation head (block 14) shows the job done. The `latest` nonce is past C, so `pending()` has
   no candidate of epoch 1, and settlement block 5 <= tip-8. The epoch-1 bridge reports `finished`, and the pass
   drops it.
4. A 4-block reorg replaces blocks 15..18. It does not touch observation head 14, and it is within the input policy
   and finality. The replacing branch does not hold C, so the journal's `pending()` again returns C with
   `context.epoch = "1"`.
5. Epoch 2's move becomes due with inclusion window [40, 60). Required: it is mined inside the window.

Variants:

- `control` (setup check, exit 2 if it fails): the node re-injects C and mines it in the new branch. Epoch 2's move
  is mined at block 45.
- `drop`: the node does not re-inject the reorged C.
- `fee`: the node re-injects C, but the replacing branch's blocks are full of other parties' transactions, so the
  base fee rises 12.5% per block (EIP-1559) until it passes C's max fee (3 gwei) and then holds at 3.25 gwei. Raising
  chain activity is an adversary capability (THREAT_MODEL section 7).

In `drop` and `fee`, epoch 2's bridge returns early at every tick on "another epoch's pending transaction is left
alone until it is mined" (prt-bridge.lua, `candidate.context.epoch ~= tostring(self.epoch)`). No bridge of epoch 1
exists to cancel or replace C, so the move is never published. No error is raised, so nothing relaunches the player.

Requirement (THREAT_MODEL.md R4): "The honest operator observes the chain and submits its transactions within the
dispute clocks." and "The honest operator defends every epoch whose dispute is open, including while it processes
the inputs of later epochs." Section 4: "The honest operator acts only on history that its policy treats as final".
Here the retirement decision reads the `latest` nonce, while the journal itself notes "A reorg can resurrect every
nonce up to high_water".

Sanity check of the assertion, done out of tree (not part of the test): a copy of `prt-bridge.lua` in which an epoch
retires only once the journal holds no candidate of that epoch makes all three variants pass, so the test exits 0.
The epoch-1 bridge stays alive, cancels C after the reorg, and retires at tip 44. Epoch 2's move is mined at block 45.

Not covered: the `--keep-epochs=0` relaunch, which also stays stuck in the hunter's experiment because epoch 1 is
not reopened.

## How to run

```sh
bugs/run.sh R6-DYNBRIDGE-1
```

It takes under a second. It uses no chain, no anvil and no emulator machine, only the recipes' Lua modules from
`bugs/env.sh`. The journal lives in a `mktemp -d` directory, which the test removes.

## Expected output on audit/prt2

```
[drop]
  ...
  tip 18: epoch 1 bridge finished and dropped (crisium pass)
  after reorg, tip 18: pending e1-recover(epoch 1)@nonce 0, C in node pool: false
  tip 70: base fee 1.000 gwei, epoch-2 move window [40,60) mined at block nil, pending e1-recover(epoch 1)@nonce 0, bridges 1
[fee]
  ...
  tip 70: base fee 3.247 gwei, epoch-2 move window [40,60) mined at block nil, pending e1-recover(epoch 1)@nonce 0, bridges 1
VIOLATED: R4 (node drops the reorged epoch-1 transaction): the live epoch's move is mined within its window [40,60)
VIOLATED: R4 (reorged epoch-1 transaction re-injected but priced out): the live epoch's move is mined within its window [40,60)
run.sh: R6-DYNBRIDGE-1: exit 1 (bug present)
```
