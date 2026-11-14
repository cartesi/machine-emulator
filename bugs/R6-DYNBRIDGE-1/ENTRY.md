## R6-DYNBRIDGE-1

**Title.** The PRT bridge retires a settled epoch based on the `latest` nonce. A reorg shallower than both policies
brings back that epoch's last transaction with no bridge left to own it, and every live epoch's bridge waits on it, so
the live dispute's moves are never sent.

**Severity.** Medium (preferred reading: a Support component standing in for a Critical R4 failure of the honest
operator). Under the other reading, where section 4's pre-finality sentence covers a shallow reorg of the operator's
own transaction, it is Out of scope.

### Problem

`methods:tick` in `doc/recipes/prt-bridge.lua` marks a settled epoch `finished` when three things hold: it has no jobs
at the observation head, `transactions:pending(signer)` returns no candidate of this epoch, and the settlement block is
at or below `head(retirement_policy)`. `pending()` (`doc/recipes/prt-transactions.lua`) finds the current candidate
from `eth_getTransactionCount` at `latest`. So the retirement check treats the epoch's last transaction C as done once
C is mined in any block, even an unconfirmed one. Only the settlement block has to be irreversible. `crisium.lua`
`pass()` then drops the finished bridge, with its listener and player.

The journal keeps every nonce until it has a receipt at or below both the finalized block and the observation head.
Its own comment says "A reorg can resurrect every nonce up to high_water". If a shallow reorg removes C's block and C
is not mined again, `pending()` again returns C, with `context.epoch` set to the retired epoch. Every live epoch's
bridge then hits this early return on every tick:

```lua
if candidate.context and candidate.context.epoch ~= tostring(self.epoch) then
    return snapshot, false, next_block
end
```

The bridge that could cancel or outbid C no longer exists. The live epoch's joins, bisections and proofs are never
sent. No error is raised, so nothing relaunches the player. The honest claim then loses its live matches by timeout,
and the honest operator fails to defend an epoch whose dispute is open. That is a completeness failure (section 1),
shown here by the Support bridge standing in for the honest operator.

### Component, role and area

PRT bridge in `doc/recipes`, together with its transaction journal and the `crisium.lua` pass that drives it. Role:
Support. AUDIT.md: "The PRT player and bridge in `doc/recipes`, ... | Support. No production deployment runs the player,
the bridge or the CLI." It stands in for the honest operator's path steps "Observing the chain" and "Submitting
transactions". Area: retiring an epoch, and sharing the signer's nonce across epochs.

### Location

- `doc/recipes/prt-bridge.lua` `methods:tick`. Lines 702-710 hold the retirement check: `pending()` plus
  `head(retirement_policy)` for the settlement block only. Lines 720-727 hold the early return on another epoch's
  pending candidate.
- `doc/recipes/prt-transactions.lua`. `methods:nonce` (line 34) defaults to `"latest"`. `methods:pending` (line 91)
  uses it. Line 81 holds the comment about reorgs.
- `doc/recipes/crisium.lua` `pass()` (line 295). Line 318 onward drops finished epochs. `doc/recipes/prt-epoch.lua`
  line 128 passes `retirement_policy = self.input_policy`. The default input policy is `finalized`, and the default
  dispute (observation) policy is 4 (`crisium.lua` lines 76-77).

### Evidence and test

`bugs/R6-DYNBRIDGE-1/` contains:

- `test.lua`, the test.
- `fakechain.lua`, an in-process scripted node. It keeps a nonce and contract state per block, a base fee, a mempool
  with 10% replacement rules, finality and reorgs, and its RNG is fixed.
- `README.md`, the scenario.

The test drives two real `prt-bridge` instances (epoch 1 settled, epoch 2 live). They share one real, file-backed
`prt-transactions` journal, and `prt-rpc`'s own `head`, `is_canonical`, `simulate` and `publish` run against the node.
Only each bridge's view of the contracts (`refresh`, `jobs`, `prepare`) is scripted. The ticks follow `crisium.lua`
`pass()`: newest epoch first, finished bridges dropped. The policies are observation depth 4, retirement depth 8, and
finality 12 deep.

The script runs as follows:

1. Epoch 1 settles at block 5. A permissionless post-settlement job (such as `tryRecoveringBond`) becomes due, and
   the honest copy C is published at tip 13.
2. Another party's identical call is included in block 14. C is mined in block 15 as a no-op.
3. At tip 18 the epoch-1 bridge retires and is dropped.
4. A 4-block reorg replaces blocks 15 to 18. That is within both policies and above the observation head, block 14.
5. Epoch 2's move must be mined inside its window [40, 60).

The test runs three variants:

- `control`: the node mines C again. The test exits 2 if this variant fails.
- `drop`: the node does not re-inject C.
- `fee`: the replacing blocks are full, so the base fee rises 12.5% per block past C's 3 gwei max fee and then holds
  at 3.25 gwei.

Run `bugs/run.sh R6-DYNBRIDGE-1`. It takes under a second and needs no chain or emulator machine. On audit/prt2 it
prints, in part:

```
[drop]
  tip 18: epoch 1 bridge finished and dropped (crisium pass)
  after reorg, tip 18: pending e1-recover(epoch 1)@nonce 0, C in node pool: false
  tip 70: base fee 1.000 gwei, epoch-2 move window [40,60) mined at block nil, pending e1-recover(epoch 1)@nonce 0, bridges 1
[fee]
  after reorg, tip 18: pending e1-recover(epoch 1)@nonce 0, C in node pool: true
  tip 70: base fee 3.247 gwei, epoch-2 move window [40,60) mined at block nil, pending e1-recover(epoch 1)@nonce 0, bridges 1
VIOLATED: R4 (node drops the reorged epoch-1 transaction): the live epoch's move is mined within its window [40,60)
VIOLATED: R4 (reorged epoch-1 transaction re-injected but priced out): the live epoch's move is mined within its window [40,60)
run.sh: R6-DYNBRIDGE-1: exit 1 (bug present)
```

The control mines the epoch-2 move at block 45. The test exited 1 in each of 4 runs by the reviewer.

Two further checks were made out of tree; neither file is part of `bugs/`:

- **The test passes once the retirement check is fixed.** The reviewer patched a copy of `prt-bridge.lua` so that an
  epoch retires only when the journal holds no candidate of that epoch at any outstanding nonce, first_nonce to
  high_water. With it, all three variants pass and the test exits 0. The epoch-1 bridge stays alive, cancels C after
  the reorg, and retires at tip 44, and the epoch-2 move is mined at block 45.
- **The default retirement policy fails too.** With the retirement policy set to crisium's default `"finalized"`
  instead of 8, the test still exits 1.

Found, proved and reviewed on Opus 5.5. No fallback model was used.

### Trigger and reachability

These conditions have to coincide:

- **The epoch's last own transaction is above the observation head when the job disappears.** Epoch X is settled, and
  its last own transaction C, a permissionless post-settlement call such as `tryRecoveringBond` (anyone may call it),
  is mined above the observation head. Meanwhile the job has already vanished at the observation head, because
  another party's identical call landed first. Anyone can make that call, and the adversary may "Race and reorder
  transactions within the chain's rules" (section 7).
- **A shallow reorg removes C.** A reorg that leaves the observation head alone, and so is shallower than both the
  dispute policy and the input policy, removes C's block. This is ordinary chain behaviour that the operator's
  policies exist to tolerate.
- **C is not mined again before the live epoch's deadlines.** Either the node does not re-inject it (mempool eviction
  or a node that drops reorged transactions), or the base fee stays above C's max fee. The adversary may "Raise
  activity on the chain that does not belong to the application" (section 7). The live moves themselves would be
  repriced by the journal, but C has no owner left to reprice it.

The stall lasts until C is mined, which in the `drop` variant never happens, or until a manual relaunch reopens epoch
X. The hunter observed that a relaunch with `--keep-epochs=0` does not reopen it. No guest state is involved, so the
trigger is reachable from any valid template that has at least two epochs with a dispute.

### Rating

1. **Out of scope: not excluded.** Section 8 excludes "Reorganizations of the chain deeper than the operator's input
   policy (section 4)". This reorg is shallower than both the input policy and the dispute (observation) policy, and
   step 1 says "Check the trigger, not the symptom". Section 4 says "The honest operator acts only on history that its
   policy treats as final ... Acting on history before it is final, and recovering when that history is replaced, is
   outside this model." The bridge's retirement decision is exactly such premature action: it relies on C's
   unconfirmed inclusion through the `latest` nonce. In the stood-in role this is a deviation from what the honest
   operator does, not a chain failure. No other exclusion applies. The chain does not censor: the live move is never
   sent. The node's behaviour is ordinary mempool behaviour, and the `fee` variant needs no node fault at all.
2. **Role: Support.** AUDIT.md rates the PRT bridge "Support. No production deployment runs the player, the bridge or
   the CLI." Section 3: "A defect that only a support component shows is Medium when it would rate High or Critical
   in the role the component stands in for, such as ... the honest operator for an implementation of an operator."
   This clause covers the bridge. It implements the honest operator's "Observing the chain" and "Submitting
   transactions" (section 2, "Honest operator's path"). Step 2: "A defect that only a support component shows is
   never above Medium."
3. **High and Medium cases: the stand-in rule fits.** Section 8 Medium lists "A defect that only a support component
   shows, when section 3 rates it Medium." In the stood-in role, no High case fits. The defect is not a verifier
   issue, not an unreachable-state issue, not caused by data the operator may decline, and not a constant-factor cost.
4. **Critical in the stood-in role.** R4: "The honest operator observes the chain and submits its transactions within
   the dispute clocks" and "The honest operator defends every epoch whose dispute is open, including while it
   processes the inputs of later epochs." Both are violated on the honest operator's path. The live epoch's moves are
   never submitted, so the honest claim loses by timeout and a dishonest claim can win (section 1, "Completeness
   failure ... cannot respond in time"). That would be Critical in the honest-operator role, so section 3 rates the
   Support component Medium.

**Two readings.**

- **Reading A (preferred):** Medium. Section 8's exclusion names only reorgs deeper than the input policy, and
  section 4's first sentence describes how the honest operator behaves, which the bridge fails to follow.
- **Reading B:** Out of scope. Section 4's last sentence ("Acting on history before it is final, and recovering when
  that history is replaced, is outside this model") excludes recovery from any shallow reorg that replaces a
  transaction the operator already sent.

The deciding question is whether that sentence excludes failures that follow from an operator implementation acting
on non-final history, or only means that an honest operator never needs such recovery. A further fact would also
decide: if submitted transactions are taken to be part of the history the operator "acts on" before finality,
reading B also covers the journal's whole reorg handling, which the journal explicitly implements.

### Possible solution and risks

- **Retirement fix.** Retire an epoch only when the journal holds no candidate of that epoch at any outstanding
  nonce, from first_nonce to high_water, so that only `forget_settled` (receipt at or below finality and the
  observation head) releases it. Alternatively, read the nonce for the retirement check at
  `head(retirement_policy)` instead of `latest`. Risk: a settled epoch's bridge and player stay alive a few blocks
  longer, as far as finality, which delays `--keep-epochs` file removal.
- **Ownership fix.** Let a live bridge adopt or cancel a pending candidate whose epoch has no live bridge. This also
  covers candidates left by a restart that does not reopen the epoch. Risk: a live bridge could cancel a settled
  epoch's still-useful bond recovery, which costs the bond recovery transaction, not the dispute.

### Risk of not fixing it

An operator running the recipes' player (crisium) can stop defending a live epoch without any error. The trigger
needs another party to race a permissionless post-settlement call, a reorg shallower than the observation depth, and
C not being mined again, through mempool eviction or a sustained base-fee rise. Every live move is then held back, and
the honest claim loses its matches by timeout. No production deployment runs the bridge, so the exposure is limited
to demonstrations and to anyone who copies its retirement logic into a real node. Outside the code, an operator can
mitigate it by relaunching with epochs kept, or by watching for a pending candidate of an epoch that is no longer
observed.
