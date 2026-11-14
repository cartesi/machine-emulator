## R9-SUBJOURNAL-2

**Title.** The PRT transaction journal throws away every signed attempt during which any new block arrives, even with the window open and the observation canonical. So when blocks come faster than one submit, the honest bridge never publishes.

**Severity.** Medium (preferred reading: a Support component standing in for a Critical R4 violation of the honest operator). Low under the alternative reading, in which the recipe supports only a quiet local Anvil chain and the ratio of block interval to submit latency is deployment sizing.

### Problem

`methods:submit` of the PRT transaction journal reads the latest block when it starts. It then makes about ten
sequential RPCs: the nonce, the receipts of every candidate of the job, `eth_maxPriorityFeePerGas`, `eth_call` of the
full action, `eth_estimateGas` and `eth_getBalance`. It also runs the keystore signer (`cast`). Only then does it run

```lua
candidate.raw, candidate.hash = signer:sign(candidate)
local _, current_hash = self.chain:head()
if current_hash ~= block.hash or not self.chain:is_canonical(observation.head, observation.hash) then
    return { waiting = true }
end
```

So if the tip moved at all while it worked, the whole attempt is discarded. Nothing is stored and nothing is published.
That happens even when the job's window `[first, last)` is still open at the new tip, and even when the caller's
observation is still canonical. The bridge (`prt-bridge.lua` `attempt`) and the player loop (`crisium.lua`) try again
only at the next tip, where the same race starts over. When the block interval is shorter than one submit, essentially
every attempt is discarded, and the honest player never publishes any move: no join, no bisection step, no leaf proof.
When the interval is about as long as a submit, each publication, including every fee bump, takes a random, geometric
number of blocks.

This threatens the goal of section 1 through completeness: "The honest operator ... cannot respond in time. If the
honest claim is eliminated, a dishonest claim can win." The recipe's own documentation describes the step differently.
`doc/recipes/prt-lua-bridge.md`, "A tick", step 5, says: "recheck that the observed block is canonical and the window is
open, and publish at most one transaction". It does not say that any tip change drops the attempt. The strict equality
is not needed for safety. The window and canonicality can be rechecked at the new tip, and a stale publication can at
worst revert. The journal's own test asserts the current behavior (`doc/recipes/prt-transactions-test.lua` 365-378:
"A live tip change while the keystore signs invalidates the attempt").

### Component, role and area

The PRT transaction journal `doc/recipes/prt-transactions.lua`, as used by the PRT bridge `doc/recipes/prt-bridge.lua`
and the player `doc/recipes/crisium.lua`. AUDIT.md role: "The PRT player and bridge in `doc/recipes` ... | Support. No
production deployment runs the player, the bridge or the CLI." The journal is the bridge's transaction layer, so this
clause covers it. It stands in for the honest operator's step "Submitting transactions" (THREAT_MODEL section 2,
honest operator's path). Area: freshness checks of a transaction attempt before publication.

### Location

- `doc/recipes/prt-transactions.lua`, `methods:submit`: line 161 reads the latest block at entry, line 266 signs, and
  lines 267-270 discard the attempt on any change of the latest block hash.
- `doc/recipes/prt-bridge.lua`, `methods:attempt` (around 641-669) checks the window at the tip and then calls `submit`.
- `doc/recipes/crisium.lua`, main loop (around 355-381): after a `waiting` result, it passes again at the next tip.
- `doc/recipes/prt-transactions-test.lua` 365-378 asserts the discard.
- `doc/recipes/prt-lua-bridge.md`, "A tick", step 5 (line 422).

### Evidence and test

`bugs/R9-SUBJOURNAL-2/` contains `test.lua` (the test) and `README.md` (the prover's notes). Run it with
`bugs/run.sh R9-SUBJOURNAL-2`. It needs `anvil` and `cast`, which `bugs/env.sh` puts on `PATH` from the harness
foundry, and takes about 1 s. It starts a private anvil on port 28693 (set `SUBJOURNAL2_PORT` to change it) with manual
mining. It runs the real journal, the RPC client (`prt-rpc.lua`) and the cast signer (`prt-signer.lua`) on a transfer
job whose window `[0, 1000)` stays open for the whole test. To model a block arriving during a submit, so that the
result does not depend on timing, it mines one empty block at a fixed point inside every submit:

- control: no block. The journal must publish at the first attempt, or the test exits 2 as a setup error;
- A: one block is mined while the keystore signs;
- B: one block is mined right after `eth_estimateGas`.

In A and B, the test requires that within 5 attempts, each with a fresh observation, the job is published at nonce 0
and the next block includes it with status 1. The anvil process and its temporary directory are removed at the end.

On audit/prt2 it prints, identically on three runs by the reviewer (exit 1 each time):

```
control: 1 attempt(s): tip 0->0 published; published nonce 0, included in block 1 with status 1
A (block mined while signing): 5 attempt(s): tip 0->1 waiting, tip 1->2 waiting, tip 2->3 waiting, tip 3->4 waiting, tip 4->5 waiting; nothing published
B (block mined after eth_estimateGas): 5 attempt(s): tip 0->1 waiting, tip 1->2 waiting, tip 2->3 waiting, tip 3->4 waiting, tip 4->5 waiting; nothing published
VIOLATED: R4: with the job's window [0, 1000) open and the observation canonical, a block arriving during each submit must not stop the journal from publishing within 5 attempts (A, block while signing: never published; B, block after eth_estimateGas: never published)
run.sh: R9-SUBJOURNAL-2: exit 1 (bug present)
```

The prover tested a scratch patch that is not committed. It keeps the attempt when the sampled block is still
canonical, the window is open at the new tip, the nonce is unchanged and the observation is still canonical. With it,
the test exits 0.

The reviewer also checked an adversary-driven variant in a scratch script, which is not part of the test. It used
anvil in its default automine mode, the configuration of `prt-demo.sh`'s `run_anvil`, which has no `--block-time`.
Another account sent plain value transfers in a loop with `cast send --async`, and every transfer mined its own block.
All 10 consecutive journal submits returned `waiting` (tips 95->99, 99->102, ... 126->130), and nothing was published.
Without that traffic, the first submit published. The hunter measured the rate on interval-mined anvil without an
adversary: with 0.25 s blocks, 24 of 30 submits were discarded, and with 1 s blocks, 2 of 20 were.

Found, proved and reviewed by Opus 5.5. No fallback model was used.

### Trigger and reachability

The defect triggers whenever a block arrives between the start of a submit and the check after signing. Three
conditions make that happen on every attempt:

- a chain whose block interval is below the submit latency, such as a sub-second chain or a 1-2 s chain reached
  through a remote RPC provider, where each of the roughly ten sequential round trips adds latency, and a leaf proof
  makes `eth_call` and `eth_estimateGas` heavier;
- on an automining chain, such as the recipe's own Anvil setup, any party that sends transactions faster than one
  submit. Section 7 lets the adversary "Raise activity on the chain that does not belong to the application" and
  "Race and reorder transactions within the chain's rules". A dishonest claimant's own moves also mine blocks there;
- the adversary can also lengthen each submit by steering the dispute to a heavy leaf proof (section 7: "Steer the
  dispute to any position of the honest computation").

No particular machine state is needed. Any job of the honest player, at any position reached from any valid template,
is affected.

### Rating

1. Out of scope: no exclusion applies. The trigger is the chain's block cadence, or other parties' transactions, not
   an excluded condition. It is not "Reorganizations of the chain deeper than the operator's input policy", because no
   reorg occurs and the observation stays canonical. It is not "Host faults". It is not censorship: section 7 says
   "The adversary is not assumed ... to censor the chain beyond the dispute clocks", but here the chain would include
   the transaction, and the operator never sends it. It is not "Average-case performance that does not change the
   worst-case cost of any operation listed in R12": the worst case is that the move is never sent, and submitting is
   not an R12 emulator operation. It needs no violation of A1 to A8. The scope note of AUDIT.md excludes the test
   harnesses (`*-test.lua`) but not `prt-transactions.lua`.
2. Role: the journal is part of "The PRT player and bridge in `doc/recipes`", which AUDIT.md rates "Support. No
   production deployment runs the player, the bridge or the CLI." That clause covers this component. Section 3: "A
   defect that only a support component shows is Medium when it would rate High or Critical in the role the component
   stands in for, such as ... the honest operator for an implementation of an operator". The settled reading that
   applies is: "When a Support component (the PRT player, the CLI) fails on its own operator path, rate it under
   section 3's stand-in rule". The stood-in role is the honest operator, on its path's step "Submitting transactions"
   (section 2).
3. High and Medium cases: in the stood-in role, none of the listed High or Medium cases fits. The defect does not
   concern an unreachable state, a verifier, a constant-factor cost of an R12 operation, data the operator may decline,
   or a loud persistence failure. For the support component itself, the Medium case "A defect that only a support
   component shows, when section 3 rates it Medium" applies once step 4 gives Critical in the stood-in role.
4. Critical (in the stood-in role): R4: "The honest operator observes the chain and submits its transactions within
   the dispute clocks." It also violates section 1's premise that the honest operator responds in time ("Completeness
   failure ... cannot respond in time"). The state is reachable, since every honest job is affected and the trigger is
   the chain cadence or other parties' traffic. In the honest-operator role this would be Critical. Under the section 3
   stand-in rule, the support component is Medium.

Alternative reading: Low. This reading treats the recipe as supporting only the demo's quiet, harness-mined Anvil
(`prt-lua-bridge.md`: "the same players against the real contracts, on a local Anvil chain"; "Anvil mines submitted
transactions immediately, and the harness mines the rest"). It also treats the block-interval-to-latency ratio as
deployment sizing (`prt-lua-bridge.md`: "Confirmation delay, computation, RPC latency, and inclusion delay must together
fit the windows the events give"). Three facts weigh against it. The threat model limits neither block cadence nor
chain choice. On a chain whose interval is below the submit latency, the delay is unbounded, not a fixed latency that
sizing could absorb. And on the recipe's own automining Anvil, an adversary's transaction traffic triggers it. Two facts
would decide: whether the recipes claim support for chains other than a harness-mined Anvil (standalone `crisium`
defaults to `finalized` and four-block policies, which suggests they do), and whether sizing under A7 may assume a
bound on how often new blocks arrive relative to the operator's submit latency.

### Possible solution and risks

Do not require the tip to be unchanged. After signing, accept the attempt when all of these hold:

- the block the attempt was built on is still canonical, or the new tip descends from it;
- the job's window is still open at the new tip plus one (`tip + 1 >= first` and `tip + 1 < last`);
- the account's nonce at the new tip still equals the candidate's nonce;
- the observation is still canonical.

Only then store and publish. Fee fields computed from the older block stay valid for the next blocks, within the
journal's ceilings. A bounded number of in-call retries is another option.

Risks: a publication based on a slightly older simulation can revert if the contract state changed in the new block.
That costs gas, and the journal already handles reverted receipts. Deciding whether a changed nonce means a reorg or
outside consumption must keep the journal's exclusive-account asserts. `prt-transactions-test.lua` 365-378 asserts the
current behavior and would need to change.

### Risk of not fixing it

Anyone who runs the recipe's player and bridge on a chain with blocks faster than one submit (about 0.3 s locally,
more through a remote provider) publishes few or no honest moves. Any claim can then beat the honest claim by
timeout. On an automining chain, any account that sends transactions in a loop has the same effect. On slower chains,
each publication and each fee bump is delayed by a random number of blocks, which eats into the honest claim's clock.
Production deployments do not run this code, but the recipe is a reference implementation of an operator, and a node
modelled on it would inherit the livelock. Until it is fixed, operators can run the player only on chains whose block
interval is well above the submit latency, with a co-located RPC node.
