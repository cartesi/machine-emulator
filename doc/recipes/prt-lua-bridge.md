# Lua PRT bridge implementation plan

The goal is to simplify the implementation of validator nodes. Dave's
Permissionless Refereed Tournaments (PRT) resolve competing claims about machine
execution by narrowing a disagreement until a state-transition proof can settle
it. The contracts define and enforce the dispute rules. Their events should
provide enough information for a validator to participate with minimal context,
without reconstructing the dispute's entire state or reproducing the contracts'
internal logic.

An additional goal is for events to translate into what amounts to a remote
procedure call into the validator node. The request means "as soon as the chain
reaches this eligible block, call this contract with this context and the
additional information produced by off-chain machine execution." The fixed
translation supplies the target and method, the event supplies the relevant
context and timing, and the validator computes the missing claim data or proof.
The validator queues the call until it becomes eligible. Any expiry limits how
long the call remains eligible.

An event can also mean "cancel this previously scheduled call." Later events
can replace work as a dispute progresses. Expressing participation through
these scheduling and cancellation operations lets the node respond directly
to the contract's events with the information it computes off chain.

The contracts retain authority over pairing, clock accounting, result selection,
and whether a submitted move is valid. Their events expose the identities,
coordinates, and deadlines needed for the next action. For example, a match
advance identifies the claims, the tree node to open, and the response window.
The validator can compute that opening directly, without replaying earlier
moves to reconstruct the match. This keeps dispute complexity where it is
unavoidable and avoids implementing another copy in each validator.

The node retains its own claims and computation resources, a few identity
associations, and a work queue containing the context supplied by events.
Cached blockchain events allow the work queue to be rebuilt after a reorg.
If the validator program stops or crashes and is launched again, it can rebuild
its queue from blockchain events. Records of submitted transactions let it check
which were mined and which remain pending before sending again.

These goals apply whether the validator is a single program or several
components. The event interface does not require a bridge/player separation.

Our implementation uses that separation to connect the existing player in the
machine-emulator documentation to the real blockchain. The Lua bridge and that
player together form one validator node.

```text
Dave events and block heads <-> Lua bridge <-> Lua player
                                     |
                                     +-> signed transactions
```

The player owns the computation. Given the initial machine state and inputs,
it executes the machine, builds computation hash trees, and answers requests for
claims, tree nodes, and proofs. In the documentation, a simulated referee asks
for these values. Our bridge sends ordinary computation requests to the same
player handlers. The player does not track contract addresses, chain heads,
deadlines, or reorgs.

Our bridge owns the work queue and all block scheduling. It translates events
into jobs using the fixed conversion table. When a job becomes eligible, it
requests any needed player computation, assembles and simulates the contract
call, and submits the transaction. It also handles chain access, signing, and
transaction tracking. A reorg rebuilds the queue while reusable in-flight player
computations continue. If the bridge process stops or crashes and is launched
again, it reconstructs the queue and checks its recorded transactions before
sending further transactions. Neither component maintains a parallel model of
the tournament's internals.

The companion [contract requirements](prt-lua-bridge-needs.md) specify the
event fields needed to make this design possible and the fixtures that check
them. Both documents describe work to implement.

The first milestone runs one honest player through the root and leaf
tournaments of the two-level geometry, from EpochSealed to a staged root tournament
result and recovered bonds. Sentries, several applications, and several
signers are out of scope. The bridge imports no code, state model, or fixtures
from other Dave clients. Contract tests supply event, view, and calldata
fixtures. The documentation simulator keeps its existing scheduling model.

## Prerequisites

Pin the Dave commit, deployment, chain ID, consensus and factory addresses,
ABI hash, event/view/calldata fixtures, supported cast version, and signer
configuration together.
Live integration requires all fields in the companion event proposal. The
match rows need the proposed ordered pairs, heights, and deadlines as well as
the result rows needing StandingChanged. We can test the bridge with example
events and expected contract calls before the updated contracts are deployed.
TournamentCreated and NewInnerTournament must carry the complete descriptor
and bond value. The bridge obtains these values from creation events and makes
no tournamentDescriptor() or bondValue() calls.

Validate the factory's complete tournament table when pinning the deployment,
before asking the player to compute a root claim or submitting a join. Read
tournamentLevelCount() once and require two levels. Then read
tournamentParameters(0) and tournamentParameters(1) once, for the root and leaf
tournaments respectively. The table calls the stride exponent log2step, which
corresponds to log2Stride in creation events.

- Both parameter rows must report levels equal to two.
- The root tournament's height plus log2step must equal 92.
- The leaf tournament's log2step must be zero.
- The leaf tournament's height must equal the root tournament's log2step.
- Both heights must be below 63, so the player's leaf counts fit in signed
  64-bit integers.

The exact heights and strides remain a deployment choice. Derive the player's
mcycle period exponent from the validated root tournament log2step minus
ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE. Require each creation event's height,
log2Stride, level, and kind to agree with that table, with a non-leaf root
tournament at level zero and a leaf tournament at level one.

These factory reads validate the deployment once. Descriptors and bond values
for individual tournaments still come entirely from events. Waiting until the
first NewInnerTournament to check the leaf geometry would be too late, because
the player could already have joined a root tournament it cannot defend.

Pin the state-transition proof encoding with that deployment. The encoder is
a pure function of the machine access logs and input bytes, wherever it lives.
Contract fixtures must accept the player's proofs through CartesiStateTransition and
reject malformed proofs. The selected encoding and its fixtures must be settled
before implementing the proof adapter.

Provide the player with the initial machine and exact epoch input payloads.
The first harness may use pre-materialized input files checked against contract
fixtures. Live ingestion must reconstruct and verify the input commitments for
the EpochSealed input bounds before computing a claim.

## Work queue and player requests

### What the bridge keeps

- The computation hashes of claims the player has built, so the bridge can recognize
  events concerning those claims and ask the player to answer. The player
  keeps the machines and computation hash trees.
- The calls waiting to be made. Each queue entry holds the contract address,
  method, arguments supplied by events, first eligible block, any expiry block,
  and the information still needed from the player. It also identifies the
  event that scheduled it. Descriptor fields and bond values are part of these
  arguments.
- Requests sent to the player that still need answers, and answers already
  received. The bridge records the claim, inputs, and request arguments each
  answer belongs to, so it can reuse an answer without repeating computation
  or applying it to the wrong claim.
- Links supplied by events between a child tournament and its parent match,
  and between a root tournament and its epoch. These tell the bridge which
  parent contract receives a child tournament's result and which epoch a root tournament's result settles.
- The contract addresses to listen to. These are the configured consensus and
  factory, the epoch's root tournament, and child tournaments discovered through events.
- Copies of blockchain events for the current epoch, so the queue can be
  rebuilt after a reorg without fetching every event again.
- The recent block numbers, hashes, and parent hashes back to finality, so the
  bridge can detect a replaced branch and find the last shared block.
- The transaction waiting to be mined, including its signed bytes, hash, fee,
  associated queued call, and signing account's transaction number (nonce).
  Keep replacements sent with the same nonce too. This lets the bridge check
  which transaction was mined, raise its fee, or resume checking it after the
  bridge process stops and is launched again.

The bridge does not keep a copy of the tournament's matches, clock balances, or
standings. To rebuild its queue, it processes the surviving blockchain events
in order and uses them to add, replace, or cancel calls. The same pass restores
the tournament links and addresses to listen to. This works both after a reorg
and after relaunching the bridge process.

Each queued call is a job. Some calls act on one match between two claims.
They answer a request to reveal tree nodes or prove a transition, claim a
timeout win, or eliminate the match. We call these match jobs. A MatchAdvanced
event replaces the pending calls for that match, and a MatchDeleted event
cancels them.

Other calls act on a tournament's outcome. They propagate a child tournament's
winner to its parent tournament, eliminate a finished child tournament, stage
a root tournament's result, or recover a bond.
We call these result jobs. A StandingChanged event replaces the pending calls
based on that tournament's outcome. They remain separate calls, so completing
one does not discard the others. For example, propagating a child tournament's
winner must leave its bond-recovery call pending.

This distinction identifies which calls an event replaces or cancels. Match
jobs use the queue key (tournament, matchIdHash, kind), with kind respond,
timeoutWin, or eliminate. Result jobs are grouped by tournament, with separate
propagate, eliminate, stage, and recover entries. A call to join a tournament
has its own queue entry.

Creation events populate the queue's tournament groups with the descriptor and
bond value needed by their jobs. Replacements carry forward the context they
need. These values belong to the work queue, not a separate tournament record.

Each job retains its key, authorizing event identity (chain ID, block hash,
transaction hash, event index given by RPC logIndex), call, fixed arguments,
required computation, and eligibility and optional exclusive expiry blocks.
Jobs for propagating or eliminating a child tournament also identify the parent
match, so deleting that match cancels those calls while leaving the child
tournament's bond recovery pending. No contract-issued revision numbers are needed. A request is associated
with its job key and authorizing event identity.
A rebuilt entry can adopt the pending request when both still match, along with
the computation context and arguments.

### Event to job conversion

H is the emitted descriptor height. own(x) means the player holds commitment
x in the relevant context. The joining deadline is descriptor.startInstant + descriptor.allowance.
New claims are accepted only before that block.
The companion document defines the complete event fields and deadline rules.

Each claim is identified by its computation hash. The player request
get_claim_children returns the two child hashes that combine to produce that
computation hash. Calls to claim a timeout win or propagate a child tournament's
winner use these two hashes to identify and verify the winning claim.

| Event | Queue changes | Ordinary player work | Window |
|---|---|---|---|
| TournamentCreated(R, descriptor, bondValue) | Populate R's queue context with the emitted descriptor and bond, pending association with EpochSealed | None | Immediate |
| EpochSealed(e, lo, hi, initialHash, R) | Record the root tournament and epoch association, watch R, install join with the descriptor and bond from TournamentCreated | commit_mcycle_claim using the configured epoch inputs | Before R's joining deadline |
| MatchCreated(h, one, two, leftOfTwo, responderDeadline, eliminableAt) | Holder of one responds. Holder of two may win by timeout. Everyone installs elimination | Respond with reveal_bisection(one, 0, H, leftOfTwo), or seal_divergence(one, 0, leftOfTwo) for H = 1. Timeout uses get_claim_children(two). Elimination needs no computation | Respond before responderDeadline. Timeout in [responderDeadline, eliminableAt). Eliminate from eliminableAt |
| MatchAdvanced(h, one, two, otherParent, leftNode, pos, currentHeight, responderDeadline, eliminableAt) | Replace all three match jobs. Responder r is one when H - currentHeight is even, otherwise two. Holder of r responds. Holder of the other side may win by timeout. Everyone installs elimination | reveal_bisection(r, pos, currentHeight, leftNode), or seal_divergence(r, pos, leftNode) at height 1. Timeout uses get_claim_children(other) | Same as MatchCreated |
| LeafMatchSealed(h, one, two, agreeState, pos, f1, f2, d1, d2, eliminableAt) | Replace match jobs. Either holder proves. Holder of the longer clock may win by timeout. Everyone installs elimination | prove_state_transition at split(baseCycle + (pos << log2Stride)), plus get_claim_children(own) for winLeafMatch. Timeout uses get_claim_children(longer side) | Prove before min(d1, d2). Timeout in [min, max), absent when equal. Eliminate from max |
| NewInnerTournament(h, C, one, two, f1, f2, descriptor, bondValue) | Cancel parent's three match jobs. Record C -> (emitter, h), populate C's queue context with the emitted descriptor and bond, watch C. Install initial parent.eliminateInnerTournament(C). Holders of one or two join C with its bond | commit_uarch_claim(input_index, period_index from C.baseCycle, {f1, f2}) | Join before C's joining deadline. Initial elimination from C's joining deadline |
| MatchDeleted(h, one, two, reason, winner) | Cancel match jobs and linked child tournament's propagation/elimination. Preserve its bond recovery | None | Immediate |
| StandingChanged(n, d, pc, resultAt, expiresAt), child tournament C of P | Replace C's result group. With n > 0 install no result work. With n = 0 and d nonzero, holder of pc propagates, everyone eliminates at expiry, holder of d recovers. With n = 0 and d zero, everyone eliminates at resultAt | Propagation uses get_claim_children(pc) for P.winInnerTournament(C, children). Elimination and recovery need no computation | Propagate in [resultAt, expiresAt). Eliminate from expiresAt, or resultAt with no candidate. Recover from resultAt |
| StandingChanged(n, d, 0, resultAt, 0), root tournament R of epoch e | Replace R's result group. With n = 0 and own(d), install separate stage and recover jobs. Otherwise install no transaction jobs | prove_outputs_merkle_root for staging | From resultAt |
| CommitmentJoined | Complete our matching join job, including when another submitter joined the same commitment | None | Immediate |
| EpochStaged | Complete the named epoch's stage job, regardless of sender. Preserve recovery | None | Immediate |
| BondRecovered | Complete that tournament's recovery job, regardless of sender | None | Immediate |

Creating a child tournament schedules its elimination at its joining deadline in case nobody
joins. Later StandingChanged events cancel or replace that scheduled call as
specified in the table.

For a finished child tournament, first try winInnerTournament on its parent
tournament to submit the winner, then tryRecoveringBond on the child tournament
to request the winning claimant's bond payment. For a finished root tournament,
first try stageTournamentResult to submit the winning result and output proof,
then tryRecoveringBond to request the winning claimant's bond payment.

This order is a scheduling preference, not a contract requirement. The calls
are independent. The tryRecoveringBond call remains eligible if someone else
submits the result or our attempt to submit it fails.
Use the link from the child tournament to its parent match to cancel calls to
the parent tournament after a MatchDeleted event for that match. Preserve bond
recovery on the child tournament.

### Coordinates and transport

Before constructing a bisection request, require 1 <= currentHeight <= H,
0 <= pos < 2^H, and alignment to 2^currentHeight. Leaf divergence positions
instead identify individual transitions. Do not apply the bisection alignment
rule to them. Validate event topic counts, data lengths, and tournament origin.

Dave meta-cycles are 92-bit integers. Decode them with evmu's big-integer type
and pass only fitting split coordinates to the player.

```text
input_index             = cycle >> 68
mcycle_in_input         = (cycle >> 20) & (2^48 - 1)
period_index            = mcycle_in_input >> log2_period
state_transition_offset =
    ((mcycle_in_input & (2^log2_period - 1)) << 20) |
    (cycle & (2^20 - 1))
```

Requests for computation hash tree nodes pass segmentStartPosition and
currentHeight unchanged.
The state-transition request remains prove_state_transition(input_index,
period_index, state_transition_offset). Its machine access logs and input bytes
are encoded for the pinned proofs argument of winLeafMatch.

Reuse ordinary typed computation handlers from [prt.lua](prt.lua) and extract
the request/response framing from [prtu.lua](prtu.lua). Keep one request in
flight per connection and queue later ordinary requests in FIFO order. The
bridge sends no scheduling callbacks, advance_time, or cancel_response. The
player sees no contract addresses, calldata, block windows, or reorg messages.
The simulator's subscriptions, response futures, and block barrier stay out of
the bridge transport.

Request computation when a job becomes eligible. A running computation must
not stop the bridge accepting new heads and updating its queue. Before sending
a queued request, and again when its response arrives, check that the owning
job is current and eligible at the latest accepted head. An obsolete response
may populate the computation cache but cannot authorize a transaction.

Cache deterministic values by player/epoch context and exact request arguments,
including claim identity when applicable. Retain the claim handles that cached
values refer to. Caching a commit response alone does not restore a player's
computation hash tree. Reuse cached work only in a matching computation context. A reorg
that changes inputs or the initial state can require new machine work.

## Heads, blockchain event cache, and recovery

Poll the latest head. Watch the configured consensus and root tournament factory as well
as the epoch's root tournament and discovered child tournaments. Fetch their blockchain events over
the new range in bounded chunks, bisecting rejected ranges. Associate a factory's
TournamentCreated with the matching EpochSealed before installing the root tournament join
job, and check that their initial hashes agree. A factory event alone does not
authorize joining an unrelated root tournament. Discover child tournaments from authenticated
parent events and fetch their blockchain events starting at creation, including
the current range. Repeat discovery until all relevant events through the selected head
are available. Deduplicate by full event identity and apply them in block,
transaction-index, event-index order. Recheck the selected chain before accepting
the range. Never execute jobs during historical catch-up.

Only after applying all events through the accepted head may due jobs run.
This handles child tournament creation and activity in the same block, as well
as a new MatchCreated preceding the old MatchDeleted in a winning transaction.
Ordering applies queue
operations without reconstructing tournament state. Skipping intermediate heads
does not execute historical jobs whose eligibility windows have already expired.

Cache accepted blockchain events by block hash, retaining block ancestry back
to finality.
Keep the current epoch's finalized event prefix as well, so reconstruction has
the complete epoch sequence without fetching it again. Finality makes that
prefix append-only. Retain headers for empty unfinalized blocks too, since they
advance deadlines and may become the common parent of a reorg.

On a reorg, find the common parent, drop the orphaned suffix from the event cache,
and fetch the replacement branch, including events from newly discovered child tournaments.
Rebuild the queue with its event-supplied context, identities, and watched
addresses from the surviving cached prefix and replacement events. Apply the
expiry filter at the new head only after reconstruction. A job canceled,
completed, or expired on the orphaned branch returns naturally if the surviving
events and new head still permit it.

Creation events supply descriptor and bond values to the rebuilt queue. If a
replacement branch creates a different clone at the same address, its event
supplies the replacement values. There is no separate cache
of contract view results to refresh or invalidate.

Keep in-flight computations running during reconstruction. A rebuilt job with
the same key and authorizing event identity adopts its pending request when the
computation context and arguments match. If no current job matches, the response
can populate the computation cache but cannot trigger a transaction. The player
receives no reorg or time messages.

Pending transactions are reconciled separately because rebuilding a queue does
not retract a broadcast. If a conflict reaches finalized history, stop
submission and report it.

Persist computation handles/cache metadata and transaction records, bound to
the deployment and epoch identity. The blockchain event cache may stay in memory.
When the bridge process is launched again after stopping or crashing, fetch the
epoch's events and use the same reconstruction routine. Then reconcile the
pending transaction before sending anything. Reconstruction
processes CommitmentJoined, EpochStaged, and BondRecovered from every
participant and executes no intermediate jobs.

Act on latest heads to avoid charging finality latency to every response.
Contract validation remains authoritative if the chain changes after a job
was prepared. Simulation does not guarantee inclusion before its deadline.

## Bonds and transactions

Attach the creation event's bondValue as msg.value to every join. Budget for the
root tournament's bond, the active child tournament's bond, transaction gas, and further joins before
earlier recovery payments arrive. PartialBondRefund needs no queue action.
Recovery pays the recorded winning claimer, which is our signer only when our
join established that claim. Holding the same commitment does not establish
ownership of someone else's bond. Preserve recovery independently of parent
settlement, and complete it from BondRecovered. A payment failure can return
false without reverting, so a successful receipt alone does not prove recovery.

Keep one pending nonce per signer. For each eligible job, simulate the exact
call, signer, and bond value against the latest accepted head. Check that the
head remains canonical and the queue entry remains current before signing.
A simulation revert skips that attempt. Retain the job for a later head unless
an event supersedes it or its window expires. Do not retry in a tight loop at
the same head.

Sign, atomically persist the signed bytes, hash, nonce, fee fields, and owning
job identity, then publish. A crash before recording must not leave an
unrecorded broadcast transaction. After the bridge process is relaunched, it
can query or republish the recorded transaction without allocating another
nonce for the same attempt.

If pending past the configured fee-bump interval, replace at the same nonce
with a higher fee. Revalidate the job first. If it is obsolete, use a currently
eligible simulated job at that nonce, or cancel the nonce when no job is due.
Persist replacements before publication and retain all candidate hashes until
the nonce is resolved. An earlier transaction can still be the one mined.

A reverted receipt consumes a nonce but does not complete the job. A successful
receipt is provisional. Apply its canonical events to complete or replace
work. Bond recovery specifically requires BondRecovered, and staging can be
completed by anyone's EpochStaged. Retain receipt provenance through finality.
If its block is orphaned, rebuild the queue from the surviving events and reconcile
the nonce and all candidate receipts before sending or replacing again.

Only prt-cast.lua invokes cast. Use cast rpc for headers, blockchain events,
calls, nonces, and receipts, and cast mktx/cast publish for signing and
publication. Pin output
formats, capture stdout and stderr separately, and check exit status. Read the
endpoint from ETH_RPC_URL. Use a keystore or external signer. Never put raw
private keys on command lines. Redact endpoint, credentials, account, and signer
paths from diagnostics. Signed transaction records must not contain credentials
or endpoint configuration.

## Implementation and validation

The implementation uses these components.

```text
doc/recipes/prt-bridge.lua       heads, event cache, work queue, player transport
doc/recipes/prt-ethereum.lua     ABI definitions and event-to-job table
doc/recipes/prt-cast.lua         RPC, signer, and publisher adapter
doc/recipes/prt-bridge-test.lua  fixture, queue, replay, and Anvil tests
src/cartesi/evmu.lua            selectorless ABI value codec additions
tests/lua/spec-evmu.lua         ABI codec tests
```

Implement the components in this order.

1. Add selectorless ABI tuple encoding/decoding. Define canonical signatures,
   indexed fields, types, outputs, and Lua names once. Pin event, factory-table,
   result-view, and mutation fixtures from the contract tests. Descriptor and bond-value
   views are contract-test oracles for the emitted fields. Validate integer
   widths, addresses, enum values, padding, topic counts, and data lengths.
2. Implement the constrained cast adapter and ordinary player transport. Bind
   deterministic computation caches to their player/epoch and claim context.
   Validate both factory levels before enabling claim computation or joins.
3. Implement job groups, event-to-queue handlers, cancellation, and queue
   reconstruction. Derive jobs directly from events, emitted descriptors,
   learned identities, and own claims. Cover the optional standing adapter
   separately from the final event path.
4. Implement head processing, child tournament discovery, and blockchain event
   fetching and caching.
   Use the same reconstruction routine after relaunching the bridge process and
   after a reorg. During a reorg, adopt pending requests for surviving jobs.
   Execution begins only after the accepted head's relevant events have all
   been applied.
5. Implement bonds, simulation, pending-nonce persistence, publication,
   replacement, and canonical receipt reconciliation.

Use repository Make targets for builds, checks, and tests.

For testing before StandingChanged is available, the bridge may temporarily
call tournamentStanding() for each watched tournament after processing the
events at an accepted head, including after rebuilding the queue. Use the
returned result to schedule propagation, elimination, staging, and recovery.
The view supplies no prospective resultAt before the joining deadline, so schedule these
calls when it reports that a result is available. The initial call to eliminate
an empty child tournament still uses the descriptor supplied by its creation
event.

Replace only jobs whose arguments or windows changed, preserving completion
established by events. This workaround supplies none of the missing fields in
match events. Remove it before accepting the implementation as complete. The
proposed bridge gets this information entirely from events.

- Test ABI encoding for selectorless tuples, indexed fields, dynamic bytes,
  92-bit coordinates, malformed padding/truncation, and byte-exact calldata.
- Validate the complete factory table before any claim computation or join.
  Accept different compatible two-level tables. Reject a level count other
  than two, inconsistent levels fields, a root height and stride sum other
  than 92, a nonzero leaf stride, a leaf height different from the root stride,
  or either height at or above 63. These checks must run without waiting for a
  NewInnerTournament event. Reject creation events that disagree with the
  validated geometry, level, or kind. Check that factory parameters are read
  once when pinning the deployment, not for each tournament.
- Exercise every event-table row with both orientations and responder parities,
  sealing at height one, equal tree children, invalid coordinates, and unrelated
  cleanup.
- Check the blocks before, at, and after every deadline in the event table.
  Include equal and unequal leaf clocks, skipped heads, expiry during
  computation, and jobs without expiry.
- Cover an empty child tournament with no further events, a join replacing its initial
  elimination, later pairing canceling prospective results, and both sides of
  the last match eliminated while a third claim wins. Parent deletion must
  cancel propagation and elimination of the child tournament while preserving recovery.
  EpochStaged and BondRecovered from other participants must complete their
  respective jobs.
- Discover child tournament creation and activity within one transaction, one block, and
  one polling range. Arbitrary range partitioning must produce the same queue.
- Associate a root tournament's factory creation event with EpochSealed before joining.
  Discovery of root tournaments and child tournaments must provide geometry, joining deadline, and join bond from
  events alone. Assert that no descriptor or bond-value view calls occur.
- After a reorg, require reconstruction from the surviving cache and replacement
  events to equal reconstruction from the chain. Include replacement child
  tournament discovery and deadline filtering at the new head.
- Replace a child tournament's creation with another at the same factory nonce and address
  but different immutable arguments. Require the rebuilt queue to use the
  descriptor and bond value from the replacement event without contract reads.
- Reconstruct while computations are in flight. Jobs with the same authorizing
  event identity and matching requests must adopt them without repeating machine
  work. Responses without a surviving owner cannot trigger transactions. The
  player must receive no time or reorg requests.
- Stop and relaunch the bridge process at every pending state. Reuse cached
  computation in the same context and reject reuse after inputs or the initial
  state change.
- Exercise transaction crashes before and after persistence and publication,
  fee bumps, either same-nonce candidate winning inclusion, failed simulation,
  reverted and orphaned receipts, payment failure without a revert, and recovery
  continuing when another participant stages first.
- Accept every supported state-transition proof through CartesiStateTransition
  and reject malformed proofs. Never weaken verification to make the bridge's
  proof format pass.
- Run an honest player against adversarial counterparts in Anvil through missed
  turns, timeouts, unrelated elimination, child tournament propagation, root tournament staging,
  bond recovery, stuck transactions, and controlled reorgs.

Final acceptance requires event-only scheduling, no player scheduling state,
identical queue reconstruction from cached and fetched blockchain events,
correct response adoption and stale-response rejection, and an end-to-end staged result with
recovered bonds. Run an opt-in read-only smoke test, then a funded low-stakes
testnet trial, only after fixtures and Anvil pass.
