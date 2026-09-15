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
The validator derives these calls afresh on each tick. Any expiry limits how
long a call remains eligible.

An event can also cancel or replace a call that an earlier event scheduled.
Expressing participation through these scheduling and cancellation operations
lets the node respond directly to the contract's events with the information
it computes off chain.

The contracts retain authority over pairing, clock accounting, result selection,
and whether a submitted move is valid. Their events expose the identities,
coordinates, and deadlines needed for the next action. For example, a match
advance identifies the claims, the tree node to open, and the response window.
The validator can compute that opening directly, without replaying earlier
moves to reconstruct the match. This keeps dispute complexity where it is
unavoidable and avoids implementing another copy in each validator.

Each tick fetches the relevant epoch's logs through a selected latest head and
applies the table to an initially empty action set. Later events replace or
cancel earlier actions. The node persists its own claims and computation
context, and its one tracked transaction. Event logs, discovered identities,
and the action set are temporary. Restarting or changing branches needs no
separate dispute-observation recovery procedure. The next tick reads the chain
again.

These goals apply whether the validator is a single program or several
components. The event interface does not require a bridge/player separation.

Our implementation calls the existing Lua player's computation methods directly
from the bridge. Together they form one validator node.

```text
Dave events and block heads <-> Lua bridge tick
                                     |
                                     +-> prt.new_player(...) computation methods
                                     +-> signed transactions
```

The player owns the computation. Given the initial machine state and inputs,
it executes the machine, builds computation hash trees, and answers requests for
claims, tree nodes, and proofs. In the documentation, a simulated referee asks
for these values. Our bridge calls the same computation handlers without a
bridge/player socket. The simulator's scheduling callbacks and response
barriers are not part of this interface.

The bridge derives due actions, computes a selected response, refreshes its
chain observation, and simulates the still-eligible call before submitting at
most one transaction per tick. It also handles chain access, signing, and
transaction tracking. Neither component maintains a parallel model of the
tournament's internals. Consistent log fetching, computation-context validation,
and transaction reconciliation remain necessary across reorgs and restarts.

The simplification is confined to observation. Discovery still follows child
event streams, and log fetching, signing, input retrieval, machine execution,
and proof encoding remain validator work.

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

## Actions and player computation

### What the bridge keeps

- Durable claim data and computation context, so the bridge can recognize its
  claims and restore the trees needed to answer. The restoration requirements
  below distinguish these from optional machine checkpoints.
- The one tracked transaction, if any, with its signed bytes, hash, nonce,
  fee fields, owning job identity, and computation context, and the highest
  nonce ever published. The record is cleared once its nonce is consumed at
  the accepted head. The high-water mark is persisted before each publication
  and never lowered, since consumption on an unfinalized branch can be undone.
- For this tick, the calls that events authorize. Each entry holds the contract
  address, method, arguments supplied by events, first eligible block, any expiry block,
  and the information still needed from the player. It also identifies the
  event that scheduled it. Descriptor fields and bond values are part of these
  arguments.
- For this tick, links supplied by events between a child tournament and its
  parent match, and between a root tournament and its epoch. These identify the
  parent contract that receives a child's result and the epoch a root result settles.
- For this tick, the contract addresses to fetch, which are the configured
  consensus and factory, the epoch's root tournament, and children discovered
  through events.

The bridge does not keep a copy of the tournament's matches, clock balances, or
standings. Each tick processes freshly fetched events in event order, adding,
replacing, or canceling calls and establishing tournament links. It retains no
event cache or
block ancestry between ticks, and adopts no pending player requests.

Each candidate call is a job in the temporary action set. Some calls act on
one match between two claims.
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
jobs use the key (tournament, matchIdHash, kind), with kind respond,
timeoutWin, or eliminate. Result jobs are grouped by tournament, with separate
propagate, eliminate, stage, and recover entries. A call to join a tournament
has its own entry.

Creation events populate the action set's tournament groups with the descriptor and
bond value needed by their jobs. Replacements carry forward the context they
need. These values belong to the current observation, not a persistent tournament record.

Each job retains its key, authorizing event identity (chain ID, block hash,
transaction hash, event index given by RPC logIndex), call, fixed arguments,
required computation, an eligibility block, and an optional expiry block, the
first block at which the call is no longer eligible.
Jobs for propagating or eliminating a child tournament also identify the parent
match, so deleting that match cancels those calls while leaving the child
tournament's bond recovery pending. No contract-issued revision numbers are
needed. Event identity records provenance. Cached computation never authorizes
a transaction without a currently eligible job with matching context and arguments.

### Event to job conversion

H is the emitted descriptor height. own(x) means the player holds commitment
x in the relevant context. claimer(x) means our own join established x, which
the submitter on CommitmentJoined shows. The joining deadline is
descriptor.startInstant + descriptor.allowance.
New claims are accepted only before that block. An expiry at block d means d
is the first expired block, so the transaction must be included before d.
The companion document defines the complete event fields and deadline rules.

Each claim is identified by its computation hash. The player request
get_claim_children returns the two child hashes that combine to produce that
computation hash. Calls to claim a timeout win or propagate a child tournament's
winner use these two hashes to identify and verify the winning claim.

| Event | Action-set changes | Player computation | Window |
|---|---|---|---|
| TournamentCreated(R, descriptor, bondValue) | Populate R's context with the emitted descriptor and bond, pending association with EpochSealed | None | Immediate |
| EpochSealed(e, lo, hi, initialHash, R) | Record the root tournament and epoch association, watch R, install join with the descriptor and bond from TournamentCreated | commit_mcycle_claim using the configured epoch inputs | Before R's joining deadline |
| MatchCreated(h, one, two, leftOfTwo, responderDeadline, eliminableAt) | Holder of one responds. Holder of two may win by timeout. Everyone installs elimination | Respond with reveal_bisection(one, 0, H, leftOfTwo), or seal_divergence(one, 0, leftOfTwo) for H = 1. Timeout uses get_claim_children(two). Elimination needs no computation | Respond before responderDeadline. Timeout in [responderDeadline, eliminableAt). Eliminate from eliminableAt |
| MatchAdvanced(h, one, two, otherParent, leftNode, pos, currentHeight, responderDeadline, eliminableAt) | Replace all three match jobs. Responder r is one when H - currentHeight is even, otherwise two. Holder of r responds. Holder of the other side may win by timeout. Everyone installs elimination | reveal_bisection(r, pos, currentHeight, leftNode), or seal_divergence(r, pos, leftNode) at height 1. Timeout uses get_claim_children(other) | Same as MatchCreated |
| LeafMatchSealed(h, one, two, agreeState, pos, f1, f2, d1, d2, eliminableAt) | Replace match jobs. Either holder proves. Holder of the longer clock may win by timeout. Everyone installs elimination | prove_state_transition at split(baseCycle + (pos << log2Stride)), plus get_claim_children(own) for winLeafMatch. Timeout uses get_claim_children(longer side) | Prove before min(d1, d2). Timeout in [min, max), absent when equal. Eliminate from max |
| NewInnerTournament(h, C, one, two, f1, f2, descriptor, bondValue) | Cancel parent's three match jobs. Record C -> (emitter, h), populate C's context with the emitted descriptor and bond, watch C. Install initial parent.eliminateInnerTournament(C). Holders of one or two join C with its bond | commit_uarch_claim(input_index, period_index from C.baseCycle, {f1, f2}) | Join before C's joining deadline. Initial elimination from C's joining deadline |
| MatchDeleted(h, one, two, reason, winner) | Cancel match jobs and linked child tournament's propagation/elimination. Preserve its bond recovery | None | Immediate |
| StandingChanged(n, d, pc, resultAt, expiresAt), child tournament C of P | Replace C's result group. With n > 0 install no result work. With n = 0 and d nonzero, holder of pc propagates, everyone eliminates at expiry, claimer(d) recovers. With n = 0 and d zero, everyone eliminates at resultAt | Propagation uses get_claim_children(pc) for P.winInnerTournament(C, children). Elimination and recovery need no computation | Propagate in [resultAt, expiresAt). Eliminate from expiresAt, or resultAt with no candidate. Recover from resultAt |
| StandingChanged(n, d, 0, resultAt, 0), root tournament R of epoch e | Replace R's result group. With n = 0, own(d) installs the stage job and claimer(d) installs the recover job, as separate jobs. Otherwise install no transaction jobs | prove_outputs_merkle_root for staging | From resultAt |
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

### Coordinates and computation

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

Load [prt.lua](prt.lua) as a module and construct the player with
new_player(geometry, inputs, machine_cache, label), using the validated
geometry, verified epoch inputs, and a caller-owned cache from
new_machine_cache. Call its event_handler entries for commit_mcycle_claim,
commit_uarch_claim, reveal_bisection, seal_divergence, prove_state_transition,
and prove_outputs_merkle_root, passing the player as the first argument.
Coordinates passed to these handlers are zero-based. Read claim children through
player.trees[claim]:get_child_hashes(position, height). The prove_output handler
and output selection are not needed for staging.

Compute for an eligible job, then refresh the head and derive the action set
again before using the result. Blocks continue advancing while a method runs,
and there is no simulator barrier or fresh allowance for computation. Cache
deterministic results by deployment, epoch computation context, claim identity,
and exact method arguments. Obsolete results can remain reusable computation
data but cannot authorize a transaction. A reorg changing inputs or the initial
state requires a different computation context.

### Claim restoration and successive opponents

The current player's trees contain frontier forests of bundle roots.
collect_mcycle_bundle and collect_uarch_cycle_bundle replay a machine to open
an opaque bundle, and tree:open_bundle in prtu.lua authenticates the reconstructed
subtree against its committed root. Saving a computation hash, commit response, or
Lua object handle alone does not restore this ability.

Persist a versioned claim record containing the forest, tree and bundle
heights, expected computation root, root children, and final-state proof.
Bind it to the deployment, epoch initial hash, exact verified input payloads
and bounds, geometry, and, for a child claim, input and period coordinates.
Store immutable inputs and the initial machine snapshot locally, or references
to durable content-addressed copies. On restart, recreate the player and its
bundle-collection callbacks from this context, restore the forest through
prtu.new_tree, and verify the root and saved proofs before use. Never deserialize
callbacks or assume that saving their Lua handles preserves machine resources.
The record format and restoration code are implementation work in this plan.

Machine checkpoints and expanded bundles are optional accelerators. With only
the initial snapshot and stored forest, replay must reconstruct the same
claim. Validate both that equality and the time needed to answer after a cold
restart. Checkpoint persistence is required for a deployment whose response
windows cold replay cannot meet.

The player currently holds one mcycle_claim and one uarch_claim, and
commit_uarch_claim replaces the latter. Keep durable claim records separately
from these active slots. Each new opponent can open a child tournament over a
different period, requiring the corresponding child commitment and contested
final-state check. Check the emitted geometry, coordinates, and contested final
states even when reusing a previously computed claim for the same period.
Restore the tree for the selected job's context before
calling a handler. Never resolve a claim solely by tournament address or by
whichever uarch tree happens to be active.

Retain claims for earlier children until the root settlement is finalized, so
a reorg can make their dispute work current again. Recovery remains discoverable
from those children's event streams until it succeeds and is finalized. It
needs the tournament and winning-claim/claimer identities, not the old child's
full tree. Parent propagation uses the parent claim's children. Pending recovery
must neither retain an obsolete active slot nor prevent the next child claim.

## Tick, log discovery, and restarts

A tick performs the following steps. Its observation starts empty every time.

1. Select the latest head by number and hash. Fetch the relevant consensus and
   factory logs from the epoch's discovery range, including its creation
   transaction, through that fixed head number. Fetch the root tournament's
   logs from creation. Use address/topic filters and bounded chunks, bisecting
   rejected ranges, and do not restrict cleanup discovery to our own claims.
2. Associate TournamentCreated with EpochSealed before authorizing a root join,
   checking the matching addresses and initial hashes. Discover children from
   authenticated parent events and fetch each child's logs from creation through
   the selected head, including activity in its creation block. Repeat until
   every reachable stream has been fetched. Include finished children whose
   parent matches were deleted, since their bonds may still be recoverable.
3. Deduplicate by full event identity and apply all events in block,
   transaction-index, logIndex order to the temporary action set. Verify that
   the selected head is still canonical and the fetched ranges belong to that
   branch before accepting the observation. Discard inconsistent reads and
   retry on a later tick. Range requests must not independently use "latest".
4. Read the signing account's nonce at the accepted head and reconcile the
   tracked transaction. A tracked nonce below the account nonce was consumed
   and its record is cleared. A tracked nonce equal to it is still pending. A
   tracked nonce above it means a reorg orphaned mined transactions, and the
   account nonce is the next one to use. Every nonce from the account nonce
   through the high-water mark may still carry an untracked candidate, since
   nodes keep orphaned and future-nonce transactions queued, and they become
   executable again as the nonces below them are consumed. This step only
   selects the nonce and the proposed action. When the account nonce is at or
   below the high-water mark and no tracked transaction is pending at it, the
   proposed action is the due job, or a cancel when none is due. Filter jobs
   by their windows at the accepted head. Choose due work
   deterministically, prioritizing expiring joins, responses, timeout wins,
   and child propagation by earliest expiry ahead of work without expiry.
   Prefer staging before recovery for the same root tournament. Use stable
   job-key ordering for remaining ties, and ensure unrelated cleanup and
   recovery make progress when urgent work permits.
5. Compute the selected job's missing data. Refresh the observation from a new
   selected latest head, applying steps 1-4 again, before preparing a transaction.
   Reuse the result only for a currently eligible job with the same computation
   context and arguments. If that job disappeared or expired, end this tick.
   Cached computation may be useful on a later one. Also defer the transaction
   if more urgent work appeared during computation.
6. Simulate the exact eligible call at the accepted head hash, recheck that the
   head remains canonical, and persist and publish at most one transaction at
   the nonce selected in step 4. Publication happens only here. Replacements,
   rebroadcasts, and nonce cancellations count toward that limit, and each is
   an attempt to out-bid whatever candidate holds the nonce. A pending
   transaction can be handled without starting new machine work.

No calls execute while processing historical events, so skipped heads never
execute already-expired historical jobs. A new MatchCreated preceding an old
MatchDeleted inside one winning transaction needs no special handling, since
the two matches have different keys.
CommitmentJoined, EpochStaged, and BondRecovered from every participant complete
the corresponding jobs before selection. After building a new claim, the
refreshed observation also recognizes events for that newly known commitment.

Each tick re-fetches the full relevant event history. There is no retained
finalized event prefix, ancestry traversal, rollback routine, or pending
computation adoption. Caching the finalized prefix of that history is a
possible later optimization that changes fetch cost, not the derived actions.
A replacement clone at the same address receives the descriptor and bond value
from its replacement creation event. Relaunching the process restores claim
records, the tracked transaction, and the high-water mark, then runs the same
tick. An interrupted computation can restart from durable claim data.

This removes special recovery machinery for dispute observation, not the need
for consistent chain reads or transaction reconciliation. Retain pending bond
recoveries in the epoch's discovery scope after staging, since staging alone
does not finish the validator's work. Act on latest heads rather than waiting for
finality before each response. Contract validation remains authoritative if
the chain changes after preparation, and simulation does not guarantee inclusion
before a deadline. Measure full-history fetch and computation latency against
the deployment's windows as part of acceptance.

## Bonds and transactions

Attach the creation event's bondValue as msg.value to every join. Budget for the
root tournament's bond, the active child tournament's bond, transaction gas, and further joins before
earlier recovery payments arrive. PartialBondRefund needs no action.
Recovery pays the recorded winning claimer, which is our signer only when our
join established that claim. Holding the same commitment does not establish
ownership of someone else's bond. Preserve recovery independently of parent
settlement, and complete it from BondRecovered. A payment failure can return
false without reverting, so a successful receipt alone does not prove recovery.

Track one transaction and keep one pending nonce per signer. Reorgs can leave
additional candidates of ours in the network. For each eligible job, simulate
the exact call, signer, and bond value against the accepted head hash. Check
that the
head remains canonical and the job remains current before signing. A
simulation revert ends that attempt. A later tick derives the job again if the
events and window still permit it. Simulation is cheap, so another due job
may be tried in the same tick, with the same refresh and simulation checks,
provided no transaction has been published. A wasted computation instead ends
the tick, as the tick steps say. Try each job at most once per tick so one
reverting call cannot block every other action or cause a tight retry loop.

Sign, atomically persist the signed bytes, hash, nonce, fee fields, and owning
job identity and computation context, then publish. A crash before recording
must not leave an unrecorded broadcast transaction. After relaunch, the bridge
can query or republish the recorded transaction without allocating another
nonce for the same attempt.

If pending past the configured fee-bump interval, replace at the same nonce
with a higher fee. Revalidate the tracked job every tick, not only then. As
soon as it is obsolete, replace it at the same nonce with a currently eligible
simulated job, or with a cancel when no job is due. A replacement, a cancel
included, is an attempt to out-bid the candidate at that nonce, not a
guarantee that it will not be included. A publication that the network rejects
as an underpriced replacement is retried at that nonce with an escalated fee
on a later tick. Persist each replacement before publication. It takes over
the record. Nonce reconciliation settles which candidate was mined, and the
events settle what it achieved.

A consumed nonce, reverted or not, completes nothing by itself. Fresh
canonical events complete or replace work. Bond recovery requires
BondRecovered, and anyone's EpochStaged completes staging. A consumed nonce
frees the next one without waiting for finality.

Contracts enforce the current validity of every call, so most stale calls
revert and cost gas. Not all do. A broadcast transaction can execute after the
observation that justified it has changed, and a well-formed stale call is
accepted. A stale root join is the case that matters. joinTournament checks the
bond, the commitment's final leaf, and the joining deadline, not that the
commitment was computed over the epoch's current inputs, so a join broadcast
before a reorg changed those inputs can post a claim over inputs the chain no
longer has and expose its bond. A cancel is attempted the tick the tracked
job becomes obsolete. Untracked candidates cannot be retracted, only out-bid
at their nonces as the tick describes, and a replacement accepted by one node
does not stop another block producer from including the original. When a
stale join does execute, the next tick's fresh observation shows a
CommitmentJoined from our own submitter for a commitment that is not a current
claim. The bridge does not defend that claim, and derives no response or
timeout-win work for it, but it still performs the permissionless cleanup of
the claim's matches like any other. If the joining window is still open, it
joins with the correct claim, which needs another bond. Budget for it. If the
window has closed, it reports that the correct claim can no longer enter this
epoch. Pin one exclusive signing account, so no other sender consumes its
nonces.

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
doc/recipes/prt-bridge.lua       tick, log discovery, action selection, claim restoration
doc/recipes/prt-ethereum.lua     ABI definitions and event-to-job table
doc/recipes/prt-cast.lua         RPC, signer, and publisher adapter
doc/recipes/prt-bridge-test.lua  fixture, tick, restart, and Anvil tests
src/cartesi/evmu.lua            selectorless ABI value codec additions
tests/lua/spec-evmu.lua         ABI codec tests
```

Implement the components in this order.

1. Add selectorless ABI tuple encoding/decoding. Define canonical signatures,
   indexed fields, types, outputs, and Lua names once. Pin event, factory-table,
   result-view, and mutation fixtures from the contract tests. Descriptor and bond-value
   views are contract-test oracles for the emitted fields. Validate integer
   widths, addresses, enum values, padding, topic counts, and data lengths.
2. Implement the constrained cast adapter and direct player calls. Validate
   both factory levels before enabling claim computation or joins. Implement
   versioned claim storage, restoration of forests and collection callbacks,
   and context-bound computation reuse across successive child tournaments.
3. Implement temporary job groups and the event-to-action table, including
   replacement and cancellation. Derive jobs directly from events, emitted
   descriptors, learned identities, and own claims. Cover the optional standing
   adapter separately from the final event path.
4. Implement full-history log fetching, child discovery, consistent-head
   validation, and tick selection. Use the same path for ordinary ticks,
   restarts, and replacement branches. Refresh observation after computation,
   and execute only after every relevant stream has been processed through the
   accepted head.
5. Implement bonds, simulation, tracked-transaction persistence with the
   high-water mark, publication, replacement, and nonce reconciliation. Enforce
   at most one publication per tick.

Use repository Make targets for builds, checks, and tests.

For testing before StandingChanged is available, the bridge may temporarily
call tournamentStanding() for each watched tournament after processing the
events at an accepted head. Pin each view call to that head hash. Use the
returned result to schedule propagation, elimination, staging, and recovery.
The view supplies no prospective resultAt before the joining deadline, so schedule these
calls when it reports that a result is available. The initial call to eliminate
an empty child tournament still uses the descriptor supplied by its creation
event.

Preserve completion established by events in the current tick's action set.
This workaround supplies none of the missing fields in match events.
Remove it before accepting the implementation as complete. The
proposed bridge gets this information entirely from events.

The existing [prt-time-test.lua](prt-time-test.lua) and
[prt-deadline-test.lua](prt-deadline-test.lua) cover logical-block queues,
deadline rejection, timeout responses, cancellation, and delayed replies.
They do not establish real-chain timing. The simulator's response barrier
prevents computation time from consuming allowance, and its referee propagates
child results immediately. The propagation and expiry exchange sketched in
prt.lua's propagate_uarch_result is commented out, not executed. Its sorted
rounds also do not reproduce the
contracts' arrival-driven re-pairing or full MatchClocks accounting.

The current player shares input delivery and rollback between sampled builds,
bundle collection, and proof replay. [prt-test.lua](prt-test.lua) includes
rejected-input, post-rejection, terminal-state, and checkpoint-replay cases.
These are emulator-side evidence. Acceptance below requires the same
commitments and encoded proofs to agree with the pinned Solidity verifier.

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
- Run the timing fixtures of the companion document against the bridge in
  Anvil. Advance blocks during claim builds, bundle opening, proof generation,
  and pending inclusion, so computation consumes allowance. Include skipped
  heads and jobs without expiry. Reject stale computation before publication,
  and verify that inclusion at the first expired block fails even when the
  proof is correct. Propagate a won child only inside [resultAt,
  winnerExpiresAt), ahead of old bond recovery.
- Cover an empty child tournament with no further events, a join replacing its initial
  elimination, later pairing canceling prospective results, and both sides of
  the last match eliminated while a third claim wins. Parent deletion must
  cancel propagation and elimination of the child tournament while preserving recovery.
  EpochStaged and BondRecovered from other participants must complete their
  respective jobs.
- Discover child tournament creation and activity within one transaction, one block, and
  one polling range. Arbitrary range partitioning must produce the same action set.
- Run the re-pairing fixtures of the companion document against the bridge.
  Carry one claim through successive opponents A and B with children over
  different periods. Keep B's jobs when A's MatchDeleted arrives after the new
  MatchCreated, answer with B's child commitment while A's child recovery is
  pending, restore A's child claim if a reorg makes it active again, and
  recover its bond independently.
- Associate a root tournament's factory creation event with EpochSealed before joining.
  Discovery of root tournaments and child tournaments must provide geometry, joining deadline, and join bond from
  events alone. Assert that no descriptor or bond-value view calls occur.
- Start each tick with empty observation state. At the same head, ordinary and
  restarted ticks must derive identical actions. Change branches during range
  fetching and reject mixed observations. Include replacement child discovery,
  disappeared completion events, and deadline filtering at the replacement head.
- Replace a child tournament's creation with another at the same factory nonce and address
  but different immutable arguments. Require the next tick to use the
  descriptor and bond value from the replacement event without contract reads.
- Broadcast a root join, then replace the branch so the epoch's inputs change
  while the root descriptor stays the same, and let the original join win the
  replacement race. The next tick must recognize the unintended join from
  CommitmentJoined, derive no response or timeout-win work for it, and still
  schedule elimination of its matches. With the joining window open it must
  join with the correct claim and a second bond. With the window closed it
  must report that the correct claim can no longer enter. Test both.
- Change heads and branches while a direct player method runs. The refreshed
  action set must reject stale results. Matching context and arguments may reuse
  deterministic computation. The player receives no time or reorg requests.
- Stop and relaunch during claim construction, after claim persistence, and
  before a previously unopened bundle is needed. Restore forests and callbacks
  with only the initial machine snapshot, check the same roots and proofs,
  and measure cold-replay latency. Reject corrupt records, incompatible record
  versions, or reuse after inputs, initial state, geometry, or child coordinates
  change. A cached commit response alone must not count as a restored tree.
- Exercise transaction crashes before and after persistence and publication,
  fee bumps, either same-nonce candidate winning inclusion, failed simulation,
  reverted and orphaned receipts, payment failure without a revert, recovery
  continuing when another participant stages first, and one publication per
  tick.
- Orphan several mined nonces at once, leaving an older higher-fee candidate
  queued at one of them, and restart in the middle of recovery. Every nonce up
  to the high-water mark must be replaced or observed consumed, and an
  underpriced-replacement rejection must escalate the fee rather than stall.
- Accept every supported state-transition proof through CartesiStateTransition
  and reject malformed proofs. Compare root and child commitments across the
  emulator and contract fixtures. Cover ordinary steps, input delivery including
  terminal no-ops, absent inputs, reset boundaries, rejecting resets, transitions
  after rejection, and consecutive rejected inputs. Verify final-machine proofs
  against the committed final state for staging. Never weaken verification to
  make the bridge's proof format pass.
- Run an honest player against adversarial counterparts in Anvil through missed
  turns, timeouts, unrelated elimination, child tournament propagation, root tournament staging,
  bond recovery, stuck transactions, and controlled reorgs.
- Measure full-history fetching and response computation with many reachable
  children and pending recoveries. Check deadline priority, eventual unrelated
  cleanup and recovery, and the deployment's response windows with one pending
  nonce. A passing sorted-bracket example alone is not a latency acceptance test.

Final acceptance requires event-only action derivation from fresh logs, direct
player computation without simulator scheduling, restorable claims,
stale-result rejection, nonce reconciliation, and an end-to-end
staged result with recovered bonds. Timing and successive-opponent scenarios
must pass against the contracts. Run an opt-in read-only smoke test, then a funded low-stakes
testnet trial, only after fixtures and Anvil pass.
