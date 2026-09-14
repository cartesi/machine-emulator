# Contract event requirements for the Lua PRT bridge

This proposal specifies the event changes needed by the
[Lua PRT bridge](prt-lua-bridge.md). The baseline is Dave commit 16d49bf8.
These are requested changes, not an implemented ABI.

The goal is to simplify the implementation of validator nodes. A client should
turn every event into its next job with a static table, using only the event
in hand, the descriptor emitted when the tournament was created, the
child-to-parent and tournament-to-epoch identities emitted at creation, and its
own claims. The client persists its own claims. Everything else it reads from
the logs of the current head and discards. It keeps no match table, advance
counter, clock, or standing, and it never reads a tournament view to recover a
value the contract had when it emitted the event.

The question for each field is what it removes from the client. Some of the
fields below can also be derived from the descriptor, from an earlier event,
or from a view. Every such derivation is code the client must write, state it
must keep across events, and an ordering it must get right, and every view
read is a round trip pinned to a block. The only cost is gas, priced below.

A client still walks the tournament tree. It discovers children through parent
events, fetches every reachable stream, and owes the permissionless cleanup of
every match and child tournament it can see. The table below schedules that
cleanup for everyone, not only for the client's own matches.

Dave has agreed to responderDeadline on MatchCreated and MatchAdvanced, and
to agreeState, divergencePosition, finalStateOne, finalStateTwo, deadlineOne,
and deadlineTwo on LeafMatchSealed. The rest of this ask adds the ordered pair
to every match event, currentHeight to MatchAdvanced, the descriptor and bond
value to creation events, and one new event. StandingChanged carries the
instants the contract itself compares against at closure. Dave floated
emitting the survivor's paused allowance on MatchDeleted for the same purpose.
StandingChanged emits the resulting instants where the contract computes them.

## The diff

```diff
 event TournamentCreated(
-    ITournament tournament
+    ITournament tournament,
+    ITournament.TournamentDescriptor descriptor,
+    uint256 bondValue
 );

 event MatchCreated(
     Match.IdHash indexed matchIdHash,
     Tree.Node indexed one,
     Tree.Node indexed two,
     Tree.Node leftOfTwo,
+    Time.Instant responderDeadline,
     Time.Instant eliminableAt
 );

 event MatchAdvanced(
     Match.IdHash indexed matchIdHash,
+    Tree.Node one,
+    Tree.Node two,
     Tree.Node otherParent,
     Tree.Node leftNode,
     uint256 segmentStartPosition,
+    uint64 currentHeight,
+    Time.Instant responderDeadline,
     Time.Instant eliminableAt
 );

 event LeafMatchSealed(
     Match.IdHash indexed matchIdHash,
+    Tree.Node one,
+    Tree.Node two,
+    Machine.Hash agreeState,
+    uint256 divergencePosition,
+    Machine.Hash finalStateOne,
+    Machine.Hash finalStateTwo,
+    Time.Instant deadlineOne,
+    Time.Instant deadlineTwo,
     Time.Instant eliminableAt
 );

 event NewInnerTournament(
     Match.IdHash indexed matchIdHash,
     ITournament indexed childTournament,
+    Tree.Node one,
+    Tree.Node two,
+    Machine.Hash contestedFinalStateOne,
+    Machine.Hash contestedFinalStateTwo,
+    TournamentDescriptor descriptor,
+    uint256 bondValue
 );

+/// @notice The tournament's standing after a state-changing call.
+/// @dev Emitted once, after all effects, by joinTournament and by every
+/// call that deletes a match. resultAt and winnerExpiresAt are prospective.
+/// They hold until the next StandingChanged, which while matchCount is zero
+/// only a join before the joining deadline can produce. Both are zero while
+/// matchCount > 0.
+event StandingChanged(
+    uint256 matchCount,
+    Tree.Node dangling,
+    Tree.Node parentCommitment,
+    Time.Instant resultAt,
+    Time.Instant winnerExpiresAt
+);
```

Mutator signatures, CommitmentJoined, MatchDeleted, EpochSealed, and
EpochStaged are unchanged. All instants are block numbers with inclusive
expiry, as in the rest of the contract. An expiry at block d means d is the
first expired block, so a transaction must be included before d.

## Semantics

### Descriptor and bond value on creation events

TournamentCreated, emitted by the factory for a root tournament, and
NewInnerTournament, emitted by a parent for a child, carry the
TournamentDescriptor that the new tournament's tournamentDescriptor() returns
and the wei amount that its bondValue() returns. The descriptor keeps its
existing eight fields in their current order.

| Field | Client use |
|---|---|
| initialHash | Initial agreed machine state |
| baseCycle | Origin for machine coordinates |
| log2Stride | Convert leaf positions to cycles |
| height | Claim geometry and initial bisection height |
| level | Identify the level in the configured tournament table |
| kind | Select leaf or inner sealing |
| startInstant, allowance | Joining deadline, startInstant + allowance |

The bond value is msg.value for joining. The descriptor supplies the claim
geometry, the machine coordinates, and the joining deadline, before which joins
are accepted. A creation event can then schedule its own first jobs, the join
and the elimination of a child that nobody joins, with no view call. It also
makes the log self-contained after the fact. A clone's arguments are otherwise
reachable only through fetchCloneArgs.

TournamentCreated does not tie a root tournament to an application. EpochSealed
does. The factory emits TournamentCreated before the consensus emits
EpochSealed in the same transaction, and a client matches the two by tournament
address.

### Ordered pair on every match event

MatchAdvanced, LeafMatchSealed, and NewInnerTournament identify their match
only by hash. Without a map from hash to pair filled from MatchCreated, a
client holding one side cannot tell from the event that the match is its own,
and no client can name the Match.Id calldata that every call on a match takes,
eliminateMatchByTimeout included. That map is per-match state. With the pair
on the event, the handler for a match event is a function of that event. The
pair goes in data words, not topics. There is nothing to filter on, and the
cost is 512 gas per event.

### currentHeight and responderDeadline

Match.State.currentHeight is in storage at the emit site, after
advanceBisection decrements it. With it and the descriptor height H, the event
alone gives the responder (one when H - currentHeight is even, otherwise two,
the rule Match.responder applies), whether the move is a reveal or a seal (a
seal exactly when currentHeight is one), and the tree coordinate to open,
(segmentStartPosition, currentHeight). The position cannot stand in for the
height. Position zero is aligned to every height, and any position is aligned
to every height up to its trailing zeros. Without the field the client counts
advances per match from a MatchCreated it must have seen, and an off-by-one
opens the wrong node.

responderDeadline is the running clock's startInstant + allowance right after
the transition. MatchCreated carries it too, so a new match schedules its first
timeout window without a view read. eliminableAt minus responderDeadline is the
waiting side's paused allowance, so a client never needs responseBudget.

### LeafMatchSealed

These are the fields of Dave's own proposal, oriented to sides one and two.
After the seal both clocks run from the seal block. Either side may prove while
both are unexpired, before min(deadlineOne, deadlineTwo). The longer clock's
side may win by timeout from min(deadlineOne, deadlineTwo) until the later
deadline. Anyone may eliminate from the later deadline, which is eliminableAt.
Equal deadlines leave no timeout window. The transition to prove starts from
agreeState at cycle baseCycle + (divergencePosition << log2Stride), the same
Commitment.toCycle the contract uses, and its result must equal the prover's
side of finalStateOne and finalStateTwo, as winLeafMatch checks.

### NewInnerTournament

The sealing transaction has the pair, both contested final states, and the
child's descriptor and bond value in hand. The pair is needed as above. The
contested final states tell a holder which parent side it defends and which
final state its child claim must have. The descriptor and bond value are needed
to join the child and to schedule its elimination if nobody joins. Reading the
final states from the clone's immutable arguments or from the parent's
sealedMatch instead means a view call pinned to the right block, or a
sealed-match record kept from the parent's stream. On the event, the join
decision is a function of the event.

### StandingChanged

Emitted once, after all effects, by joinTournament and by every path that
calls deleteMatch (winMatchByTimeout, eliminateMatchByTimeout, winLeafMatch,
winInnerTournament, eliminateInnerTournament). advanceMatch and the two seal
calls do not change these fields and emit nothing. In the win paths
pairCommitment precedes deleteMatch, so the single emission after deleteMatch
reports the standing after the call.

Each field is storage after the call or a value the call already computes.

- matchCount is storage.
- dangling is danglingCommitment, zero when there is none.
- parentCommitment is _parentCommitment(nestedDispute, finalStates[dangling]),
  the value innerResult reports, for a non-root tournament with a dangling
  commitment. Zero otherwise.
- resultAt is max(startInstant + allowance, lastMatchDeleted) when matchCount
  is zero, the value _timeFinished reports once the joining deadline has
  passed. Zero otherwise.
- winnerExpiresAt is resultAt plus the dangling commitment's paused allowance,
  for a non-root tournament with a dangling commitment and no matches. That is
  the boundary _winnerExpired tests and tournamentStanding reports. Zero
  otherwise.

The prospective values are exact. A dangling commitment's clock is paused and
cannot change until it is paired. Pairing needs a join, which the joining
deadline forbids afterwards, or a win, which needs a live match. So while
matchCount is zero, the only call that can change these values is a join before
the joining deadline. With a dangling commitment, that join pairs it and emits
MatchCreated and a StandingChanged with matchCount one. Without one, it emits
a StandingChanged carrying the new dangling commitment. Either way the new
StandingChanged supersedes the earlier values. The latest StandingChanged per
tournament therefore schedules a child's propagation and elimination, a root's
staging, and bond recovery. No innerResult or tournamentStanding read is
needed.

Closure and winner expiry are time-driven, but the instants that drive them
are fixed at the last state change, and the contract can emit them there. No
standing read per tournament remains.

The tournament does not need to know its epoch. A client associates
EpochSealed's epoch number with its tournament address and stages when the
root's StandingChanged shows no matches and a dangling commitment it holds.

## The conversion table

This is the acceptance test for the ask. Every cell names only event fields,
the emitted descriptor, an identity from a creation event, or the client's own
claims. If a row needs anything else, the ask is incomplete. H is the
descriptor height. "Holder of x" means the client holds commitment x. "Claimer
of x" means the client's own join established x, which the submitter on
CommitmentJoined shows. The "children" of a claim are the two child hashes
that combine to produce its computation hash.

| Event | Jobs | Fixed arguments | Machine-derived arguments | Window |
|---|---|---|---|---|
| TournamentCreated(R, descriptor, bondValue) | populate R's context for association with EpochSealed | R, descriptor, bondValue | none | immediate |
| EpochSealed(epoch, lo, hi, initialHash, R) | associate R with the epoch and join R | bond value from TournamentCreated | computation hash over inputs [lo, hi), its last-leaf proof, and its children | before R's joining deadline |
| MatchCreated(h, one, two, leftOfTwo, responderDeadline, eliminableAt) | holder of one responds at height H from position 0. Holder of two may win by timeout. Anyone may eliminate | matchId = (one, two) | children of the revealed node and of the selected child, or the seal when H is one | respond before responderDeadline. Timeout win in [responderDeadline, eliminableAt). Eliminate from eliminableAt |
| MatchAdvanced(h, one, two, otherParent, leftNode, pos, currentHeight, responderDeadline, eliminableAt) | responder is one when H - currentHeight is even, else two. Same three jobs | matchId | opening of the responder's node at (pos, currentHeight) against leftNode, or the seal when currentHeight is one | same |
| LeafMatchSealed(h, one, two, agreeState, pos, f1, f2, d1, d2, eliminableAt) | either holder proves. Holder of the longer clock may win by timeout. Anyone may eliminate | matchId and the holder's children | proof of the transition at baseCycle + (pos << log2Stride) | prove before min(d1, d2). Timeout win in [min, max). Eliminate from max |
| NewInnerTournament(h, C, one, two, f1, f2, descriptor, bondValue) | cancel the parent match's three jobs. Holders of one or two join C. Everyone follows C's stream and installs P.eliminateInnerTournament(C), where P is the emitter | C, descriptor, bondValue | commitment over C's window with final state in {f1, f2} | join before C's joining deadline. Eliminate from C's joining deadline |
| MatchDeleted(h, one, two, reason, winner) | cancel the match's three jobs and any linked child's propagation and elimination. Keep the child's bond recovery | | | |
| StandingChanged on child C of (P, h) | matchCount > 0 cancels the result jobs. With matchCount 0 and a dangling commitment, the holder of parentCommitment calls P.winInnerTournament(C, children), anyone calls P.eliminateInnerTournament(C), and the claimer of dangling calls C.tryRecoveringBond. With matchCount 0 and no dangling commitment, anyone eliminates | C, parentCommitment | children of parentCommitment | win in [resultAt, winnerExpiresAt). Eliminate from winnerExpiresAt, or from resultAt with no dangling. Recover from resultAt |
| StandingChanged on root R of epoch e | matchCount > 0 cancels the result jobs. With matchCount 0 and a dangling commitment, its holder calls stageTournamentResult(e, proof) and its claimer calls R.tryRecoveringBond, as separate jobs. With no dangling commitment there is no staging job | e | the MachineValidityProof of the winner's final state | from resultAt |
| CommitmentJoined on T | complete the matching join job, whoever submitted it | | | immediate |
| EpochStaged | complete staging for the epoch, whoever submitted it. Keep R's bond recovery | | | immediate |
| BondRecovered on T | complete T's bond recovery, whoever submitted it | | | immediate |

Match jobs are keyed by (tournament, matchIdHash, kind). Result jobs are keyed
by (tournament, kind) with propagate, eliminate, stage, and recover as separate
kinds, so completing one does not discard another. MatchAdvanced and
LeafMatchSealed replace the three jobs of their match, MatchDeleted cancels
them, and StandingChanged replaces a tournament's result jobs. A client applies
the logs of a head in block, transaction, and log order and runs nothing until
every reachable stream has been processed. The new match and the old match have
different keys, so MatchCreated preceding MatchDeleted inside a winning
transaction needs no special handling.

CommitmentJoined, EpochStaged, and BondRecovered exist today and their rows
need no ABI change.

## Cost

Event data costs 256 gas per word. MatchAdvanced gains four words, 1,024 gas
per advance, three of them beyond responderDeadline. That is about 92k over the
90 advances of a descent through a two-level table with heights 55 and 37.
MatchCreated gains one word. LeafMatchSealed
gains eight words, once per leaf match. NewInnerTournament gains thirteen words
and TournamentCreated nine, once per tournament. StandingChanged is one topic
and five words, about 2k per join, win, or elimination. The cost of computing
the new fields must be measured with the emissions implemented, and Dave's
refund calibration run remains mandatory.

## Fixtures we ask for

Emission fixtures.

- Creation events carry a descriptor equal to all eight fields of
  tournamentDescriptor() and a bond value equal to bondValue(), for both kinds
  and levels and for children with differing coordinates and allowances.
- A root's TournamentCreated precedes the matching EpochSealed in its creation
  transaction, with equal addresses and initial hashes.
- one and two on every match event equal the Match.Id, in both orientations.
- currentHeight equals storage on every MatchAdvanced, in both responder
  parities, with segmentStartPosition aligned to 2^currentHeight.
- StandingChanged is emitted after every join, win, and elimination, never by
  advance or seal, with matchCount and dangling equal to storage.
- Its resultAt and winnerExpiresAt equal tournamentStanding().finishedAt and
  winnerExpiresAt at the first finished block, and innerResult flips from
  WINNER to ELIMINABLE exactly at winnerExpiresAt.
- A join that leaves a dangling commitment before the joining deadline emits
  resultAt equal to the joining deadline. A later pairing emits matchCount one,
  and the earlier values never apply.
- Eliminating both sides of the last match with a third dangling commitment
  emits that commitment, and for a child its parent side.
- An empty child emits nothing after creation and is eliminable at its joining
  deadline from its emitted descriptor alone.
- winMatchByTimeout and winInnerTournament accept the winner's children
  whether the winner is commitment one or two, and reject any other pair.

Timing fixtures. The clock keeps running while a client computes, expiry is
inclusive, and a won child must be propagated before the winner's remaining
allowance runs out.

- Every window in the table holds at the block before, at, and after each
  boundary, for both bisection orientations, and for equal and unequal leaf
  deadlines. Equal deadlines leave no timeout-win window.
- A won child's propagation succeeds in [resultAt, winnerExpiresAt), fails at
  winnerExpiresAt and afterwards, and is replaced by elimination at expiry.
  Delay propagation across blocks and transactions. The allowance carried into
  the parent shrinks by the delay and never restarts.

Re-pairing fixtures. A claim fights a sequence of matches, and each new
opponent needs a new child commitment while old bond recoveries stay pending.

- When a win pairs the survivor into a new match, MatchCreated precedes the old
  MatchDeleted within the transaction. Pin this ordering.
- Carry one parent claim through successive opponents whose matches open
  children over different periods. The old deletion leaves the new match's
  jobs intact, the next child needs its own matching commitment, and the
  previous child's bond is recovered independently and later.
- A second join of an already joined commitment reverts, and recovery pays
  the submitter of the first. Holding the commitment does not establish the
  bond.

Separately from the events, the unchanged proof calldata of winLeafMatch needs
CartesiStateTransition acceptance and rejection vectors for ordinary steps,
input delivery including terminal no-ops, absent inputs, reset boundaries,
rejecting resets, transitions after a rejected input, and consecutive rejected
inputs, together with the
root and leaf commitment comparison Dave offered.

## Not in this ask

- Atomic parent settlement is a separate protocol question about the winner
  expiry window and the delay bound. A child does not know its parent address
  today. This proposal keeps the explicit propagation call.
- Removing the recursive walk is a separate contract design question.
