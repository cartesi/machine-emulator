# Contract event requirements for the Lua PRT bridge

This proposal specifies the event changes needed by the
[Lua PRT bridge](prt-lua-bridge.md). These are requested changes, not an
implemented ABI.

A client should turn every event into its next job with a static table. It may
keep its own claims, its own job queue, identities learned once (child tournament
to parent tournament, tournament to epoch), and immutable per-tournament facts supplied by creation
events (descriptor, bond value). It should never maintain tournament state to
recover a value the contract had when it emitted the event.

The match events carry the ordered pair, coordinates, and deadlines needed to
act. The child tournament creation event repeats final states recoverable
elsewhere, for convenience.
StandingChanged supplies the prospective tournament result and expiry blocks.
Creation events for root tournaments and child tournaments must also supply the complete
descriptor and bond value, so discovery and replay need no contract reads for
these values.

The baseline is Dave commit 16d49bf8. Live integration requires a deployment
with all of the event changes below and matching ABI fixtures.

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
+/// They hold unless a later MatchCreated arrives, which only a join before
+/// the joining deadline can produce. Both are zero while matchCount > 0.
+event StandingChanged(
+    uint256 matchCount,
+    Tree.Node dangling,
+    Tree.Node parentCommitment,
+    Time.Instant resultAt,
+    Time.Instant winnerExpiresAt
+);
```

Mutator signatures, CommitmentJoined, MatchDeleted, and EpochSealed are
unchanged. All instants are block numbers with inclusive expiry, as in the rest
of the contract.

## Semantics

### Descriptor and bond value on creation

TournamentCreated, emitted by the factory for a root tournament, and NewInnerTournament,
emitted by a parent tournament for a child tournament, must include the exact
TournamentDescriptor returned by the created tournament's tournamentDescriptor() and the uint256
wei amount returned by bondValue(). Use the existing descriptor type, including
all eight fields in their current order.

| Field | Type | Client use |
|---|---|---|
| initialHash | Machine.Hash | Initial agreed machine state |
| baseCycle | uint256 | Origin for machine coordinates |
| log2Stride | uint64 | Convert leaf positions to cycles |
| height | uint64 | Claim geometry and initial bisection height |
| level | uint64 | Identify the level in the configured tournament table |
| kind | TournamentKind | Select leaf or inner sealing |
| startInstant | Time.Instant | Calculate joining deadline with allowance |
| allowance | Time.Duration | Calculate joining deadline with startInstant |

The emitted bondValue supplies msg.value for joining. The descriptor supplies
the claim geometry, machine coordinates, and joining deadline needed to build a
claim and schedule the initial elimination of an empty child tournament. These
fields are required for discovery of both root tournaments and child tournaments.

The joining deadline is descriptor.startInstant + descriptor.allowance.
New claims are accepted only before that block.

Providing them in creation events removes the client's tournamentDescriptor()
and bondValue() view calls. A client can reconstruct its work from blockchain
events without additional RPC round trips or historical contract reads. A child tournament that receives
no joins still supplies everything needed to schedule its elimination.

This also makes replay across reorgs simpler. Child tournament clones use CREATE, so a
replacement branch can reuse a factory nonce and create a clone with different
immutable arguments at the same address. The replacement creation event carries
the replacement values. Reading them from the surviving event sequence avoids
an address-keyed descriptor cache and its invalidation rules.

TournamentCreated supplies the descriptor and bond value but does not establish
that the root tournament belongs to the client's application. EpochSealed supplies that association.
The factory creation event must precede the matching EpochSealed in the root tournament's
creation transaction. A client uses their matching tournament address to
associate the emitted descriptor and bond with the epoch.

### Ordered pair on every match event

MatchAdvanced, LeafMatchSealed, and NewInnerTournament carry only the match id
hash. A client holding one side cannot recognize its match, cannot name the
Match.Id calldata, and cannot replace the right job without a map from hash to
pair that it filled from MatchCreated and must persist, restore, and replay.
That map is the per-match state this proposal removes. Plain data words, not
topics. There is no filtering need, and the cost is 512 gas per event.

### currentHeight and responderDeadline

Match.State.currentHeight is in storage at the emit site, after
advanceBisection decrements it. With it and the immutable descriptor height H,
the client derives from the event alone the responder (commitment one when
H - currentHeight is even, otherwise two, the rule Match.responder applies),
whether the move is a reveal or a seal (a seal exactly when currentHeight is
one), and the computation hash tree coordinate (segmentStartPosition, currentHeight). The
position cannot stand in for the height. Position zero is aligned to every
height, and any position is aligned to every height up to its trailing zeros.

Without the field the client keeps one counter per live match, started from a
MatchCreated it must have seen. That counter is the last piece of protocol
state a bisection forces on a client once the pair is on the event.

responderDeadline is the running clock's startInstant + allowance right after
the transition. MatchCreated carries it too, so a created match needs no view
read to schedule its first timeout window.

### LeafMatchSealed

After the seal both clocks run from the seal block. Either side may prove
while both are unexpired, that is before min(deadlineOne, deadlineTwo).
The longer clock's side may win by timeout from
that block until the later deadline. Anyone may eliminate from the later
deadline, which is eliminableAt. The transition to prove is at
baseCycle + (divergencePosition << log2Stride) from the descriptor, the same
Commitment.toCycle the contract uses, starting from agreeState.

### NewInnerTournament

The sealing transaction has the pair, both contested final states, the agree
hash, the base cycle, and the inherited allowance in hand. The pair is needed
for the same reason as above. The contested final states tell a holder which
parent side it is defending and which final state its claim in the child tournament must have.

These states are recoverable today, from the child tournament clone's immutable arguments
(fetchCloneArgs over the clone code, readable forever) and from the parent's
sealedMatch view while the child tournament lives. The ask is for convenience and for
post-mortem reading from blockchain events alone, not for availability. The
child tournament's descriptor and bond value are required fields of the same event as specified above.

### StandingChanged

Emitted once per external state-changing call, after all effects, by
joinTournament and by every path that calls deleteMatch (winMatchByTimeout,
eliminateMatchByTimeout, winLeafMatch, winInnerTournament,
eliminateInnerTournament). advanceMatch and the two seal calls do not change
these fields and emit nothing. In the win paths pairCommitment precedes
deleteMatch, so a single emission after deleteMatch reports the final state.

Each field is storage or a value the same transaction already computes.

- matchCount is storage after the call.
- dangling is danglingCommitment after the call, zero when there is none.
- parentCommitment is _parentCommitment(nestedDispute, finalStates[dangling])
  for a non-root tournament with a dangling commitment, the same call
  innerResult makes. Zero for the root tournament or with no dangling commitment.
- resultAt is max(startInstant + allowance, lastMatchDeleted) when matchCount
  is zero, the same value _timeFinished reports once the joining deadline has been reached.
  Zero otherwise.
- winnerExpiresAt is resultAt plus the dangling commitment's paused allowance,
  for a non-root tournament with a dangling commitment and no matches. That is
  the boundary _winnerExpired tests and tournamentStanding reports. Zero
  otherwise.

The prospective values are exact. A join that leaves a dangling commitment with
no matches happens before the joining deadline, and every earlier deletion precedes the
join, so its resultAt is the joining deadline. A dangling commitment's clock is
paused and cannot change until it is paired. Pairing emits MatchCreated and a
new StandingChanged with matchCount one, which cancels the earlier values.
Once the joining deadline is reached, no join is possible and a matchCount of zero is final. So the
latest StandingChanged per tournament, plus the block it was emitted in, is
enough to schedule the child tournament's propagation and elimination, the root tournament's
staging, and bond recovery. No innerResult or tournamentStanding read is needed
to discover any of them.

The tournament does not need to know its epoch. A client pairs
EpochSealed's epoch number and tournament address once and stages when the
root tournament's StandingChanged shows no matches and a dangling commitment it holds.

## What the client keeps

- Its own claims and the machines behind them.
- Its job queue, keyed by (tournament, matchIdHash, kind), with separately
  executable jobs in each (tournament, result) group. Each event replaces or
  cancels the jobs it names. The queue holds the context supplied by creation
  events, including the descriptor and bond value needed by its jobs.
- Identities learned once. Child tournament to (parent tournament, matchIdHash) from
  NewInnerTournament. Root tournament to epoch number from EpochSealed.
- The set of tournament addresses it watches. The recursive walk through
  child tournament event streams remains.

There is no reconstructed match table, advance counter, clock, or standing.

## The conversion table

This is the acceptance test for the ask. Every cell names only event fields,
the emitted descriptor, an identity learned once, or the client's own
claims. If a row needs anything else, the ask is incomplete. H is the
descriptor height. "Holder of x" means the client holds commitment x.

| Event | Jobs | Fixed arguments | Machine-derived arguments | Window |
|---|---|---|---|---|
| TournamentCreated(R, descriptor, bondValue) | populate R's queue context for association with EpochSealed | R, descriptor, bondValue | none | immediate |
| EpochSealed(epoch, lo, hi, initialHash, R) | associate R with the epoch and join R | bond value from TournamentCreated | computation hash over inputs [lo, hi), its last-leaf proof, and the two child hashes that combine to produce it | before R's joining deadline from the emitted descriptor |
| MatchCreated(h, one, two, leftOfTwo, responderDeadline, eliminableAt) | holder of one responds at height H from position 0. Holder of two may win by timeout. Anyone may eliminate | matchId = (one, two) | children of the revealed node and of the selected child, or the seal when H is one | respond before responderDeadline. Timeout win in [responderDeadline, eliminableAt). Eliminate from eliminableAt |
| MatchAdvanced(h, one, two, otherParent, leftNode, pos, currentHeight, responderDeadline, eliminableAt) | responder is one when H - currentHeight is even, else two. Same three jobs | matchId | opening of the responder's node at (pos, currentHeight) against leftNode, or the seal when currentHeight is one | same |
| LeafMatchSealed(h, one, two, agreeState, pos, f1, f2, d1, d2, eliminableAt) | either holder proves. Holder of the longer clock may win by timeout. Anyone may eliminate | matchId and the two child hashes that combine to produce the holder's computation hash | proof of the transition at baseCycle + (pos << log2Stride) | prove before min(d1, d2). Timeout win in [min, max). Eliminate from max |
| NewInnerTournament(h, C, one, two, f1, f2, descriptor, bondValue) | cancel the parent match's three jobs. Holders of one or two join C. Everyone follows C's stream and installs initial P.eliminateInnerTournament(C), where P is the emitter | C, emitted descriptor and bond value | commitment over C's window, final state in {f1, f2} | join before C's joining deadline. Initial elimination from C's joining deadline |
| MatchDeleted(h, one, two, reason, winner) | cancel the match's three jobs and any linked child tournament's propagation/elimination jobs. Preserve its bond recovery | | | |
| StandingChanged on child tournament C of (P, h) | matchCount > 0 cancels the result jobs. matchCount 0 with dangling. Holder of parentCommitment calls P.winInnerTournament(C, children), anyone calls P.eliminateInnerTournament(C), holder of dangling calls C.tryRecoveringBond. matchCount 0 without dangling. Anyone eliminates | C, parentCommitment | the two child hashes that combine to produce parentCommitment | win in [resultAt, winnerExpiresAt). Eliminate from winnerExpiresAt, or from resultAt with no dangling. Recover from resultAt |
| StandingChanged on root tournament R of epoch e | matchCount > 0 cancels the result group. matchCount 0 with dangling. Its holder installs separate stageTournamentResult(e, proof) and R.tryRecoveringBond jobs. Without dangling there is no staging job | e | machine validity proof of the winner's final state | from resultAt |
| CommitmentJoined on tournament T | complete the matching join job, including when another submitter joined the same commitment | commitment identity | none | immediate |
| EpochStaged on the consensus | complete staging for the named epoch, whoever submitted it. Preserve the root tournament's bond recovery | epoch identity | none | immediate |
| BondRecovered on tournament T | complete T's bond-recovery job, whoever submitted it | tournament identity | none | immediate |

Job replacement follows from the event alone. MatchAdvanced and LeafMatchSealed
replace the three jobs of their match. Creating a child tournament schedules
its elimination at its joining deadline in case nobody joins. Later StandingChanged events
cancel or replace that scheduled call as
specified in the table, along with any other calls based on the tournament result.
Propagation, elimination, staging, and bond recovery are distinct jobs within
the result group, so completing one does not discard another.

Apply events to the queue in chain order (block, transaction index, event index
given by RPC logIndex) before running due jobs. This handles a new MatchCreated preceding the old
MatchDeleted inside a winning transaction without reconstructing tournament
state.

CommitmentJoined, EpochStaged, and BondRecovered already exist. Their rows add
no contract ABI changes. Completion and cancellation also apply when another
participant sent the successful transaction. Recovery remains independent of
staging and child tournament propagation.

## Cost

MatchAdvanced gains four data words, adding 1,024 event-data gas per advance.
The total depends on the heights selected for the deployed two-level geometry.
MatchCreated gains one word. LeafMatchSealed gains eight words, about 2k once
per leaf match. NewInnerTournament gains four match words plus the eight-word
descriptor and bond value, for thirteen words once per child tournament. TournamentCreated
gains the descriptor and bond value, for nine words once per root tournament. Each creation
event's descriptor and bond add 2,304 event-data gas. This excludes any additional
execution costs, which must be measured with the emissions implemented.
StandingChanged is one signature topic and five words, about 2k per join, win,
or elimination. The Dave refund calibration run remains mandatory.

## Fixtures we ask for

- Creation events for root tournaments and child tournaments carry a descriptor equal to all eight fields
  of tournamentDescriptor() and a bond value equal to bondValue(). Cover both
  tournament kinds, levels, and differing child tournament coordinates and allowances.
- A root tournament's TournamentCreated precedes the matching EpochSealed in its creation
  transaction. Their addresses and initial hashes agree.
- StandingChanged is emitted after every join, win, and elimination, and never
  by advance or seal. matchCount and dangling equal storage after the call.
- Its resultAt and winnerExpiresAt equal tournamentStanding().finishedAt and
  winnerExpiresAt at the first finished block, and innerResult flips from
  WINNER to ELIMINABLE exactly at winnerExpiresAt.
- A join that leaves a dangling commitment before the joining deadline emits resultAt equal
  to the joining deadline. A later pairing emits matchCount one, and the earlier
  values never apply.
- Eliminating both sides of the last match with a third dangling commitment
  emits that commitment, and for a child tournament its parent side.
- An empty child tournament emits nothing after creation and is eliminable at its joining deadline
  from its emitted descriptor alone.
- currentHeight equals storage on every MatchAdvanced, in both responder
  parities, with segmentStartPosition aligned to 2 to the currentHeight.
- one and two on every match event equal the Match.Id, in both orientations.
- winMatchByTimeout and winInnerTournament accept the two child hashes that
  combine to produce the winning computation hash, supplied by the player in
  both orientations. They reject child hashes that produce a different
  computation hash.
- Unequal leaf deadlines produce the stated prove, timeout win, and eliminate
  windows at the block before, at, and after each boundary.
- When a win pairs its survivor into a new match, MatchCreated precedes the
  old MatchDeleted within the transaction. Pin this event ordering.

## Not in this ask

- Atomic parent settlement is a separate protocol question about the winner
  expiry window and the delay bound. A child tournament does not know its parent tournament address
  today. This proposal keeps the existing explicit propagation call.
- Removing the recursive walk is a separate contract design question.
