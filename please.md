# Proposal: make tournament events actionable by independent clients

## Summary

An honest tournament client should not need to reconstruct the contract's live
match representation before it can act. Each transaction that creates the next
honest-player task should emit the complete public context for that task.

The interface then has two kinds of trigger:

```text
contract event -> the next available tournament action
new block      -> an action whose deadline has arrived
```

The only tasks not caused by a transaction are caused by block-number deadlines:
a match timeout, tournament closure, and expiry of an inner winner. Those require
watching new heads. Closure already has permissionless consuming calls:
`winInnerTournament` or `eliminateInnerTournament` for a child, and
`stageTournamentResult` for the root. No new finalization transaction or storage
is needed.

This is an ABI change, not a protocol change. It adds no storage, changes no
clock or tournament rule, and gives events only values the emitting transaction
has just validated or computed.

The direction is one Dave has already chosen. The node architecture
documentation assigns events ownership of tournament structure, commitment
placement, match lifecycle, and elimination schedules, with point reads adding
only facts events do not carry. This proposal moves the last per-match facts
(the descent coordinate, the sealed divergence and child configuration, and the
per-side deadlines) from point reads into the events whose transactions compute
them, leaving live reads with immutable descriptors and the terminal closure
capabilities.

## The event changes

The existing events are close to actionable. The factory event needs the root
deadline, and four tournament events need more context:

| event | additional or replacement data |
|---|---|
| `TournamentCreated` | `closesAt` |
| `MatchCreated` | `currentHeight`, `responderDeadline` |
| `MatchAdvanced` | ordered commitments, `currentHeight`, `segmentStartPosition`, `responderDeadline` |
| `LeafMatchSealed` | ordered commitments, sealed divergence, `deadlineOne`, `deadlineTwo` |
| `NewInnerTournament` | ordered parent commitments, child configuration, `childClosesAt` |

`CommitmentJoined` and `MatchDeleted` already contain enough for a client that
does not derive closure from logs. `MatchDeleted` cancels outstanding jobs and
reports the survivor. A replacement `MatchCreated`, when there is one, announces
the survivor's next task independently.

Representative signatures are:

```solidity
event TournamentCreated(
    ITournament indexed tournament,
    Time.Instant closesAt
);

event MatchCreated(
    Match.IdHash indexed matchIdHash,
    Tree.Node indexed one,
    Tree.Node indexed two,
    Tree.Node leftOfTwo,
    uint64 currentHeight,
    Time.Instant responderDeadline,
    Time.Instant eliminableAt
);

event MatchAdvanced(
    Match.IdHash indexed matchIdHash,
    Tree.Node indexed one,
    Tree.Node indexed two,
    Tree.Node otherParent,
    Tree.Node leftNode,
    uint64 currentHeight,
    uint256 segmentStartPosition,
    Time.Instant responderDeadline,
    Time.Instant eliminableAt
);

event LeafMatchSealed(
    Match.IdHash indexed matchIdHash,
    Tree.Node indexed one,
    Tree.Node indexed two,
    Machine.Hash agreeState,
    uint256 divergenceCycle,
    Machine.Hash finalStateOne,
    Machine.Hash finalStateTwo,
    Time.Instant deadlineOne,
    Time.Instant deadlineTwo
);

event NewInnerTournament(
    Match.IdHash indexed matchIdHash,
    ITournament indexed childTournament,
    Tree.Node parentCommitmentOne,
    Tree.Node parentCommitmentTwo,
    Machine.Hash initialHash,
    uint256 baseCycle,
    Machine.Hash contestedFinalStateOne,
    Machine.Hash contestedFinalStateTwo,
    Time.Instant childClosesAt
);
```

`TournamentCreated.closesAt` makes root closure directly schedulable. The child
event repeats its deadline so it remains independently actionable and linked to
its parent match. The exact integer widths should follow the existing contract
types. The ABI and generated bindings are one coordinated version boundary.

## Why each field is necessary

### Bisection jobs

`advanceMatch` takes the full ordered `Match.Id`, but `MatchAdvanced` currently
contains only its hash. Hashes are not reversible, so a client must otherwise
retain the earlier `MatchCreated` event. Repeating `one` and `two` makes the
advance independently actionable.

`currentHeight` tells the client whether to request another bisection opening or
seal the divergence. The responder follows from the initial tournament height,
the current height, and the ordered match ID, using the same turn rule documented
by the contract. In `MatchCreated` it equals the descriptor height and is
included so that every match event stands alone.

`segmentStartPosition` gives the exact computation coordinate. It cannot always
be recovered by comparing `otherParent` with the prior waiting-left node. When
the waiting commitment's children are equal, both descents produce the same
node. Equal children are common in padded computations and fabricated claims.
Independent clients can use this position directly as the first leaf covered
by the node at `currentHeight`. Per-level node indices are an internal Dave
representation and, when required by a call, belong at the contract adapter
boundary rather than in a client's tree or proof model.

`otherParent` and `leftNode` remain the inputs the next responder needs. With
the descriptor, this one event contains the complete request for either
`reveal_bisection` or `seal_divergence` and the complete `Match.Id` for the
resulting contract call.

### Sealing jobs

Once a leaf is sealed, anyone may provide the state-transition proof. The
event must therefore identify the full match and the transition:

- the state before the disputed transition;
- its absolute meta-cycle;
- the two ordered claimed successor states; and
- the two inclusive clock deadlines.

For a non-leaf seal, the child event must identify the parent commitments and
the complete child dispute: initial state, base cycle, ordered contested final
states, and closing block. That is enough to construct and join the appropriate
child commitment without reading `sealedMatch` or the child's live state.

### Deadlines

During bisection, the responder loses at `responderDeadline`. From that block
until `eliminableAt`, the waiting side may call `winMatchByTimeout`; from
`eliminableAt`, anyone may call `eliminateMatchByTimeout`.

After a leaf seal both clocks run. If exactly one emitted deadline has been
reached, the other side may win. If both have been reached, anyone may eliminate
both. All boundaries are inclusive and use block numbers, never wall-clock time.

Emitting the deadlines avoids duplicating `Clock` and `MatchClocks` arithmetic
in every language. A later progress or deletion event supersedes the old job for
the same `(tournament, matchIdHash)`.

## What remains block-driven

Solidity cannot emit an event merely because `block.number` reached a value.
Three jobs therefore start on a new head rather than a log:

1. resolve an expired match using its latest emitted deadlines;
2. inspect a child at `childClosesAt`, and again after a later `MatchDeleted` if
   unrelated matches kept it active;
3. inspect the root at its closing block, and again after later deletions.

For child closure, read `innerResult` and then use the existing permissionless
`winInnerTournament` or `eliminateInnerTournament`. For root closure, call
`canStageTournamentResult`, then submit the result with its outputs proof.
These reads are used only to close a child or root tournament, not to recover
ordinary match state.

A separate `finalizeTournament` transaction would not remove head monitoring:
someone would still have to call it after closure. If it only emitted an event,
it would add a redundant transaction; if it stored the result, it would add a
new state machine and carryover invariant. The existing consuming calls are the
simpler boundary.

## Cost

The recurring cost is the additional data on `MatchAdvanced`. Relative to the
current event, the actionable form adds two indexed commitment topics and three
data words (`currentHeight`, `segmentStartPosition`, and
`responderDeadline`). The direct log cost is about 1,500 gas per advance, or
about 137,000 gas over the 90 advances in the selected two-level path. Compiler
and memory overhead must be measured, but this is about 1.3% of the roughly
10.3 million gas used by 90 current `advanceMatch` calls.

For scale, 137,000 gas costs 0.00137 ETH at 10 gwei. At an illustrative
$2,350/ETH that is $3.22 across the whole path, normally split between the two
responders. The contract gas calibration, rather than this estimate, remains
the release evidence.

## Payoff

An honest client can act from the latest event concerning one of its
commitments, plus immutable tournament descriptors and block-number deadlines.
It does not need to recover match phases or bisection coordinates through live
views, retain earlier match events to invert an ID hash, or reproduce contract
clock arithmetic. The same interface can be implemented independently in any
language.

The first such client is already specified. The Cartesi machine emulator's PRT
documentation ships an honest Lua player for the two-level shape, and its
planned bridge takes these actionable events as a prerequisite.
