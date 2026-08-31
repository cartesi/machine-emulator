# Lua PRT bridge implementation plan

## Objective

Build an independent Lua bridge that lets the existing machine-emulator PRT
player defend its commitments against Dave contracts:

```text
Dave task events and block deadlines <-> Lua bridge <-> Lua player
                                      |
                                      +-> signed transactions
```

The bridge is the first consumer of a language-neutral client interface. It may
use other Dave clients as background material, but imports none of their code,
state models, fixtures, or expected results. Contract tests provide the event,
view, and calldata fixtures. Comparing results with another client may expose
disagreements, but cannot by itself establish that this interface is sufficient
or that the bridge is correct.

The first milestone runs one honest player from `EpochSealed`, through the root
and leaf tournaments of the selected two-level geometry, to a root tournament
result. Consensus staging is a separate final stage.

## Prerequisites

Freeze these together before implementation:

1. Dave commit, deployment, chain ID, contract addresses, ABI hash, and event,
   view, and calldata fixtures from the contract tests.
2. The actionable events specified in `please.md`.
3. A compatible two-level descriptor:
   `root.height = 92 - root.log2Stride`, `leaf.log2Stride = 0`, and
   `leaf.height = root.log2Stride`.
4. The machine API for producing the `proofs` argument to `winLeafMatch`.
5. The supported `cast` version and signer configuration.

The Lua player's mcycle-period exponent is
`root.log2Stride - ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE`. For the selected
`[37, 0]` geometry it is 17. The historical three-level `[44, 27, 0]`
deployment is incompatible and must be rejected at startup.

## Design

### Event-driven jobs, not a tournament fold

Each actionable event contains the full ordered match ID, current coordinate,
and values needed for the next move. The bridge keeps only:

- locally held commitments and their players;
- cached root children and final-state proofs;
- the current root/child lineage;
- one replaceable deadline job per local match;
- closure jobs for the current child and root;
- a canonical log cursor and replayable unfinalized suffix; and
- one pending signer nonce and transaction record.

It does not track unrelated commitments, derive the dangling commitment, or
reconstruct `tournamentStanding`. Unrelated permissionless garbage collection
is outside this bridge. If unrelated matches delay closure, a later
`MatchDeleted` causes the bridge to retry the child or root closure read.

### Two sources of jobs

Contract logs create ordinary jobs:

- `TournamentCreated`: cache the root closing block by tournament address;
  install its closure job only when `EpochSealed` names that tournament.
- `EpochSealed`: build and join the root commitment.
- `MatchCreated` or `MatchAdvanced`: reveal or seal when the local commitment
  is the responder.
- `NewInnerTournament`: build and join the local child commitment.
- `LeafMatchSealed`: obtain and submit the transition proof.
- `MatchDeleted`: cancel the match deadline and record whether the local
  commitment survived.

New canonical heads create time jobs:

- claim or eliminate an expired match from its latest event-carried deadlines;
- query `innerResult` at child closure or after a later deletion, then propagate
  or eliminate the child through the existing parent calls; and
- query `canStageTournamentResult`, or simulate `stageTournamentResult`, at
  root closure or after a later deletion.

All `Time.Instant` values are block numbers with inclusive expiry. No decision
uses wall-clock time.

### State-transition proof

The player request remains:

```text
prove_state_transition(input_index, period_index, state_transition_offset)
```

The planned response is:

```text
{ proofs = Base64(bytes) }
```

The player produces the state-transition proof. The bridge decodes the Base64
value and passes the resulting bytes as the `proofs` argument to
`winLeafMatch`.

## Components

```text
doc/recipes/prt-bridge.lua       top-level job loop and player transport
doc/recipes/prt-ethereum.lua     ABI definitions, event jobs, calls, deadlines
doc/recipes/prt-cast.lua         constrained RPC, signer, and publisher adapter
doc/recipes/prt-bridge-test.lua  fixture, replay, and integration tests
src/cartesi/evmu.lua             selectorless ABI value codec additions
tests/lua/spec-evmu.lua          reusable ABI codec tests
```

Keep `prt.lua` and the player algorithms intact. Extract a one-player transport
from `prtu.lua` without depending on subscriptions, `emit`, or the
demonstration phase closer. Tag every request with its originating event or
deadline-job identity and discard a response if that job has been superseded.

Dave meta-cycles are 92-bit integers. Decode them with `evmu`'s big-integer
type, then pass only fitting split coordinates to the player:

```text
input_index             = cycle >> 68
mcycle_in_input         = (cycle >> 20) & (2^48 - 1)
period_index            = mcycle_in_input >> log2_period
state_transition_offset =
    ((mcycle_in_input & (2^log2_period - 1)) << 20) |
    (cycle & (2^20 - 1))
```

## Implementation

### 1. ABI and fixtures

Add selectorless tuple encoding and decoding to `evmu` for event data and
function return data. Define every event and function once with its canonical
signature, indexed fields, value types, output types, and Lua names. Use the
same definition for topic validation, decoding, and calldata generation.

Pin fixtures from the contract tests for:

- every actionable event;
- `innerResult`, `canStageTournamentResult`, and immutable descriptors;
- every mutation calldata shape.

Exercise state-transition proofs produced by `prove_state_transition` through
the actual `CartesiStateTransition` contract. The contract tests must accept
valid proofs and reject malformed proofs.

Represent all Solidity integers at their declared widths; never convert a
92-bit cycle to a Lua number. Require canonical addresses, topics, enum values,
padding, and exact event data length.

### 2. RPC and signing boundary

Only `prt-cast.lua` may invoke `cast` or construct subprocess arguments. Use
`cast rpc` for chain ID, block headers, bounded `eth_getLogs`, EIP-1898
`eth_call`, and receipts. Use `cast mktx` and `cast publish` for signed raw
transactions.

- Read the endpoint from `ETH_RPC_URL`; never persist or print it.
- Never put a raw private key on a command line. Use a keystore, hardware
  signer, or another supported external signer.
- Capture stdout and stderr separately, check exit status, and parse only the
  pinned output format.
- Redact endpoint, account, password, and signer paths from diagnostics.
- Bisect rejected log ranges and sort results by block number, transaction
  index, and log index.

### 3. Canonical cursor and job store

Persist state by atomic replacement. Record:

- deployment and ABI identity;
- last finalized block number and hash;
- the replayable unfinalized block/log suffix;
- local commitment handles, cached claim responses, and recursive lineage;
- current match and closure jobs with their authorizing log or block identity;
- recorded player requests and responses; and
- pending raw transaction, hash, nonce, fee fields, and job identity.

Identify a log by chain ID, block hash, transaction hash, and log index. On each
poll:

1. read finalized and latest heads;
2. prove that the stored unfinalized suffix remains canonical;
3. discard and replay that suffix after a reorg;
4. fetch and process the next bounded log ranges in canonical order;
5. replace jobs by `(tournament, matchIdHash)`; and
6. evaluate deadlines only after all logs through the accepted head.

Duplicate logs and replayed player responses must not create a second action.

### 4. Event handlers

On `TournamentCreated`, cache `closesAt` by tournament address. Do not assume
that every tournament created by the configured factory belongs to this dapp.

On `EpochSealed`, require the cached `TournamentCreated` entry for its
tournament, install the root closure job, reconstruct the exact epoch input
sequence, build the dapp contract and player, request `commit_mcycle_claim`,
and submit `joinTournament`. The first implementation may accept
pre-materialized input files; a live implementation must reconstruct the
existing `EvmAdvance` payload format from rollups input events and verify the
resulting commitment before joining.

On `MatchCreated` or `MatchAdvanced`:

1. validate `one.join(two) == matchIdHash`, geometry, height, and deadlines;
2. derive the responder from the descriptor height and current height;
3. ignore the event unless that responder is a locally held commitment;
4. for `MatchCreated`, use the implicit zero position; for `MatchAdvanced`,
   validate `segmentStartPosition` and compute
   `node_index = segmentStartPosition / 2^currentHeight`;
5. request `reveal_bisection` when `currentHeight > 1`, otherwise request
   `seal_divergence`; and
6. simulate and submit the corresponding contract call.

The emitted position is authoritative. Never infer a descent by comparing node
hashes; equal children make that ambiguous.

On `NewInnerTournament`, match the local parent commitment and its contested
final state, slice `baseCycle`, request `commit_uarch_claim`, cache the response,
join the child, and install its closure job at `childClosesAt`.

On `LeafMatchSealed`, identify the locally held side, slice
`divergenceCycle`, request the state-transition proof, and submit
`winLeafMatch`. Install both deadline alternatives before waiting for the
player so an expired response cannot later be submitted.

On `MatchDeleted`, cancel its deadline job. A replacement `MatchCreated` is an
independent job even when it appears earlier in the same transaction.

### 5. Head-driven handlers

For the latest unsuperseded match job:

- before the responder or leaf deadlines, do nothing;
- when only the opponent has expired and the local commitment survives, submit
  `winMatchByTimeout` with cached root children; and
- at `eliminableAt`, or when both leaf deadlines have arrived, submit
  `eliminateMatchByTimeout` if the match still exists.

At `childClosesAt`, and after each later `MatchDeleted`, call `innerResult` at
the accepted canonical block hash. Propagate only a result that maps to the
local parent commitment and is still a `WINNER`; eliminate an `ELIMINABLE`
child; otherwise wait.

At root closure, and after each later `MatchDeleted`, query
`canStageTournamentResult` or simulate `stageTournamentResult`. The first
milestone reports the resulting root state. Optional consensus integration
requests `prove_outputs_merkle_root` and submits `stageTournamentResult`.

### 6. Safe transaction lifecycle

Each action records its authorizing job, target, function, typed
arguments, calldata, expected deadline or precondition, and simulation block
hash.

Before signing, simulate the exact call from the signer using EIP-1898
`blockHash` with `requireCanonical`, then confirm the head is still canonical.
Persist signed bytes and their hash before publication. Treat the receipt as
provisional until its event is processed.

Keep one pending signer nonce. If its job becomes stale, replace that nonce with
the newly valid action, or with a cancellation when no action is valid and the
nonce would block future work. Never blindly rebuild or republish stale
calldata.

## Validation

Use repository Make targets for all builds, checks, and tests.

- ABI tests: selectorless tuples, indexed values, large integers, dynamic
  bytes, malformed padding, truncation, and byte-for-byte mutation calldata.
- Event tests: both commitment orientations, every bisection branch, equal
  children, sealing by either party, replacement matches, and superseded jobs.
- Deadline tests: the block before, at, and after every responder, elimination,
  leaf, child-close, inner-expiry, and root-close boundary.
- State-transition tests: proofs produced by `prove_state_transition` for every
  supported transition must pass through `CartesiStateTransition`; malformed
  proofs must fail simulation.
- Replay tests: one pass, arbitrary polling ranges, duplicate logs, restart at
  every pending state, and replaced unfinalized suffixes must produce the same
  jobs and actions.
- Anvil tests: honest and adversarial counterparts, missed turns, timeout in
  both orientations, unrelated matches delaying closure, child propagation and
  elimination, stale nonce replacement, and controlled reorgs.

Only after deterministic fixtures and Anvil pass should the bridge run an
opt-in read-only Infura smoke test and then a funded low-stakes testnet trial.

## Completion criteria

The first bridge is ready when:

- one existing honest Lua player defends compatible root and child commitments
  from `EpochSealed` to the root result;
- ordinary moves use only actionable events and local commitment data;
- only match deadlines and child or root closure are evaluated on new canonical
  heads;
- no machine proof encoding exists in the bridge;
- restarts, duplicate logs, RPC retries, and reorgs cannot duplicate a
  successful action;
- every transaction is simulated at a canonical block hash before signing;
- secrets and endpoints never appear in state, logs, or process arguments; and
- contract fixtures, Lua tests, and Anvil scenarios all pass.
