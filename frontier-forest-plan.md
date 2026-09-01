# Frontier forest: implement and migrate the PRT claim tree

## Context

`frontier-forest.md` specifies a generic Merkle structure, the frontier
forest, to replace the run-based claim tree in `doc/recipes/prtu.lua`. A
frontier forest is a frontier whose occupied levels retain complete subtrees
instead of only root hashes, so it can answer node queries and append siblings
later. It must stay generic (no machines, computation hashes, mcycle groups, or PRT
refinement) and keep repeated hashes and repeated complete subtrees cheap. The
spec in `frontier-forest.md` is the authoritative design. This plan grounds it
in the code.

## Affected files

- `src/cartesi/hash-tree.lua` - new frontier forest API, `frontier_append`,
  shared helper factoring
- `tests/lua/spec-hash-tree-lua.lua` - unit tests
- `tests/lua/test-computation-hash.lua` - forest parity oracle
- `doc/recipes/prtu.lua` - claim-tree wrapper replaces the runs machinery
- `doc/recipes/prt-player.lua` - builders, refinement, and dishonest players
  migrate to forests
- `doc/recipes/prt-test.lua` - synthetic claims migrate to the wrapper
- `doc/README.md.template` - prose in "Claim trees with repetition" that
  describes runs, `get_runs_node`, and `get_node`
- `doc/README.md` - regenerated documentation

`doc/recipes/prt.lua` (the referee) never touches claim trees, only proofs and
node hashes off the wire. It needs no changes.

## Step 1. Factor shared frontier helpers (hash-tree.lua)

Extract the rules `frontier_push_back` and `frontier_pad_back` share so the
forest reuses them instead of reimplementing alignment, capacity, and carries:

- the below-level alignment assert loop (appears in `frontier_push_back`,
  `frontier_pad_back`, and `frontier_get_root_hash`)
- the binary-carry fold (the `while frontier[level] do` loop), parameterized on
  a combine function so the forest can carry complete trees (building mixed
  nodes) while the frontier carries hashes
- a capacity helper over the leaf count, including pending forest
  values; `frontier_padding_fits` cannot be reused as is for that check
- the two-phase pad walk of `frontier_pad_back`, parameterized the same way

Valid existing frontier behavior must not change. Add an explicit overflow
assert to `frontier_push_back`; `frontier_append` and forest operations use
the same rule. The existing spec-hash-tree-lua tests gate this step, with a new
case for scalar overflow.

## Step 2. frontier_append

Add `frontier_append(frontier, hashes, first, last, log2_hash_size)`:

- append `hashes[first..last]` in order, `first` defaulting to 1 and `last` to
  `#hashes`, `first == last + 1` an empty no-op, invalid ranges rejected
- keep `frontier_push_back(frontier, hash, log2_hash_size)` scalar-only; overflow
  now asserts

Consume the range as maximal aligned complete subtrees. For the plain frontier each
subtree still hashes pairwise to one root, then one carry. Validate
alignment and overflow before hashing. Add spec tests (same roots as repeated
scalar pushes, non-default first/last/log2_hash_size, empty and invalid ranges).

## Step 3. Complete-tree representations

Internal to hash-tree.lua, two tree kinds, each identified by a `kind` field and
carrying its height. Tables remain distinguishable from raw hash strings:

1. Dense tree - a power-of-two capacity and a non-empty partial array
   of equal-height base values. Base values may be opaque hashes or complete
   trees. The final stored value fills every omitted position. Store one
   partial hash array per higher level through the root; an index past a level
   array's end returns its last entry. A one-entry base array is a completely
   repeated tree, a full base array is a dense tree, and an intermediate array
   represents an explicit prefix followed by repetitions.
2. Mixed tree - `left`, `right`, `hash`, joining any two equal-height trees.

Node lookup on a tree routes by kind. Queries below an opaque hash fail with a
clear error. All validation (hash size, heights, equal child heights, indices)
happens before any hashing or mutation, failing closed.

A completed frontier forest can be passed directly to another forest's
`push_back` or `pad_back`; the receiving forest uses its full top entry. No
public internal-tree getter is needed.

## Step 4. Forest construction

`hash_tree.frontier_forest(log2_max_leaves, hash_type)` creates a forest with
the same dense level array as `frontier` (false or a complete tree per
level), plus a pending partial array and an explicit appended-leaf-count counter
(pending values are not in the levels yet). Forest heights are less than 63, so
the capacity and count remain positive Lua integers. Periods 17 and 18 produce
claim heights 55/37 and 54/38; the current period-10 recipe reaches 62. For a
taller claim of height `H`, bundling can keep both component forests below 63
when the bundle height `B` satisfies `B < 63` and `H - B < 63`; the wrapper
composes their sibling arrays.

- `frontier_forest_push_back(forest, value, log2_hash_size)` - appends one raw
  hash or completed forest. A completed forest contributes its full top entry.
- `frontier_forest_append(forest, hashes, first, last, log2_hash_size)` - appends
  a raw hash array slice. Hashes append to
  the pending partial array by reference (copied out of the caller's array at
  call time). A height mismatch or an earlier implied suffix flushes first.
  Raw hashes default to height 0.
- `frontier_forest_pad_back(forest, value, count, log2_hash_size)` - starts or
  extends an implied suffix. The last array value is followed by `pad_count`
  implicit copies. Append the base once when needed, then increase `pad_count`.
  A one-copy pad behaves as a scalar push unless it extends an existing suffix.
  Compatible means same bytes and declared height for raw
  hashes, same object for trees. Never merge an opaque hash with a
  tree on root equality.
- Flush triggers - `push_back` after an implied suffix, a height change, an
  incompatible pad after an implied suffix, or reaching capacity. A flush
  consumes maximal aligned complete subtrees. Each becomes a dense tree, with
  one carry each; mixed nodes are created at carries.

Validate the incoming operation, including its entire reserved range, before a
flush or any other mutation. No `finish`. Reaching capacity flushes immediately,
queries require the forest exactly full, and appends past capacity assert.

## Step 5. Queries

- `frontier_forest_get_root_hash(forest)` - assert complete and return the top
  level's root, O(1); completion already flushed pending work.
- `frontier_forest_get_node(forest, index, height)` - follow the machine API's
  position-first argument order, validate height and 0-based index, descend by
  tree kind, and return the node hash. A partial level
  array returns its last entry for an index past its stored end.
- `frontier_forest_get_siblings(forest, index, into)` - one descent, appending
  siblings from the leaf upward into the supplied array and returning that
  array. It performs no proof formatting or allocation beyond the appended
  entries. Must not be H independent get_node calls.

## Step 6. Tests before migration

`tests/lua/spec-hash-tree-lua.lua`, following its existing lester structure and
small-height reference-tree style:

- scalar vs array push_back root equality, non-default first/last/heights
- empty ranges no-op, invalid ranges, misalignment, overflow all fail
- forest roots equal plain frontier roots over mixed scalar, array, and
  pad_back sequences
- node queries and sibling arrays against a fully materialized reference tree;
  assemble a standard proof from the returned siblings and check it through
  `verify_slice`
- full, one-entry, and explicit-prefix/repeated-suffix partial arrays queryable
  at every stored level
- descending below an opaque nonzero-level hash fails
- scalar, array, pad, and post-completion overflow assert without mutation
- the current height-62 recipe case works; no height-64 support is required

`tests/lua/test-computation-hash.lua` - alongside the existing frontier
assemblies (`check_small_mcycle`, `uarch_mcycle_root`, `uarch_period_root`),
assemble the same trees with a frontier forest and compare against both the
frontier root and the recorded corpus hash. Cover the uarch group layout the
oracles already exercise, ordinary bundles, the all-halted bundle, the
reset-ending bundle, and a fixed-point group repeated across a period (built
as a completed forest passed to pad_back).

## Step 7. Claim-tree wrapper in prtu.lua

Remove `push_run`, `slice_runs`, `seal_runs`, `find_run`,
`compute_repeated_root`, and `get_runs_node` (and their exports). Keep
`new_tree`, but replace its implementation with a wrapper that keeps the
current method API used by prt-player.lua and prt-test.lua: `get_node(h, q)`,
`get_children(h, q)`, `get_root()`, and `prove(index)`.

The wrapper owns PRT's lazy bundle expansion:

- outer forest of height `height - bundle_height`, with bundle roots at its
  local level zero
- query at or above bundle_height subtracts bundle_height and queries the outer
  forest
- query below asks the refine callback for a complete forest of that one
  bundle, checks its root against the stored bundle root before caching
  (mismatch is an error), then queries inside it
- `prove` creates one sibling array, asks the refined bundle forest to append
  its siblings, then asks the outer forest to append the bundle siblings. It
  adds the standard proof fields after those two `get_siblings` calls.

Constructor shape stays `new_tree(height, bundle_height, outer_forest, refine)`
with refine now returning a full bundle forest. Update the `docs:begin`/`docs:end`
regions (`get_runs_node`, `get_tree_node`) to the new code the template should
show, and purge run terminology from comments in favor of the established
terms (state root hash, bundle root, mcycle group, all-halted bundle,
reset-ending bundle, computation hash, proof).

## Step 8. Migrate prt-player.lua and prt-test.lua

prt-player.lua:

- `push_mcycle_collection` / `build_mcycle_claim` - append `collected.hashes`
  directly (first/last, no slicing), pad the input's
  remaining positions and the epoch tail with `pad_back`
- `push_uarch_mcycle` / `push_uarch_collection` / `build_uarch_claim` - real
  bundles via append over the offsets window, halt repetitions via
  pad_back, the reset-ending bundle via one scalar push_back
- a complete fixed-point mcycle group repeated across a period becomes a
  completed forest at the outer forest's local bundle level (built once, passed
  directly to pad_back), keeping its bundle roots reachable for a later match
  walk
- `refine_mcycle_claim` / `refine_uarch_claim` - build the bundle's complete
  forest directly at the window (mcycle refinement already collects exactly the
  bundle window, uarch refinement collects the instruction unbundled and appends
  the window's leaves with first/last plus pad_back).
  `mcycle_hash_offsets` interpretation, break reasons, halt and reset
  positions, and revert tails all stay here.
- dishonest players. The quitter pads a fake hash across the whole tree with
  pad_back. The fabulist uses a PRT-specific patched claim wrapper around the
  honest claim: replace one bundle or leaf, recompute and cache only its ancestor
  path, and delegate unaffected nodes and sibling ranges to the honest claim.
  This needs no generic tree getter.

prt-test.lua builds its synthetic flat and bundled claims through the wrapper
plus forests (`push_run` and runs arrays disappear). The walk, referee, and
transport sections are untouched.

## Step 9. Docs template and verification

- Update the "Claim trees with repetition" prose in
  `doc/README.md.template` (the paragraphs describing runs, repeated squaring
  in `get_runs_node`, and refinement in `get_node`) to describe the frontier
  forest. Keep the include-block keys (`prt_runs_node`, `prt_story`,
  `prt_build_mcycle_claim`, `prt_test_src`) unchanged unless a region rename
  forces it, per doc conventions do not re-flow keys.

Verification, in order:

1. `PATH=/opt/local/bin:$PATH make -C tests run-lua-spec-hash-tree-lua` after
   each hash-tree step.
2. `PATH=/opt/local/bin:$PATH make -C tests test-computation-hash` for the
   corpus parity oracle.
3. Load the environment emitted by `make env`, then run
   `PATH=/opt/local/bin:$PATH lua5.4 doc/recipes/prt-test.lua` with the recipe
   Lua path for the wrapper, walk, and transport; there is no focused Makefile
   target for this recipe program.
4. `PATH=/opt/local/bin:$PATH make -C doc README.md` rebuilds the PRT blocks,
   re-running the full
   tournament recipe end to end and re-rendering the prose. Diff the rendered
   README against expectations.
5. Format and lint each changed tree through the toolchain environment:
   `make toolchain-exec CONTAINER_COMMAND='make -C src format-lua check-format-lua check-lua'`,
   then the equivalent `-C tests` and `-C doc` invocations.

## Order and gating

Follow the implementation order of frontier-forest.md (helpers, dense
push_back, tree representations, forest ops, queries, tests, wrapper,
dishonest paths, checks). Steps 1-6 land and pass before any recipe file
changes, so the generic structure is gated by unit and corpus parity tests
before PRT migrates onto it.
