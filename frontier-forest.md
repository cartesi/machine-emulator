# Frontier forest implementation plan

## Goal

Replace the PRT recipe's run-based claim tree with a general Merkle structure that
retains the complete power-of-two subtrees accumulated by a frontier. The common
case is an array of distinct bundle roots. Repeated hashes and repeated complete
subtrees must remain cheap.

This is not run-length encoding. A frontier forest decomposes the appended prefix
into aligned complete subtrees, just as `frontier` decomposes its leaf count into
set bits. The difference is that a frontier forest retains enough structure to
return nodes and append sibling hashes later; a frontier retains only subtree
root hashes.

The implementation must not know about machines, computation hashes, mcycle
groups, or PRT refinement.

## Public API

Add the following functions to `src/cartesi/hash-tree.lua`, following the existing
module-style frontier API:

```lua
local forest = hash_tree.frontier_forest(log2_max_leaves, hash_type)

hash_tree.frontier_forest_push_back(forest, hash_or_forest, value_height)
hash_tree.frontier_forest_append(forest, hashes, first, last, hash_height)
hash_tree.frontier_forest_pad_back(forest, hash_or_forest, count, value_height)

hash_tree.frontier_forest_get_root_hash(forest)
hash_tree.frontier_forest_get_node(forest, position, height)
hash_tree.frontier_forest_get_siblings(forest, position, height, into)
```

- `push_back` appends one raw hash or completed forest.
- `append` appends raw `hashes[first..last]` in order. `first` defaults to 1
  and `last` defaults to `#hashes`.
- A raw hash has the supplied `hash_height` or `value_height`, defaulting to zero.
  A completed forest carries its own height, which must match `value_height` when supplied.
- Indices are inclusive. `first == last + 1` is an empty no-op range.
- Both operations require the current leaf count to be aligned to
  the supplied height and reject overflow.

`pad_back` appends `count` copies of one raw hash or completed forest.
Its count is in units of the supplied subtree, as it is for
`frontier_pad_back`. A raw hash at a nonzero level is opaque: its descendants
cannot be recovered. Supplying a completed forest preserves its descendants
and is required when a caller may later query inside that subtree. The
receiving forest uses the completed forest's full top entry.

There is no `finish`. A forest has fixed capacity. Reaching capacity immediately
flushes pending work. Root, node, and sibling queries require the forest to be
exactly full, and further appends assert as overflow.

Node and sibling queries identify their target by `(position, height)`, where
position is the target node's first covered leaf and must be aligned to
`2^height`. The sibling result starts at the target node and climbs to the
forest root, so it can prove an internal node without descending to a leaf.

Add `frontier_append` with the same array operation. Keep all valid
`frontier_push_back` and `frontier_pad_back` behavior, but make scalar overflow
assert just like array overflow.

## Representation

A frontier forest has the same dense level array as `frontier`. An empty level is
`false`; an occupied level contains a complete subtree rather than only
its root hash. The occupied levels still encode the appended leaf count.

The forest also has one pending accumulator. It owns a partial array of
equal-height base values and a `pad_count`. The last array value is followed by
`pad_count` implicit copies. Consecutive `push_back` calls extend the explicit
array while `pad_count` is zero. `pad_back` records its base once and increases
`pad_count`; a one-copy `pad_back` behaves as a scalar `push_back` unless it
extends an existing compatible suffix.

The forest stores the total appended leaf count explicitly because pending values are
not yet represented by occupied frontier levels. Capacity and overflow checks
include both the frontier and the pending accumulator.

Every occupied frontier entry is one complete tree. There are exactly two
representations:

1. A dense tree has a power-of-two capacity and a non-empty partial array of
   equal-height base values. Each base value is either an opaque hash or an
   dense or mixed tree taken from a completed forest. The last stored value
   fills every omitted position.
   Each higher level is another partial hash array with the same rule: indexing
   beyond its end returns its last entry. Levels continue through the root even
   after their stored length reaches one. This one representation covers a
   fully explicit tree, a completely repeated tree, and an explicit prefix
   followed by repetitions of its last value.
2. A mixed tree stores an actual node with `left`, `right`, and `hash`. Each
   child is a dense or mixed tree. Mixed nodes join complete trees produced by
   different pending regions or binary carries.

Each complete tree also carries the height needed to validate combinations and
route queries. All base values in a dense tree have that same height. A raw hash
is opaque below its declared height; a base tree can be queried below
that height through its own representation.

A completed frontier forest can be supplied directly as a scalar value to
another forest. The receiving forest considers its full top entry the complete
tree value. This is how a fixed-point mcycle group is built once and repeated
without exposing an internal tree getter.

The representation must reject a query below an opaque input hash. PRT handles
such a query by constructing and validating a separate forest for that bundle;
the generic forest does not call a refinement callback.

All construction checks fail closed: validate hash sizes, heights, positions,
alignment, capacity, and equal child heights before hashing or modifying the
frontier forest.

An individual forest supports heights below 63, keeping its capacity and positions
in positive Lua integers. Bundling can split a taller claim of height `H` into an
inner forest of height `B` and an outer forest of height `H - B`; both fit when
`B < 63` and `H - B < 63`. Periods 17 and 18 already give total claim heights
55/37 and 54/38, so they need no bundle-size constraint for this purpose.

## Construction algorithms

Share the alignment, capacity, and carry rules with the existing frontier rather
than maintaining a second interpretation of them.

### `push_back` and `append`

`push_back` and `append` add their values to the pending partial array when its
base height matches. `push_back` extends an implied suffix when its value is
compatible, while `append` flushes any implied suffix first. A different base
height or incompatible pushed value also flushes pending work. The array range
is copied as references when the call is made, so later mutation of the caller's
array cannot change the forest. No parent hashes are computed yet.

When pending work is flushed, consume its `#values + pad_count` entries as maximal aligned
complete subtrees. Each becomes one dense tree. A subtree inside the explicit
prefix stores all of its values. A subtree crossing into or contained in
the repeated suffix stores only the available prefix through the repeated base;
the last-entry rule supplies the rest. Perform one binary carry per subtree.
Hashes are computed once per stored parent. Flushing is linear in the number of
stored explicit values plus O(tree height), independent of the length of the
repeated suffix.

Implement the same range traversal for `frontier_append`, but retain only the
root of each complete subtree there.

### `pad_back`

Preserve the interval decomposition used by `frontier_pad_back` when pending
work is flushed:

1. Complete occupied low levels and carry upward.
2. Decompose the remaining count into powers of two and place the corresponding
   partially filled dense trees directly into empty levels.

`pad_back` appends its base to the pending partial array once, then records the
additional implicit copies in `pad_count`. If the partial array already ends in
a compatible base, it need not append it again. Raw hashes are compatible when
their bytes and declared heights match. Trees are compatible when they
are the same object. Do not merge an opaque hash with a tree
merely because their root hashes match: that could discard descendant
information.

If pending work already has an implied repeated suffix with an incompatible
base, or has a different base height, flush it first. The last-entry rule then
represents the new repeated region without a separate repeated-tree kind.

The operation must have the same alignment, fit, overflow, and count-zero
behavior as `frontier_pad_back`. Validate and reserve the complete requested
range when `pad_back` is called, not later when it is flushed.

### Flushing

Flush the pending accumulator when:

- `push_back` follows an incompatible implied repeated suffix;
- `append` follows an implied repeated suffix;
- a value has a different base height;
- `pad_back` follows an incompatible implied repeated suffix; or
- the leaf count reaches the forest capacity.

Consecutive `push_back` calls therefore form one dense tree even when the hashes
arrive in several collections. An explicit prefix followed by `pad_back` also
forms one partially filled dense tree. Consecutive compatible `pad_back` calls
only extend `pad_count`. Mixed nodes occur at actual boundaries between
incompatible regions and during binary carries.

Most calls only validate and extend the pending accumulator. A flush performs
work proportional to its stored values, its power-of-two decomposition, and its
carries. It remains O(stored values + tree height) in the worst case and is paid
once per maximal compatible region.

### Queries

Once the forest is full, its top entry is the complete root subtree.

- `get_root_hash` returns that entry's root hash in O(1). Completion has already
  flushed all pending work.
- `get_node(position, height)` follows the machine API's position-first
  argument order. It descends through mixed trees or indexes the appropriate
  partial level array, using its last entry when the index is past the stored
  end. It validates the requested height and aligned 0-based position.
- `get_siblings(position, height, into)` descends once and appends siblings
  from the target node upward to `into`. A caller can first append a bundle
  forest's siblings and then append the outer forest's siblings to form one
  proof. Siblings are collected temporarily so a failed descent leaves `into`
  unchanged.

Queries do not alter the committed structure. All hashes needed by a complete
tree are computed when that tree is constructed; queries need no hash cache.

## PRT recipe migration

Replace `push_run`, `slice_runs`, `seal_runs`, `find_run`,
`compute_repeated_root`, and `get_runs_node` in `doc/recipes/prtu.lua`. Keep
`new_tree` and its method API, but implement it as a small claim-tree wrapper
around frontier forests.

The wrapper owns PRT-specific lazy bundle expansion:

1. The outer forest has height `claim_height - bundle_height`, so bundle roots
   are its level-zero nodes.
2. A query at or above bundle height subtracts bundle height and queries the
   outer forest.
3. A query below bundle height asks the player to construct a separate complete
   forest for that bundle.
4. Before caching it, compare its root hash with the bundle root stored in the
   outer forest. A mismatch is an error.
5. Proof construction asks the refined bundle forest to append its siblings,
   then asks the outer forest to append the bundle siblings into the same array.
   The wrapper adds the standard proof fields; `hash-tree.lua` does not learn
   about refinement.

Update `doc/recipes/prt-player.lua` as follows:

- Send ordinary arrays from `collected.hashes` directly to `append`, using
  `first` and `last` rather than copying a slice.
- Use `pad_back` for an all-halted bundle and for fixed-point padding.
- Append the reset-ending bundle once with scalar `push_back`.
- Build a complete forest for a fixed-point mcycle group and pass that forest
  directly to `pad_back`. Passing only its root hash would make its bundle roots
  unavailable during a later match walk.
- Keep the interpretation of `mcycle_hash_offsets`, break reasons, halt/reset
  positions, and revert tails in `prt-player.lua`; none belongs in the generic
  forest.
- Adapt the deliberately dishonest claims without expanding the entire honest
  claim. Use a PRT-specific patched claim wrapper that delegates unaffected
  nodes to the honest claim and rebuilds only the changed ancestor path.

Remove the run terminology from the recipe comments after the migration. Use
the existing terms `state root hash`, `bundle root`, `mcycle group`,
`all-halted bundle`, `reset-ending bundle`, `computation hash`, and `proof`.

## Comparison with Dave's Merkle tree

Dave's `MerkleBuilder` stores one `{ hash, accumulated_count }` cell per `add`
call. It does not merge adjacent calls with the same value. `build` recursively
binary-searches those cumulative counts. A region covered by one cell uses
`iterated_merkle`; a region crossing a cell boundary splits into two and joins
the resulting hashes.

The resulting Dave tree is not represented only by those cells. Every joined
`Hash` retains `left` and `right`, and repeated hashes retain their iterated
hashes in process-global tables. Proof generation walks that linked hash
graph. Dave also permits a builder cell to contain a complete `MerkleTree`, so
both repetition and arrays of complete trees are already recursive there.

Let:

- `H` be the resulting tree height;
- `N` be the number of explicit base values;
- `R` be the number of Dave builder cells;
- `M` be the number of mixed internal nodes created by Dave's recursive build;
- `S` be the slots stored across a frontier forest's partial level arrays; and
- `J` be its mixed node count.

### Representation size

| Shape | Dave | Frontier forest |
| --- | --- | --- |
| One base tree repeated to height `H` | One cell and `O(H)` linked `Hash` objects | One base value and one hash in each of `O(H)` partial level arrays |
| `N` mostly different values | `N` cell tables and `N - 1` linked `Hash` objects | `2N - 1` array slots across `O(H)` level arrays |
| An explicit prefix of `N` values followed by repetitions | `O(N + M)` cells and linked hashes | `O(N + H)` partial-array slots and hashes |
| Mixed incompatible regions | `O(R + M)` cells and mixed nodes, plus cached repetition chains | `O(S + J)` partial-array slots and mixed nodes |

Both representations are `O(H)` for one repeated region and `O(N)` for a dense
tree. Irregular regions can require `O(RH)` structure in either representation.
Alignment to power-of-two subtrees reduces that bound in both.

The expected constant-size advantage of a frontier forest is in the dense case.
It stores parent hashes in a small number of Lua arrays. Dave retains one table
per builder cell and one table with `digest`, `left`, and `right` per joined
hash, in addition to the process-global hash interning and repetition tables.
Dave may share identical internal hashes globally; a frontier forest shares
only the complete trees referenced by its partial arrays and mixed trees.

### Operation complexity

| Operation | Dave | Frontier forest |
| --- | --- | --- |
| Create | `O(1)` | `O(H)` for the fixed frontier |
| Append one explicit value | `O(1)` | Amortized `O(1)` while pending; hashing occurs on flush |
| Append `K` explicit values | `O(K)` calls or assignments, without hashing | `O(K)` reference copies while pending and `O(K + H)` on flush |
| Make `Q` compatible repeated appends | `O(Q)` cells | `O(Q)` accumulation and one `O(H)` worst-case flush |
| Build a queryable tree | Recursive build after all cells are present | No separate build; the last flush completes the tree |
| Read the completed root | `O(1)` after `build` | `O(1)` after the pending accumulator is flushed |
| Read an arbitrary node | `O(H)` graph traversal; no direct public operation | `O(H)` worst case, often `O(1)` within one partial level array |
| Append siblings | `O(H)` proof traversal | `O(H)` with one descent and no proof allocation |
| Replace one subtree | `O(H)` hashes | `O(H)` hashes to rebuild the affected mixed path |

Dave makes `add(hash, count)` `O(1)` by deferring all tree work to `build`.
If `V` recursive regions are visited during `build`, its count lookups take at
most `O(V log R)` and its hashing is proportional to the mixed nodes and
previously uncached repetition levels. Here `V` is bounded by the materialized
tree size and is `O(RH)`.

The frontier forest instead defers work until an incompatible value or an array
append follows an implied suffix, the base height changes, or the forest fills.
Completion flushes immediately, so all valid queries see a materialized tree.
Consequently, compatible repeated calls have the same `O(Q)` accumulation cost
as Dave plus one final `O(H)` flush. Alternating incompatible regions can still
cost `O(QH)`, but their boundaries also cause Dave's recursive build to retain
mixed nodes.

The frontier forest does not reduce the number of Merkle hashes required for a
dense tree. Its intended benefits are lower Lua table overhead, batching arrays
returned by the emulator, incremental construction, and direct node access.

`get_siblings` must descend once while appending siblings. Implementing it as
`H` independent `get_node` calls could take `O(H^2)` and is not acceptable.

## Validation

Add focused cases to `tests/lua/spec-hash-tree-lua.lua`:

- Scalar and array `push_back` produce the same roots as repeated scalar calls,
  including non-default `first`, `last`, and `hash_height`.
- Empty ranges are no-ops; invalid ranges, misalignment, and overflow fail.
- Forest roots match ordinary frontier roots for mixed scalar, array, and
  `pad_back` sequences.
- Node queries and sibling arrays match a fully materialized reference tree.
- Fully explicit, fully repeated, and explicit-prefix/repeated-suffix dense
  trees can be queried at every stored level.
- Descending below an opaque nonzero-level hash fails.
- Overflow asserts without hashing or mutating the forest.
- The practical period choices 17 and 18 produce claim heights 55/37 and
  54/38. The current demonstration still uses period 10 and reaches height 62;
  keep that test working without adding height-64 count semantics.

Extend `tests/lua/test-computation-hash.lua` to assemble the existing mcycle and
uarch computation hashes with a frontier forest and compare them with both the
ordinary frontier and the saved expected hashes. Include the special uarch group
layout: ordinary execution bundles, the all-halted bundle, and the reset-ending
bundle, plus a fixed-point group repeated across the remainder of a period.

Run Lua formatting and lint checks through the Makefile-managed toolchain. Run
the documented hash-tree, computation-hash, and PRT recipe tests with the
environment emitted by `make env` and the required MacPorts path on macOS.

## Implementation order

1. Factor shared frontier alignment, capacity, and carry helpers without changing
   valid existing behavior; make overflow assert.
2. Add `frontier_append` and its tests.
3. Implement the dense and mixed complete-tree representations.
4. Implement forest `push_back` and forest `pad_back` using those trees.
5. Implement full-forest node and sibling queries.
6. Add unit and computation-hash parity tests.
7. Replace the PRT run tree with the claim-tree wrapper and frontier forests.
8. Adapt the fixed-point and deliberately dishonest claim paths.
9. Run the focused checks, the PRT recipe test, and the required static checks.
