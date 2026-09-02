local cartesi = require("cartesi")

-- Tree leaves are words, the smallest proof target.
local WORD_LOG2_SIZE = cartesi.HASH_TREE_LOG2_WORD_SIZE
local WORD_LENGTH = 1 << WORD_LOG2_SIZE

-- docs:begin roll_hash_up_tree
local function roll_hash_up_tree(proof, target_hash, hash_type)
    local hash_function = cartesi[hash_type or "keccak256"]
    local hash = target_hash
    for log2_size = proof.log2_target_size, proof.log2_root_size - 1 do
        local sibling = assert(proof.sibling_hashes[log2_size - proof.log2_target_size + 1], "too few siblings")
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = sibling, hash
        else
            first, second = hash, sibling
        end
        hash = hash_function(first, second)
    end
    return hash
end
-- docs:end roll_hash_up_tree

-- docs:begin verify_slice
local function verify_slice(proof, hash_type)
    assert(roll_hash_up_tree(proof, proof.target_hash, hash_type) == proof.root_hash, "target node not in tree")
end
-- docs:end verify_slice

-- docs:begin verify_splice
local function verify_splice(proof, new_target_hash, new_root_hash, hash_type)
    verify_slice(proof, hash_type)
    assert(roll_hash_up_tree(proof, new_target_hash, hash_type) == new_root_hash, "target node not in tree")
end
-- docs:end verify_splice

-- Computes the Merkle tree root of a byte string laid at the base of a tree covering
-- 2^log2_root_size bytes. The data need not fill the tree or be a power of two long. Leaves
-- are word-size keccak256 hashes, a trailing partial word zero-padded, and inner nodes hash
-- their two children. Every node the data does not reach takes its level's pristine hash, the
-- root of an all-zero subtree, which doubles each level climbed. Overflow is rejected.
-- docs:begin get_data_root_hash
local function get_data_root_hash(data, log2_root_size, hash_type)
    local hash_function = cartesi[hash_type or "keccak256"]
    assert(#data <= (1 << log2_root_size), "data does not fit in the tree")
    -- Level zero is one hash per word, a trailing partial word zero-padded after the loop.
    local level = {}
    local full = #data - #data % WORD_LENGTH
    for i = 1, full, WORD_LENGTH do
        level[#level + 1] = hash_function(data:sub(i, i + WORD_LENGTH - 1))
    end
    if full < #data then
        local word = data:sub(full + 1)
        level[#level + 1] = hash_function(word .. string.rep("\0", WORD_LENGTH - #word))
    end
    -- Pair upward to the root, the pristine hash standing in for every node the data misses.
    local pristine = hash_function(string.rep("\0", WORD_LENGTH))
    for _ = WORD_LOG2_SIZE, log2_root_size - 1 do
        local parents = {}
        for i = 1, #level, 2 do
            parents[#parents + 1] = hash_function(level[i], level[i + 1] or pristine)
        end
        level, pristine = parents, hash_function(pristine, pristine)
    end
    return level[1]
end
-- docs:end get_data_root_hash

-- The functions below are a generic incremental keccak Merkle accumulator (a "back merkle
-- tree") for the CMIO outputs Merkle tree: a fixed-height tree whose leaves are keccak256(output),
-- accumulating from genesis and padded on the right with pristine subtrees. Unlike the
-- word-leaf memory tree above, its pristine leaf is literally HASH_SIZE zero bytes (not a
-- hash of them), matching libcmt's cmt_merkle_t and tests/lua/cmio-test.lua. Nothing here is
-- output-specific; the caller feeds keccak256(output) leaves.
--
-- A frontier captures the complete left subtrees standing over the leaves seen so far. It is a
-- table with a length-(log2_max_leaves + 1) array part indexed by a 1-based level, where level 1
-- corresponds to bit 0 (the 0-based leaves). Entry level holds that level's complete left subtree
-- when the matching bit of the leaf count is set, else false (false, not nil, so the array stays
-- dense). Its hash_function field holds the resolved hash function. The present subtrees' sizes sum to
-- the leaf count, so the count is recovered from the array rather than stored. The top entry holds
-- the root when the tree is exactly full.

-- The pristine leaf, the all-zero subtree of height 0, is literally HASH_SIZE zero bytes. Larger
-- pristine subtrees double on demand inside each loop (keccak256(pristine, pristine)).
local pristine_leaf = string.rep("\0", cartesi.HASH_SIZE)

-- The leaf count standing under a frontier: a level is filled exactly when its bit of the count is
-- set, so summing those bit values over the filled levels recovers it.
local function frontier_leaf_count(frontier)
    local leaf_count = 0
    for level = 1, #frontier do
        local bit = level - 1
        if frontier[level] then
            assert(bit < 64, "frontier leaf count exceeds 64 bits")
            leaf_count = leaf_count | (1 << bit)
        end
    end
    return leaf_count
end

-- The hash of node "index" at one level, given that level's frontier entry (the complete left
-- subtree to the left, or false) and pristine entry (the all-pristine subtree to the right). The
-- three regions read left-to-right as they sit in the tree: the frontier, the active region
-- covering global indices base..base+#active-1, and pristine.
-- docs:begin frontier_node
local function frontier_node(frontier_entry, base, active, pristine_entry, index)
    local lo, hi = base, base + #active - 1
    if index < lo then
        return frontier_entry -- fell left: a complete left subtree from the frontier
    elseif index > hi then
        return pristine_entry -- fell right: an all-pristine subtree
    else
        return active[index - lo + 1] -- inside the active region
    end
end
-- docs:end frontier_node

-- Asserts that every level of the accumulator below level is empty, so the filled leaf
-- count is a multiple of the entry size standing at level.
local function assert_aligned_below(levels, level, message)
    for below = 1, level - 1 do
        assert(not levels[below], message)
    end
end

-- Applies the defaults and validates an inclusive array range. first == last + 1
-- denotes an empty range.
local function normalize_range(values, first, last)
    first, last = first or 1, last or #values
    assert(math.type(first) == "integer" and math.type(last) == "integer", "invalid range")
    assert(first >= 1 and last <= #values and first <= last + 1, "invalid range")
    return first, last
end

-- Whether count entries standing at first_level still fit, by binary carry over the level
-- occupancy, so trees taller than a Lua integer need no materialized leaf count.
local function frontier_padding_fits(frontier, count, first_level)
    if count == 0 then return true end
    if frontier[#frontier] then return false end
    local height = #frontier - first_level
    count = count - 1
    local carry = 0
    for bit = 0, math.max(height, 63) do
        local sum = ((count >> bit) & 1) + carry
        if bit < height and frontier[first_level + bit] then sum = sum + 1 end
        if bit >= height and (sum & 1) ~= 0 then return false end
        carry = sum >> 1
    end
    return carry == 0
end

-- Folds one new entry into the frontier by the binary-carry update: combine with the present
-- low levels up to the first empty one, O(1) amortized. Mutates the frontier in place. The entry
-- is a leaf, or, when height is given, the root of a complete subtree of that height,
-- which requires the levels below it to be empty (the filled leaf count must be a multiple of
-- the entry size). Appending past the tree capacity fails.
-- docs:begin frontier_push_back
local function frontier_push_back(frontier, hash, height)
    local hash_function = assert(frontier.hash_function)
    local level = (height or 0) + 1
    assert_aligned_below(frontier, level, "frontier is not aligned to the subtree size")
    assert(not frontier[#frontier], "too many leaves")
    local right = hash
    while frontier[level] do
        right = hash_function(frontier[level], right)
        frontier[level] = false
        level = level + 1
    end
    frontier[level] = right
end
-- docs:end frontier_push_back

-- Appends hashes[first..last] in order (first defaults to 1, last to #hashes, and
-- first == last + 1 is an empty range). The hashes are consumed as maximal aligned
-- complete subtrees, each the largest that still starts at the filled leaf count and fits
-- the remaining range, hashed pairwise into one root and pushed back as one entry.
-- Appending past the tree capacity fails before anything changes.
-- docs:begin frontier_append
local function frontier_append(frontier, hashes, first, last, height)
    local hash_function = assert(frontier.hash_function)
    first, last = normalize_range(hashes, first, last)
    local first_level = (height or 0) + 1
    assert_aligned_below(frontier, first_level, "frontier is not aligned to the subtree size")
    assert(frontier_padding_fits(frontier, last - first + 1, first_level), "too many leaves")
    while first <= last do
        local added_height = 0
        local subtree_count = 1
        while not frontier[first_level + added_height] and subtree_count <= ((last - first + 1) >> 1) do
            added_height = added_height + 1
            subtree_count = subtree_count << 1
        end
        local nodes = table.move(hashes, first, first + subtree_count - 1, 1, {})
        for _ = 1, added_height do
            local parents = {}
            for j = 1, #nodes, 2 do
                parents[#parents + 1] = hash_function(nodes[j], nodes[j + 1])
            end
            nodes = parents
        end
        frontier_push_back(frontier, nodes[1], first_level + added_height - 1)
        first = first + subtree_count
    end
end
-- docs:end frontier_append

-- Pads the current frontier up to its root, O(log2_max_leaves). Does not mutate the frontier. The
-- empty leaves take pad, or the pristine leaf when pad is omitted. When pad_height is given,
-- pad is instead the root of a complete subtree of that height, repeated over the empty positions,
-- which requires the levels below it to be empty (the filled leaf count must be a multiple of the
-- pad size). An exactly-full tree needs no padding: its root sits in the top entry.
-- docs:begin frontier_get_root_hash
local function frontier_get_root_hash(frontier, pad, pad_height)
    local hash_function = assert(frontier.hash_function)
    local height = #frontier - 1
    if frontier[height + 1] then return frontier[height + 1] end
    pad = pad or pristine_leaf
    local root = pad
    assert_aligned_below(frontier, (pad_height or 0) + 1, "frontier is not aligned to the pad size")
    -- pad doubles into the all-pad subtree of each level, the right sibling of every empty one
    for level = (pad_height or 0) + 1, height do
        if frontier[level] then
            root = hash_function(frontier[level], root)
        else
            root = hash_function(root, pad)
        end
        pad = hash_function(pad, pad)
    end
    return root
end
-- docs:end frontier_get_root_hash

-- Pads the frontier with count copies of an entry (a leaf hash, or, when pad_height is given,
-- the root of a complete subtree of that height, which requires the levels below it to be empty),
-- the same two-phase algorithm as back_merkle_tree::pad_back. First complete the occupied low
-- levels, each time folding one pad subtree into the smallest occupied subtree and carrying
-- upward like push_back. Once no occupied level is small enough to matter, the bits of the
-- remaining count land each pad subtree directly in its own empty level. The level cursor only
-- moves forward across both phases, so each level is hashed at most once: O(log2_max_leaves)
-- hashes. Mutates the frontier in place. Padding to exactly full leaves the root in the top
-- entry.
local function frontier_pad_back(frontier, hash, count, pad_height)
    local hash_function = assert(frontier.hash_function)
    pad_height = pad_height or 0
    local first_level = pad_height + 1
    local top = #frontier
    assert_aligned_below(frontier, first_level, "frontier is not aligned to the pad size")
    assert(frontier_padding_fits(frontier, count, first_level), "too many leaves")
    if count == 0 then return end
    -- pad_hashes[level] is the root of the complete subtree whose 2^(level-first_level) entries
    -- are all hash
    local pad_hashes = { [first_level] = hash }
    for level = first_level + 1, top do
        pad_hashes[level] = hash_function(pad_hashes[level - 1], pad_hashes[level - 1])
    end
    -- Complete the occupied low levels with pad subtrees, carrying upward.
    local level = first_level
    while level <= top do
        if count == 0 then break end
        local size = 1 << (level - first_level)
        if math.ult(count, size) then break end
        if frontier[level] then
            local right = pad_hashes[level]
            while frontier[level] do
                assert(level < top, "too many leaves")
                right = hash_function(frontier[level], right)
                frontier[level] = false
                level = level + 1
            end
            frontier[level] = right
            count = count - size
        else
            level = level + 1
        end
    end
    -- Drop the remaining pad subtrees directly into their own empty levels.
    for pad_level = first_level, top do
        if count == 0 then break end
        local size = 1 << (pad_level - first_level)
        if count & size ~= 0 then
            assert(not frontier[pad_level], "too many leaves")
            frontier[pad_level] = pad_hashes[pad_level]
            count = count - size
        end
    end
    assert(count == 0)
end

-- Given the frontier at the start of an epoch and the ordered keccak256(output) leaves accepted
-- during it, returns one Proof per new output, all against the single final root (the tree of all
-- leaves padded to height log2_max_leaves). proofs[i] belongs to next_output_hashes[i] (no
-- reordering). The proofs are computed in one batch because an early output's low-level siblings
-- depend on later leaves of the same epoch. Does not mutate the frontier.
-- O(next_output_count * log2_max_leaves).
-- docs:begin frontier_next_proofs
local function frontier_next_proofs(frontier, next_output_hashes)
    local hash_function = assert(frontier.hash_function)
    local log2_max_leaves = #frontier - 1
    local next_output_count = #next_output_hashes
    if next_output_count == 0 then return {} end
    local leaf_count = frontier_leaf_count(frontier)
    -- Allocate each proof's sibling array.
    local siblings = {}
    for i = 1, next_output_count do
        siblings[i] = {}
    end
    -- Start with the new leaves at their global indices.
    local active = next_output_hashes
    local base = leaf_count
    -- Track the pristine subtree at the current level.
    local pristine = pristine_leaf
    for level = 1, log2_max_leaves do
        local bit = level - 1
        local frontier_entry = frontier[level]
        -- Add each output's sibling at this level.
        for i = 1, next_output_count do
            local node = (leaf_count + i - 1) >> bit
            siblings[i][level] = frontier_node(frontier_entry, base, active, pristine, node ~ 1)
        end
        -- Hash the active nodes into their parents.
        local parents = {}
        local parents_base = base >> 1
        for p = parents_base, (base + #active - 1) >> 1 do
            local left = frontier_node(frontier_entry, base, active, pristine, 2 * p)
            local right = frontier_node(frontier_entry, base, active, pristine, 2 * p + 1)
            parents[p - parents_base + 1] = hash_function(left, right)
        end
        active, base = parents, parents_base
        pristine = hash_function(pristine, pristine)
    end
    -- The final active node is the root.
    local root_hash = active[1]
    local proofs = {}
    for i = 1, next_output_count do
        proofs[i] = {
            target_address = leaf_count + i - 1,
            log2_target_size = 0,
            log2_root_size = log2_max_leaves,
            target_hash = next_output_hashes[i],
            root_hash = root_hash,
            sibling_hashes = siblings[i],
        }
    end
    return proofs
end
-- docs:end frontier_next_proofs

-- An empty frontier of the given height: all log2_max_leaves + 1 levels unfilled (false).
local function frontier_genesis(log2_max_leaves, hash_type)
    local f = { hash_function = assert(cartesi[hash_type], "unsupported hash function") }
    for level = 1, log2_max_leaves + 1 do
        f[level] = false
    end
    return f
end

-- A shallow copy of a frontier, so the original keeps its leaves while the copy advances independently.
local function frontier_copy(frontier)
    local copy = { table.unpack(frontier) }
    copy.hash_function = frontier.hash_function
    return copy
end

-- Whether a frontier constructor argument is a last-output proof rather than a tree height.
local function is_proof(log2_max_leaves_or_last_proof) return type(log2_max_leaves_or_last_proof) == "table" end

-- The single frontier constructor resolves the required hash_type once and stores the function
-- in the frontier. A number is the tree height log2_max_leaves and yields an empty frontier (leaf
-- count 0) used for genesis. Otherwise the argument is the previous epoch's
-- last-output Proof, and the result is the left frontier for the start of the next epoch, rebuilt
-- from that proof (its height taken from log2_root_size). The last leaf has index target_address,
-- so the leaf count is target_address + 1. The lowest complete level is the level whose complete
-- left subtree ends exactly at the leaf count.
-- docs:begin frontier
local function frontier(log2_max_leaves_or_last_proof, hash_type)
    assert(hash_type ~= nil, "hash type is required")
    if is_proof(log2_max_leaves_or_last_proof) then
        local proof = log2_max_leaves_or_last_proof
        local log2_max_leaves = proof.log2_root_size
        local f = frontier_genesis(log2_max_leaves, hash_type)
        local hash_function = f.hash_function
        local leaf_count = proof.target_address + 1
        local lowest_complete_level = 1
        while (leaf_count & (1 << (lowest_complete_level - 1))) == 0 do
            lowest_complete_level = lowest_complete_level + 1
        end
        -- Above the lowest complete level, where the leaf count's bit at that level is set, the last leaf
        -- is a right child, so its proof sibling there is exactly the complete left subtree we need.
        for level = lowest_complete_level + 1, log2_max_leaves do
            local bit = level - 1
            if (leaf_count & (1 << bit)) ~= 0 then f[level] = proof.sibling_hashes[level] end
        end
        -- At the lowest complete level, the last leaf is a right child at every lower level, so rolling it
        -- up through the siblings below rebuilds that level's complete left subtree, which ends at the leaf
        -- count.
        local hash = proof.target_hash
        for level = 1, lowest_complete_level - 1 do
            hash = hash_function(proof.sibling_hashes[level], hash)
        end
        f[lowest_complete_level] = hash
        return f
    end
    return frontier_genesis(log2_max_leaves_or_last_proof, hash_type)
end
-- docs:end frontier

-- A forest is an appendable frontier that retains complete trees instead of only their hashes.
-- A tree is a complete subtree retained by a forest and is either dense or mixed.
-- A dense tree stores values as leaves and raw hashes at its inner levels up to the root.
-- At every level, its last stored entry implicitly repeats until the level is complete.
-- A mixed tree joins two equal-height trees without changing their internal representations.
-- A value is a raw hash or a tree.

local function is_forest(value) return type(value) == "table" and value.kind == "forest" end
local function is_tree(value) return type(value) == "table" and (value.kind == "dense" or value.kind == "mixed") end

-- Dense-tree levels contain raw hashes or complete trees at their base and raw hashes
-- above it.
local function get_value_hash(root) return type(root) == "string" and root or root.hash end

-- Returns the value at a 0-based logical index, repeating the last stored value beyond
-- the explicit prefix.
local function get_or_last(values, index) return values[math.min(index + 1, #values)] end

local function append_if(into, value)
    if into then into[#into + 1] = value end
end

-- A dense tree covers 2^log2_count base values at base_height, starting at values[first].
-- The range is limited to the available values, with at least one value stored. The last
-- stored value fills every omitted position. Each level up to the root stores the distinct
-- parents plus the first repeated one, and indexing past a level's end reads its last entry,
-- so a repeated suffix of any length costs one hash per level.
local function new_dense_tree(hash_function, base_height, log2_count, values, first)
    first = math.min(first, #values)
    local tree = { table.move(values, first, math.min(first + (1 << log2_count) - 1, #values), 1, {}) }
    for relative_height = 1, log2_count do
        local children = tree[relative_height]
        local parents = {}
        for i = 1, math.min((#children >> 1) + 1, 1 << (log2_count - relative_height)) do
            local left = get_or_last(children, 2 * i - 2)
            local right = get_or_last(children, 2 * i - 1)
            parents[i] = hash_function(get_value_hash(left), get_value_hash(right))
        end
        tree[relative_height + 1] = parents
    end
    tree.kind = "dense"
    tree.height = base_height + log2_count
    tree.base_height = base_height
    tree.hash = get_value_hash(tree[#tree][1])
    return tree
end

-- A mixed tree joins two equal-height trees produced by different regions or by a carry.
local function new_mixed_tree(hash_function, left, right)
    assert(left.height == right.height, "mixed children have different heights")
    return {
        kind = "mixed",
        height = left.height + 1,
        left = left,
        right = right,
        hash = hash_function(left.hash, right.hash),
    }
end

-- Descends along leaf_index until bit reaches stop_bit. When siblings is given, appends
-- the path siblings from the root downward. A raw base hash is opaque below its height,
-- so a query below one fails.
local function descend_tree(tree, leaf_index, bit, stop_bit, siblings)
    if bit == stop_bit then return tree.hash end
    if tree.kind == "mixed" then
        bit = bit >> 1
        local child, sibling
        if (leaf_index & bit) == 0 then
            child, sibling = tree.left, tree.right
        else
            child, sibling = tree.right, tree.left
        end
        append_if(siblings, sibling.hash)
        return descend_tree(child, leaf_index, bit, stop_bit, siblings)
    end

    local level_index = 0
    for relative_height = #tree - 2, 0, -1 do
        bit = bit >> 1
        level_index = 2 * level_index
        if (leaf_index & bit) ~= 0 then level_index = level_index + 1 end
        local values = tree[relative_height + 1]
        append_if(siblings, get_value_hash(get_or_last(values, level_index ~ 1)))
        if bit == stop_bit then return get_value_hash(get_or_last(values, level_index)) end
    end

    local value = get_or_last(tree[1], level_index)
    assert(is_tree(value), "the node is below an opaque hash")
    return descend_tree(value, leaf_index, bit, stop_bit, siblings)
end

-- An empty frontier forest of the given height, ready to append 2^log2_max_leaves leaves.
-- The level array is that of a frontier. Values first accumulate in a pending partial array
-- whose last value implicitly fills the positions padded after it, and materialize into
-- complete trees when the accumulated region ends, so the leaf count is tracked explicitly.
-- Heights stay below 63 so counts and indices remain positive Lua integers. A taller tree
-- splits into bundle forests under an outer forest.
local function frontier_forest(log2_max_leaves, hash_type)
    assert(hash_type ~= nil, "hash type is required")
    assert(
        math.type(log2_max_leaves) == "integer" and log2_max_leaves >= 0 and log2_max_leaves < 63,
        "unsupported forest height"
    )
    local forest = {
        kind = "forest",
        hash_function = assert(cartesi[hash_type], "unsupported hash function"),
        height = log2_max_leaves,
        leaf_count = 0,
        pending = { values = {}, pad_count = 0 },
    }
    for level = 1, log2_max_leaves + 1 do
        forest[level] = false
    end
    return forest
end

-- Validates a declared raw-hash height and applies its leaf default.
local function normalize_hash_height(hash_height)
    assert(hash_height == nil or (math.type(hash_height) == "integer" and hash_height >= 0), "invalid value height")
    return hash_height or 0
end

-- Returns one raw hash or a completed forest's root tree after validating it against
-- the destination forest. Forests therefore never occur inside dense or mixed trees.
local function normalize_forest_value(forest, value, value_height)
    local declared_height = normalize_hash_height(value_height)
    if type(value) == "string" then
        assert(#value == cartesi.HASH_SIZE, "invalid hash size")
        return value, declared_height
    end
    assert(is_forest(value), "a value is not a hash or a forest")
    assert(value.hash_function == forest.hash_function, "value hash function mismatch")
    local root = assert(value[value.height + 1], "a forest value is not full")
    assert(value_height == nil or value_height == value.height, "value height mismatch")
    return root, value.height
end

-- Normalizes an inclusive array range and validates its raw hashes.
local function normalize_hash_range(values, first, last)
    first, last = normalize_range(values, first, last)
    for i = first, last do
        local value = values[i]
        assert(type(value) == "string", "a value is not a hash")
        assert(#value == cartesi.HASH_SIZE, "invalid hash size")
    end
    return first, last
end

-- Materializes the pending values as maximal aligned complete subtrees, each the largest
-- that still starts at the leaf count and fits the remaining values. Each becomes a
-- dense tree, except that a single tree value is already the required tree. Each subtree
-- is folded into the levels by the binary-carry update, joining carries into mixed trees.
-- The cleared accumulator starts at next_height, or remains inactive when it is omitted.
local function forest_flush(forest, next_height)
    local pending = forest.pending
    local height = pending.height
    local values = pending.values
    local pad_count = pending.pad_count
    pending.height = next_height
    pending.values = {}
    pending.pad_count = 0
    if not height then return end
    local first_level = height + 1
    local offset = 0
    local count = #values + pad_count
    while count > 0 do
        local added_height = 0
        local subtree_count = 1
        while not forest[first_level + added_height] and subtree_count <= (count >> 1) do
            added_height = added_height + 1
            subtree_count = subtree_count << 1
        end
        local subtree = get_or_last(values, offset)
        if added_height > 0 or not is_tree(subtree) then
            subtree = new_dense_tree(forest.hash_function, height, added_height, values, offset + 1)
        end
        local level = first_level + added_height
        while forest[level] do
            assert(level < #forest, "too many leaves")
            subtree = new_mixed_tree(forest.hash_function, forest[level], subtree)
            forest[level] = false
            level = level + 1
        end
        forest[level] = subtree
        offset = offset + subtree_count
        count = count - subtree_count
    end
end

local function assert_forest_can_append(forest, height, count)
    assert(height <= forest.height, "value height exceeds forest height")
    assert((forest.leaf_count & ((1 << height) - 1)) == 0, "the forest is not aligned to the given height")
    assert(count <= ((1 << forest.height) - forest.leaf_count) >> height, "too many leaves")
end

local function should_flush_pending_hashes(pending, hash_height)
    return not pending.height or pending.height ~= hash_height or pending.pad_count > 0
end

local function should_flush_pending_value(pending, value, value_height)
    return not pending.height
        or pending.height ~= value_height
        or (pending.pad_count > 0 and pending.values[#pending.values] ~= value)
end

-- Appends raw hashes[first..last] to the pending partial array. Hashing happens when the
-- accumulated region is flushed. The complete operation is validated before mutation.
local function frontier_forest_append(forest, hashes, first, last, hash_height)
    first, last = normalize_hash_range(hashes, first, last)
    local count = last - first + 1
    if count == 0 then return end
    hash_height = normalize_hash_height(hash_height)
    assert_forest_can_append(forest, hash_height, count)
    if should_flush_pending_hashes(forest.pending, hash_height) then forest_flush(forest, hash_height) end
    table.move(hashes, first, last, #forest.pending.values + 1, forest.pending.values)
    forest.leaf_count = forest.leaf_count + (count << hash_height)
    if forest.leaf_count == (1 << forest.height) then forest_flush(forest) end
end

-- Appends one raw hash or completed forest.
local function frontier_forest_push_back(forest, value, value_height)
    value, value_height = normalize_forest_value(forest, value, value_height)
    assert_forest_can_append(forest, value_height, 1)
    if should_flush_pending_value(forest.pending, value, value_height) then forest_flush(forest, value_height) end
    if forest.pending.pad_count > 0 then
        forest.pending.pad_count = forest.pending.pad_count + 1
    else
        forest.pending.values[#forest.pending.values + 1] = value
    end
    forest.leaf_count = forest.leaf_count + (1 << value_height)
    if forest.leaf_count == (1 << forest.height) then forest_flush(forest) end
end

-- Appends count copies of one raw hash or completed forest. Mutates the forest in place. Only
-- validates, appends the base to the pending partial array when its last value is not
-- already that base, and records the additional implicit copies in pad_count. The
-- last-entry rule of dense trees represents the repetitions. The whole range is validated
-- and reserved here, not when it is flushed. A raw hash and a tree never merge, even with
-- equal roots, since that would discard the tree's descendants.
local function frontier_forest_pad_back(forest, value, count, value_height)
    assert(math.type(count) == "integer" and count >= 0, "invalid pad count")
    if count == 0 then return end
    value, value_height = normalize_forest_value(forest, value, value_height)
    assert_forest_can_append(forest, value_height, count)
    if should_flush_pending_value(forest.pending, value, value_height) then forest_flush(forest, value_height) end
    if forest.pending.pad_count > 0 then
        forest.pending.pad_count = forest.pending.pad_count + count
    elseif count == 1 then
        forest.pending.values[#forest.pending.values + 1] = value
    elseif forest.pending.values[#forest.pending.values] == value then
        forest.pending.pad_count = count
    else
        forest.pending.values[#forest.pending.values + 1] = value
        forest.pending.pad_count = count - 1
    end
    forest.leaf_count = forest.leaf_count + (count << value_height)
    if forest.leaf_count == (1 << forest.height) then forest_flush(forest) end
end

-- The root hash of a full forest, O(1), because completion has already flushed all pending
-- work. Does not mutate the forest.
local function frontier_forest_get_root_hash(forest)
    return assert(forest[forest.height + 1], "the forest is not full").hash
end

local function assert_valid_forest_node(forest, position, height)
    assert(math.type(height) == "integer" and height >= 0 and height <= forest.height, "invalid node height")
    assert(
        math.type(position) == "integer" and position >= 0 and position < (1 << forest.height),
        "invalid node position"
    )
    assert((position & ((1 << height) - 1)) == 0, "node position is not aligned to its height")
end

-- The node hash at height whose first covered leaf is position, following the machine API's
-- position-first argument order. Requires the forest to be full and position to be aligned
-- to the node size. Does not mutate the forest. O(log2_max_leaves).
local function frontier_forest_get_node(forest, position, height)
    local top = assert(forest[forest.height + 1], "the forest is not full")
    assert_valid_forest_node(forest, position, height)
    local current_bit = 1 << top.height
    local stop_bit = 1 << height
    return descend_tree(top, position, current_bit, stop_bit)
end

-- Appends the proof siblings of the node at position and height, from that node upward,
-- into the given array (a new one when omitted) and returns it, in a single descent,
-- O(log2_max_leaves). Requires the forest to be full and position to be aligned to the
-- node size. Does not mutate the forest. A caller proves across two stacked forests by
-- appending the inner forest's siblings and then the outer forest's.
local function frontier_forest_get_siblings(forest, position, height, into)
    local top = assert(forest[forest.height + 1], "the forest is not full")
    assert_valid_forest_node(forest, position, height)
    local current_bit = 1 << top.height
    local stop_bit = 1 << height
    local siblings = {}
    descend_tree(top, position, current_bit, stop_bit, siblings)
    into = into or {}
    for i = #siblings, 1, -1 do
        into[#into + 1] = siblings[i]
    end
    return into
end

return {
    roll_hash_up_tree = roll_hash_up_tree,
    verify_slice = verify_slice,
    verify_splice = verify_splice,
    get_data_root_hash = get_data_root_hash,
    frontier = frontier,
    frontier_copy = frontier_copy,
    frontier_push_back = frontier_push_back,
    frontier_append = frontier_append,
    frontier_pad_back = frontier_pad_back,
    frontier_get_root_hash = frontier_get_root_hash,
    frontier_next_proofs = frontier_next_proofs,
    frontier_forest = frontier_forest,
    frontier_forest_push_back = frontier_forest_push_back,
    frontier_forest_append = frontier_forest_append,
    frontier_forest_pad_back = frontier_forest_pad_back,
    frontier_forest_get_root_hash = frontier_forest_get_root_hash,
    frontier_forest_get_node = frontier_forest_get_node,
    frontier_forest_get_siblings = frontier_forest_get_siblings,
}
