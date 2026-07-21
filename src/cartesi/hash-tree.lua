local cartesi = require("cartesi")

-- Tree leaves are words, the smallest proof target.
local WORD_LOG2_SIZE = cartesi.HASH_TREE_LOG2_WORD_SIZE
local WORD_LENGTH = 1 << WORD_LOG2_SIZE

-- docs:begin roll_hash_up_tree
local function roll_hash_up_tree(proof, target_hash)
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
        hash = cartesi.keccak256(first, second)
    end
    return hash
end
-- docs:end roll_hash_up_tree

-- docs:begin verify_slice
local function verify_slice(proof)
    assert(roll_hash_up_tree(proof, proof.target_hash) == proof.root_hash, "target node not in tree")
end
-- docs:end verify_slice

-- docs:begin verify_splice
local function verify_splice(proof, new_target_hash, new_root_hash)
    verify_slice(proof)
    assert(roll_hash_up_tree(proof, new_target_hash) == new_root_hash, "target node not in tree")
end
-- docs:end verify_splice

-- Computes the Merkle tree root of a byte string laid at the base of a tree covering
-- 2^log2_root_size bytes. The data need not fill the tree or be a power of two long. Leaves
-- are word-size keccak256 hashes, a trailing partial word zero-padded, and inner nodes hash
-- their two children. Every node the data does not reach takes its level's pristine hash, the
-- root of an all-zero subtree, which doubles each level climbed. Overflow is rejected.
-- docs:begin get_root_hash
local function get_root_hash(data, log2_root_size)
    assert(#data <= (1 << log2_root_size), "data does not fit in the tree")
    -- Level zero is one hash per word, a trailing partial word zero-padded after the loop.
    local level = {}
    local full = #data - #data % WORD_LENGTH
    for i = 1, full, WORD_LENGTH do
        level[#level + 1] = cartesi.keccak256(data:sub(i, i + WORD_LENGTH - 1))
    end
    if full < #data then
        local word = data:sub(full + 1)
        level[#level + 1] = cartesi.keccak256(word .. string.rep("\0", WORD_LENGTH - #word))
    end
    -- Pair upward to the root, the pristine hash standing in for every node the data misses.
    local pristine = cartesi.keccak256(string.rep("\0", WORD_LENGTH))
    for _ = WORD_LOG2_SIZE, log2_root_size - 1 do
        local parents = {}
        for i = 1, #level, 2 do
            parents[#parents + 1] = cartesi.keccak256(level[i], level[i + 1] or pristine)
        end
        level, pristine = parents, cartesi.keccak256(pristine, pristine)
    end
    return level[1]
end
-- docs:end get_root_hash

-- The functions below are a generic incremental keccak Merkle accumulator (a "back merkle
-- tree") for the CMIO outputs Merkle tree: a fixed-height tree whose leaves are keccak256(output),
-- accumulating from genesis and padded on the right with pristine subtrees. Unlike the
-- word-leaf memory tree above, its pristine leaf is literally HASH_SIZE zero bytes (not a
-- hash of them), matching libcmt's cmt_merkle_t and tests/lua/cmio-test.lua. Nothing here is
-- output-specific; the caller feeds keccak256(output) leaves.
--
-- A frontier captures the complete left subtrees standing over the leaves seen so far. It is a
-- length-(log2_max_leaves + 1) array indexed by a 1-based level, where level 1 corresponds to bit
-- 0 (the 0-based leaves). Entry level holds that level's complete left subtree when the matching
-- bit of the leaf count is set, else false (false, not nil, so the array stays dense and
-- round-trips as JSON). The present subtrees' sizes sum to the leaf count, so the count is
-- recovered from the array rather than stored. The top entry holds the root when the tree is
-- exactly full, matching back_merkle_tree's context.

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

-- Folds one new entry into the frontier by the binary-carry update: combine with the present
-- low levels up to the first empty one, O(1) amortized. Mutates the frontier in place. The entry
-- is a leaf, or, when log2_hash_size is given, the root of a complete subtree of that height,
-- which requires the levels below it to be empty (the filled leaf count must be a multiple of
-- the entry size).
-- docs:begin frontier_push_back
local function frontier_push_back(frontier, hash, log2_hash_size)
    local level = (log2_hash_size or 0) + 1
    for below = 1, level - 1 do
        assert(not frontier[below], "frontier is not aligned to the hash size")
    end
    local right = hash
    while frontier[level] do
        right = cartesi.keccak256(frontier[level], right)
        frontier[level] = false
        level = level + 1
    end
    frontier[level] = right
end
-- docs:end frontier_push_back

-- Pads the current frontier up to its root, O(log2_max_leaves). Does not mutate the frontier. The
-- empty leaves take pad, or the pristine leaf when pad is omitted. When log2_pad_size is given,
-- pad is instead the root of a complete subtree of that height, repeated over the empty positions,
-- which requires the levels below it to be empty (the filled leaf count must be a multiple of the
-- pad size). An exactly-full tree needs no padding: its root sits in the top entry.
-- docs:begin frontier_get_root_hash
local function frontier_get_root_hash(frontier, pad, log2_pad_size)
    local height = #frontier - 1
    if frontier[height + 1] then return frontier[height + 1] end
    pad = pad or pristine_leaf
    local root = pad
    for level = 1, log2_pad_size or 0 do
        assert(not frontier[level], "frontier is not aligned to the pad size")
    end
    -- pad doubles into the all-pad subtree of each level, the right sibling of every empty one
    for level = (log2_pad_size or 0) + 1, height do
        if frontier[level] then
            root = cartesi.keccak256(frontier[level], root)
        else
            root = cartesi.keccak256(root, pad)
        end
        pad = cartesi.keccak256(pad, pad)
    end
    return root
end
-- docs:end frontier_get_root_hash

-- Pads the frontier with count copies of an entry (a leaf hash, or, when log2_pad_size is given,
-- the root of a complete subtree of that height, which requires the levels below it to be empty),
-- the same two-phase algorithm as back_merkle_tree::pad_back. First complete the occupied low
-- levels, each time folding one pad subtree into the smallest occupied subtree and carrying
-- upward like push_back. Once no occupied level is small enough to matter, the bits of the
-- remaining count land each pad subtree directly in its own empty level. The level cursor only
-- moves forward across both phases, so each level is hashed at most once: O(log2_max_leaves)
-- hashes. Mutates the frontier in place. Padding to exactly full leaves the root in the top
-- entry.
local function frontier_padding_fits(frontier, count, first_level)
    if count == 0 then return true end
    if frontier[#frontier] then return false end
    local height = #frontier - first_level
    count = count - 1
    local carry = 0
    for bit = 0, math.max(height, 63) do
        local sum = ((count >> bit) & 1) + carry
        if bit < height and frontier[first_level + bit] then sum = sum + 1 end
        if bit >= height and sum & 1 ~= 0 then return false end
        carry = sum >> 1
    end
    return carry == 0
end

local function frontier_pad_back(frontier, hash, count, log2_pad_size)
    log2_pad_size = log2_pad_size or 0
    local first_level = log2_pad_size + 1
    local top = #frontier
    for level = 1, log2_pad_size do
        assert(not frontier[level], "frontier is not aligned to the pad size")
    end
    assert(frontier_padding_fits(frontier, count, first_level), "too many leaves")
    if count == 0 then return end
    -- pad_hashes[level] is the root of the complete subtree whose 2^(level-first_level) entries
    -- are all hash
    local pad_hashes = { [first_level] = hash }
    for level = first_level + 1, top do
        pad_hashes[level] = cartesi.keccak256(pad_hashes[level - 1], pad_hashes[level - 1])
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
                right = cartesi.keccak256(frontier[level], right)
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
    local log2_max_leaves = #frontier - 1
    local next_output_count = #next_output_hashes
    if next_output_count == 0 then return {} end
    local leaf_count = frontier_leaf_count(frontier)
    -- siblings[i] is the i-th new output's sibling array.
    local siblings = {}
    for i = 1, next_output_count do
        siblings[i] = {}
    end
    -- active holds the node hashes covering global indices [base, base + #active - 1] at the
    -- current level; start at the leaves over [leaf_count, leaf_count + next_output_count).
    local active = next_output_hashes
    local base = leaf_count
    local pristine = pristine_leaf -- the all-pristine subtree at the current level
    for level = 1, log2_max_leaves do
        local bit = level - 1
        local frontier_entry = frontier[level]
        -- Each output's proof sibling at this level is its node's neighbour (toggle the low bit).
        for i = 1, next_output_count do
            local node = (leaf_count + i - 1) >> bit
            siblings[i][level] = frontier_node(frontier_entry, base, active, pristine, node ~ 1)
        end
        -- Climb one level: parent p has children 2p and 2p+1; the leftmost index halves.
        local parents = {}
        local parents_base = base >> 1
        for p = parents_base, (base + #active - 1) >> 1 do
            local left = frontier_node(frontier_entry, base, active, pristine, 2 * p)
            local right = frontier_node(frontier_entry, base, active, pristine, 2 * p + 1)
            parents[p - parents_base + 1] = cartesi.keccak256(left, right)
        end
        active, base = parents, parents_base
        pristine = cartesi.keccak256(pristine, pristine)
    end
    local root_hash = active[1] -- after the last level the single active node is the root
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
local function frontier_genesis(log2_max_leaves)
    local f = {}
    for level = 1, log2_max_leaves + 1 do
        f[level] = false
    end
    return f
end

-- A shallow copy of a frontier, so the original keeps its leaves while the copy advances independently.
local function frontier_copy(frontier) return { table.unpack(frontier, 1, #frontier) } end

-- Whether a frontier constructor argument is a last-output proof rather than a tree height.
local function is_proof(log2_max_leaves_or_last_proof) return type(log2_max_leaves_or_last_proof) == "table" end

-- The single frontier constructor. A number is the tree height log2_max_leaves and yields an empty
-- frontier (leaf count 0) used for genesis. Otherwise the argument is the previous epoch's
-- last-output Proof, and the result is the left frontier for the start of the next epoch, rebuilt
-- from that proof (its height taken from log2_root_size). The last leaf has index target_address,
-- so the leaf count is target_address + 1. The lowest complete level is the level whose complete
-- left subtree ends exactly at the leaf count.
-- docs:begin frontier
local function frontier(log2_max_leaves_or_last_proof)
    if is_proof(log2_max_leaves_or_last_proof) then
        local proof = log2_max_leaves_or_last_proof
        local log2_max_leaves = proof.log2_root_size
        local f = frontier_genesis(log2_max_leaves)
        local leaf_count = proof.target_address + 1
        local lowest_complete_level = 1
        while leaf_count & (1 << (lowest_complete_level - 1)) == 0 do
            lowest_complete_level = lowest_complete_level + 1
        end
        -- Above the lowest complete level, where the leaf count's bit at that level is set, the last leaf
        -- is a right child, so its proof sibling there is exactly the complete left subtree we need.
        for level = lowest_complete_level + 1, log2_max_leaves do
            local bit = level - 1
            if leaf_count & (1 << bit) ~= 0 then f[level] = proof.sibling_hashes[level] end
        end
        -- At the lowest complete level, the last leaf is a right child at every lower level, so rolling it
        -- up through the siblings below rebuilds that level's complete left subtree, which ends at the leaf
        -- count.
        local hash = proof.target_hash
        for level = 1, lowest_complete_level - 1 do
            hash = cartesi.keccak256(proof.sibling_hashes[level], hash)
        end
        f[lowest_complete_level] = hash
        return f
    end
    return frontier_genesis(log2_max_leaves_or_last_proof)
end
-- docs:end frontier

return {
    roll_hash_up_tree = roll_hash_up_tree,
    verify_slice = verify_slice,
    verify_splice = verify_splice,
    get_root_hash = get_root_hash,
    frontier = frontier,
    frontier_copy = frontier_copy,
    frontier_push_back = frontier_push_back,
    frontier_pad_back = frontier_pad_back,
    frontier_get_root_hash = frontier_get_root_hash,
    frontier_next_proofs = frontier_next_proofs,
}
