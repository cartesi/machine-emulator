--[[
Test suite for the Lua hash-tree module.
Specifically, it provides test coverage for:
    src/cartesi/hash-tree.lua
It covers the outputs Merkle tree frontier accumulator and the proof verifier at the outputs Merkle tree depth.
Can be run independently during development of the mentioned file.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local H = cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT

-- Independent reference for the height-H pristine-padded keccak outputs Merkle root, mirroring
-- check_outputs_merkle_root in tests/lua/cmio-test.lua. The leaves are already keccak256(output).
local function reference_root(leaves)
    local z = string.rep("\0", cartesi.HASH_SIZE)
    local level = #leaves == 0 and { z } or leaves
    for _ = 1, H do
        local parents = {}
        local child = 1
        while level[child] do
            parents[#parents + 1] = cartesi.keccak256(level[child], level[child + 1] or z)
            child = child + 2
        end
        z = cartesi.keccak256(z, z)
        level = parents
    end
    return level[1]
end

local function leaf(k)
    return cartesi.keccak256("output-" .. k)
end

local function make_leaves(n)
    local leaves = {}
    for k = 1, n do
        leaves[k] = leaf(k)
    end
    return leaves
end

-- Two proofs of the same output, computed independently, must agree on every field.
local function expect_same_proof(a, b)
    expect.equal(a.target_address, b.target_address)
    expect.equal(a.log2_target_size, b.log2_target_size)
    expect.equal(a.log2_root_size, b.log2_root_size)
    expect.equal(a.target_hash, b.target_hash)
    expect.equal(a.root_hash, b.root_hash)
    expect.equal(#a.sibling_hashes, #b.sibling_hashes)
    for i = 1, #a.sibling_hashes do
        expect.equal(a.sibling_hashes[i], b.sibling_hashes[i])
    end
end

describe("hash-tree.lua", function()
    local counts = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 64, 100 }

    describe("frontier", function()
        it("requires the hash type", function()
            expect.fail(function()
                hash_tree.frontier(H)
            end, "hash type is required")
        end)

        it("produces proofs that verify and share the reference root", function()
            for _, n in ipairs(counts) do
                local leaves = make_leaves(n)
                local proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), leaves)
                expect.equal(#proofs, n)
                local root = reference_root(leaves)
                for i = 1, n do
                    expect.equal(proofs[i].target_address, i - 1)
                    expect.equal(proofs[i].log2_target_size, 0)
                    expect.equal(proofs[i].log2_root_size, H)
                    expect.equal(proofs[i].target_hash, leaves[i])
                    expect.equal(proofs[i].root_hash, root)
                    hash_tree.verify_slice(proofs[i]) -- errors unless the proof rolls up to root
                end
            end
        end)

        it("matches the reference root as leaves are pushed back", function()
            local frontier = hash_tree.frontier(H, "keccak256")
            local leaves = {}
            expect.equal(hash_tree.frontier_get_root_hash(frontier), reference_root(leaves))
            for k = 1, 100 do
                leaves[k] = leaf(k)
                hash_tree.frontier_push_back(frontier, leaves[k])
                expect.equal(hash_tree.frontier_get_root_hash(frontier), reference_root(leaves))
            end
        end)

        it("uses the hash function selected by the constructor", function()
            local z = string.rep("\0", cartesi.HASH_SIZE)
            local leaves = { cartesi.sha256("left"), cartesi.sha256("right") }
            local frontier = hash_tree.frontier(2, "sha256")
            expect.equal(frontier.hash_function, cartesi.sha256)
            hash_tree.frontier_push_back(frontier, leaves[1])
            hash_tree.frontier_push_back(frontier, leaves[2])
            expect.equal(
                hash_tree.frontier_get_root_hash(frontier),
                cartesi.sha256(cartesi.sha256(leaves[1], leaves[2]), cartesi.sha256(z, z))
            )
            expect.equal(hash_tree.frontier_copy(frontier).hash_function, cartesi.sha256)
        end)

        it("resumes from the previous epoch's last proof (epoch-split equivalence)", function()
            for _, n in ipairs({ 5, 8, 16, 33, 100 }) do
                local leaves = make_leaves(n)
                local single = hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), leaves)
                for split = 1, n - 1 do
                    local first, second = {}, {}
                    for k = 1, split do
                        first[k] = leaves[k]
                    end
                    for k = split + 1, n do
                        second[#second + 1] = leaves[k]
                    end
                    local first_proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), first)
                    -- the previous epoch's last proof seeds the next epoch
                    local seed = hash_tree.frontier(first_proofs[#first_proofs], "keccak256")
                    local second_proofs = hash_tree.frontier_next_proofs(seed, second)
                    for j = 1, #second do
                        expect_same_proof(second_proofs[j], single[split + j])
                    end
                end
            end
        end)

        it("has nothing to prove for an empty epoch", function()
            expect.equal(#hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), {}), 0)
        end)

        it("rejects a frontier leaf count that exceeds 64 bits", function()
            local frontier = hash_tree.frontier(64, "keccak256")
            frontier[65] = leaf(1)
            expect.fail(function()
                hash_tree.frontier_next_proofs(frontier, { leaf(2) })
            end, "frontier leaf count exceeds 64 bits")
        end)
    end)

    describe("frontier_pad_back", function()
        -- Small-height reference: the root of the tree whose leaf list is the pushed leaves,
        -- then `count` copies of `pad`, then pristine leaves to the end.
        local SMALL_H = 4
        local SMALL_MAX = 1 << SMALL_H
        local function reference_padded_root(leaves, pad, count)
            local level = {}
            for k = 1, SMALL_MAX do
                if k <= #leaves then
                    level[k] = leaves[k]
                elseif k <= #leaves + count then
                    level[k] = pad
                else
                    level[k] = string.rep("\0", cartesi.HASH_SIZE)
                end
            end
            while #level > 1 do
                local parents = {}
                for k = 1, #level, 2 do
                    parents[#parents + 1] = cartesi.keccak256(level[k], level[k + 1])
                end
                level = parents
            end
            return level[1]
        end

        local pad = cartesi.keccak256("pad")

        it("matches the reference root for every leaf and pad count", function()
            for n = 0, SMALL_MAX do
                for k = 0, SMALL_MAX - n do
                    local frontier = hash_tree.frontier(SMALL_H, "keccak256")
                    local leaves = make_leaves(n)
                    for _, l in ipairs(leaves) do
                        hash_tree.frontier_push_back(frontier, l)
                    end
                    hash_tree.frontier_pad_back(frontier, pad, k)
                    expect.equal(hash_tree.frontier_get_root_hash(frontier), reference_padded_root(leaves, pad, k))
                end
            end
        end)

        it("keeps accepting leaves after a partial pad", function()
            local frontier = hash_tree.frontier(SMALL_H, "keccak256")
            local leaves = make_leaves(3)
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(frontier, l)
            end
            hash_tree.frontier_pad_back(frontier, pad, 4)
            local expected = { leaves[1], leaves[2], leaves[3], pad, pad, pad, pad }
            for k = 8, 10 do
                expected[k] = leaf(k)
                hash_tree.frontier_push_back(frontier, expected[k])
            end
            expect.equal(hash_tree.frontier_get_root_hash(frontier), reference_padded_root(expected, pad, 0))
        end)

        it("keeps the root of an exactly-full tree in the top entry", function()
            -- filled by padding
            local padded = hash_tree.frontier(SMALL_H, "keccak256")
            hash_tree.frontier_pad_back(padded, pad, SMALL_MAX)
            expect.equal(padded[SMALL_H + 1], reference_padded_root({}, pad, SMALL_MAX))
            expect.equal(hash_tree.frontier_get_root_hash(padded), reference_padded_root({}, pad, SMALL_MAX))
            -- filled by pushing
            local pushed = hash_tree.frontier(SMALL_H, "keccak256")
            local leaves = make_leaves(SMALL_MAX)
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(pushed, l)
            end
            expect.equal(hash_tree.frontier_get_root_hash(pushed), reference_padded_root(leaves, pad, 0))
        end)

        it("rejects padding past the end of the tree", function()
            local frontier = hash_tree.frontier(SMALL_H, "keccak256")
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, SMALL_MAX)
            end)
        end)

        it("fills a tree taller than a Lua integer without materializing its capacity", function()
            local height = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
                + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
            local frontier = hash_tree.frontier(height, "keccak256")
            local subtree = pad
            -- These complete left subtrees represent every leaf except the final one.
            for level = 1, height do
                frontier[level] = subtree
                subtree = cartesi.keccak256(subtree, subtree)
            end
            hash_tree.frontier_pad_back(frontier, pad, 1)
            expect.equal(frontier[height + 1], subtree)
            expect.equal(hash_tree.frontier_get_root_hash(frontier), subtree)
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, 1)
            end, "too many leaves")
        end)

        it("pads with subtree roots when log2_pad_size is given", function()
            local log2_pad_size = 2
            local pad_size = 1 << log2_pad_size
            local pad_root = cartesi.keccak256(cartesi.keccak256(pad, pad), cartesi.keccak256(pad, pad))
            -- every aligned fill and every subtree pad count that still fits
            for n = 0, SMALL_MAX // pad_size do
                for k = 0, SMALL_MAX // pad_size - n do
                    local leaves = make_leaves(n * pad_size)
                    local frontier = hash_tree.frontier(SMALL_H, "keccak256")
                    for _, l in ipairs(leaves) do
                        hash_tree.frontier_push_back(frontier, l)
                    end
                    hash_tree.frontier_pad_back(frontier, pad_root, k, log2_pad_size)
                    -- one subtree root pad is pad_size leaf pads
                    expect.equal(
                        hash_tree.frontier_get_root_hash(frontier),
                        reference_padded_root(leaves, pad, k * pad_size)
                    )
                end
            end
        end)

        it("rejects a subtree pad when the frontier is not aligned to it", function()
            local frontier = hash_tree.frontier(SMALL_H, "keccak256")
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, 1, 2)
            end, "frontier is not aligned to the pad size")
        end)

        it("rejects a subtree pad past the end of the tree", function()
            local frontier = hash_tree.frontier(SMALL_H, "keccak256")
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, SMALL_MAX // 4 + 1, 2)
            end, "too many leaves")
        end)
    end)

    describe("frontier_push_back", function()
        local pad = cartesi.keccak256("pad")

        it("pushes a subtree root when log2_hash_size is given", function()
            local SMALL_H = 4
            -- push leaves 1..2 individually, then the subtree of leaves 3..4 as one entry
            local leaves = make_leaves(4)
            local frontier = hash_tree.frontier(SMALL_H, "keccak256")
            hash_tree.frontier_push_back(frontier, leaves[1])
            hash_tree.frontier_push_back(frontier, leaves[2])
            hash_tree.frontier_push_back(frontier, cartesi.keccak256(leaves[3], leaves[4]), 1)
            local reference = hash_tree.frontier(SMALL_H, "keccak256")
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(reference, l)
            end
            expect.equal(
                hash_tree.frontier_get_root_hash(frontier, pad),
                hash_tree.frontier_get_root_hash(reference, pad)
            )
        end)

        it("rejects a subtree push when the frontier is not aligned to it", function()
            local frontier = hash_tree.frontier(4, "keccak256")
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_push_back(frontier, leaf(2), 1)
            end, "frontier is not aligned to the hash size")
        end)

        it("appends an array of hashes like repeated scalar pushes", function()
            for _, n in ipairs({ 0, 1, 2, 3, 5, 8, 11, 16 }) do
                local leaves = make_leaves(n)
                local expected = hash_tree.frontier(4, "keccak256")
                for _, l in ipairs(leaves) do
                    hash_tree.frontier_push_back(expected, l)
                end
                local frontier = hash_tree.frontier(4, "keccak256")
                hash_tree.frontier_append(frontier, leaves)
                expect.equal(
                    hash_tree.frontier_get_root_hash(frontier, pad),
                    hash_tree.frontier_get_root_hash(expected, pad)
                )
            end
        end)

        it("appends a slice bounded by first and last", function()
            local leaves = make_leaves(10)
            local expected = hash_tree.frontier(4, "keccak256")
            for k = 3, 7 do
                hash_tree.frontier_push_back(expected, leaves[k])
            end
            local frontier = hash_tree.frontier(4, "keccak256")
            hash_tree.frontier_append(frontier, leaves, 3, 7)
            hash_tree.frontier_append(frontier, leaves, 8, 7) -- an empty range is a no-op
            expect.equal(
                hash_tree.frontier_get_root_hash(frontier, pad),
                hash_tree.frontier_get_root_hash(expected, pad)
            )
        end)

        it("appends an array of subtree roots at their height", function()
            local roots = {}
            for i = 1, 3 do
                roots[i] = cartesi.keccak256("subtree-" .. i)
            end
            local expected = hash_tree.frontier(4, "keccak256")
            for _, r in ipairs(roots) do
                hash_tree.frontier_push_back(expected, r, 1)
            end
            local frontier = hash_tree.frontier(4, "keccak256")
            hash_tree.frontier_append(frontier, roots, 1, 3, 1)
            expect.equal(
                hash_tree.frontier_get_root_hash(frontier, pad),
                hash_tree.frontier_get_root_hash(expected, pad)
            )
        end)

        it("rejects invalid ranges and overflow", function()
            local leaves = make_leaves(4)
            local frontier = hash_tree.frontier(2, "keccak256")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 0, 2)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 3, 1)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 1, 2.5)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 1, 5)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, make_leaves(5))
            end, "too many leaves")
            hash_tree.frontier_append(frontier, leaves, 1, 4)
            expect.fail(function()
                hash_tree.frontier_push_back(frontier, leaves[1])
            end, "too many leaves")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 1, 1)
            end, "too many leaves")
        end)
    end)

    describe("frontier_get_root_hash", function()
        local H4 = 4
        local MAX4 = 1 << H4
        local pad = cartesi.keccak256("pad")

        -- Root of the tree over the pushed leaves with every empty leaf taking pad_leaf: the same
        -- result as filling the tree with an explicit pad_back and reading it with no pad_leaf.
        local function fill_and_read(leaves)
            local frontier = hash_tree.frontier(H4, "keccak256")
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(frontier, l)
            end
            hash_tree.frontier_pad_back(frontier, pad, MAX4 - #leaves)
            return hash_tree.frontier_get_root_hash(frontier)
        end

        it("pads the empty leaves with pad_leaf", function()
            for n = 0, MAX4 do
                local leaves = make_leaves(n)
                local frontier = hash_tree.frontier(H4, "keccak256")
                for _, l in ipairs(leaves) do
                    hash_tree.frontier_push_back(frontier, l)
                end
                expect.equal(hash_tree.frontier_get_root_hash(frontier, pad), fill_and_read(leaves))
            end
        end)

        it("pads with the pristine leaf when pad_leaf is omitted", function()
            -- default path stays byte-for-byte what it was before pad_leaf existed
            local z = string.rep("\0", cartesi.HASH_SIZE)
            local frontier = hash_tree.frontier(H4, "keccak256")
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.equal(hash_tree.frontier_get_root_hash(frontier), hash_tree.frontier_get_root_hash(frontier, z))
        end)

        it("pads with a subtree root when log2_pad_size is given", function()
            local log2_pad_size = 2
            local pad_size = 1 << log2_pad_size
            for n = 0, MAX4 // pad_size do
                -- fill n complete subtrees of distinct leaves, so levels below log2_pad_size are empty
                local leaves = make_leaves(n * pad_size)
                local frontier = hash_tree.frontier(H4, "keccak256")
                for _, l in ipairs(leaves) do
                    hash_tree.frontier_push_back(frontier, l)
                end
                -- padding with the subtree root is padding with the subtree's own leaves
                local subtree = { leaf(100), leaf(101), leaf(102), leaf(103) }
                local subtree_root = cartesi.keccak256(
                    cartesi.keccak256(subtree[1], subtree[2]),
                    cartesi.keccak256(subtree[3], subtree[4])
                )
                local expected_frontier = hash_tree.frontier(H4, "keccak256")
                for _, l in ipairs(leaves) do
                    hash_tree.frontier_push_back(expected_frontier, l)
                end
                for _ = n + 1, MAX4 // pad_size do
                    for _, l in ipairs(subtree) do
                        hash_tree.frontier_push_back(expected_frontier, l)
                    end
                end
                expect.equal(
                    hash_tree.frontier_get_root_hash(frontier, subtree_root, log2_pad_size),
                    hash_tree.frontier_get_root_hash(expected_frontier)
                )
            end
        end)

        it("rejects a subtree pad when the frontier is not aligned to it", function()
            local frontier = hash_tree.frontier(H4, "keccak256")
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_get_root_hash(frontier, pad, 2)
            end, "frontier is not aligned to the pad size")
        end)
    end)

    describe("frontier_forest", function()
        local H4 = 4
        local MAX4 = 1 << H4
        local keccak = cartesi.keccak256

        -- Every node of the fully materialized reference tree over exactly 2^H4 leaves.
        local function reference_levels(leaves)
            assert(#leaves == MAX4)
            local levels = { [0] = leaves }
            for log2_size = 1, H4 do
                local parents = {}
                local children = levels[log2_size - 1]
                for i = 1, #children, 2 do
                    parents[#parents + 1] = keccak(children[i], children[i + 1])
                end
                levels[log2_size] = parents
            end
            return levels
        end

        -- Checks a full forest against the reference: every node at every height and its
        -- siblings, assembled into a proof that verifies.
        local function expect_matches_reference(forest, leaves)
            local levels = reference_levels(leaves)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), levels[H4][1])
            for log2_size = 0, H4 do
                for index = 0, (MAX4 >> log2_size) - 1 do
                    local position = index << log2_size
                    local target_hash = levels[log2_size][index + 1]
                    expect.equal(hash_tree.frontier_forest_get_node(forest, position, log2_size), target_hash)
                    local siblings = hash_tree.frontier_forest_get_siblings(forest, position, log2_size)
                    expect.equal(#siblings, H4 - log2_size)
                    for sibling_height = log2_size, H4 - 1 do
                        expect.equal(
                            siblings[sibling_height - log2_size + 1],
                            levels[sibling_height][((position >> sibling_height) ~ 1) + 1]
                        )
                    end
                    hash_tree.verify_slice({
                        target_address = position,
                        log2_target_size = log2_size,
                        target_hash = target_hash,
                        log2_root_size = H4,
                        root_hash = levels[H4][1],
                        sibling_hashes = siblings,
                    })
                end
            end
        end

        it("assembles a dense tree with push_back and append", function()
            local leaves = make_leaves(MAX4)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(forest, leaves[1])
            hash_tree.frontier_forest_append(forest, leaves, 2, 9)
            hash_tree.frontier_forest_append(forest, leaves, 10, 9) -- an empty range is a no-op
            hash_tree.frontier_forest_append(forest, leaves, 10, MAX4)
            expect_matches_reference(forest, leaves)
        end)

        it("pads explicit prefixes with repeated suffixes", function()
            local pad = keccak("pad")
            local prefix = make_leaves(3)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_append(forest, prefix)
            hash_tree.frontier_forest_pad_back(forest, pad, 6)
            hash_tree.frontier_forest_pad_back(forest, pad, 4) -- extends the same repetition
            hash_tree.frontier_forest_push_back(forest, prefix[1]) -- a push after a repetition
            hash_tree.frontier_forest_pad_back(forest, prefix[2], 2) -- an incompatible pad
            local leaves = { prefix[1], prefix[2], prefix[3] }
            for i = 4, 13 do
                leaves[i] = pad
            end
            leaves[14], leaves[15], leaves[16] = prefix[1], prefix[2], prefix[2]
            expect_matches_reference(forest, leaves)
        end)

        it("appends opaque subtrees at their declared height", function()
            local roots = {}
            for i = 1, 4 do
                roots[i] = keccak("subtree-" .. i)
            end
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(forest, roots[1], 2)
            hash_tree.frontier_forest_append(forest, roots, 2, 3, 2)
            hash_tree.frontier_forest_pad_back(forest, roots[4], 1, 2)
            local frontier = hash_tree.frontier(H4, "keccak256")
            hash_tree.frontier_append(frontier, roots, 1, 4, 2)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), hash_tree.frontier_get_root_hash(frontier))
            expect.equal(hash_tree.frontier_forest_get_node(forest, 4, 2), roots[2])
            expect.fail(function()
                hash_tree.frontier_forest_get_node(forest, 0, 1)
            end, "below an opaque hash")
            expect.fail(function()
                hash_tree.frontier_forest_get_node(forest, 1, 2)
            end, "not aligned")
            expect.fail(function()
                hash_tree.frontier_forest_get_siblings(forest, 1, 2)
            end, "not aligned")
            local into = { roots[1] }
            expect.fail(function()
                hash_tree.frontier_forest_get_siblings(forest, 0, 0, into)
            end, "below an opaque hash")
            expect.equal(#into, 1)
            expect.equal(into[1], roots[1])
        end)

        it("queries inside completed forests, including repeated ones", function()
            local sub_leaves, other_leaves = {}, {}
            for i = 1, 4 do
                sub_leaves[i] = keccak("sub-" .. i)
                other_leaves[i] = keccak("other-" .. i)
            end
            local sub = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_append(sub, sub_leaves)
            local other = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_append(other, other_leaves)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_pad_back(forest, sub, 3)
            hash_tree.frontier_forest_push_back(forest, other)
            local leaves = {}
            for _ = 1, 3 do
                table.move(sub_leaves, 1, 4, #leaves + 1, leaves)
            end
            table.move(other_leaves, 1, 4, #leaves + 1, leaves)
            expect_matches_reference(forest, leaves)
        end)

        it("rejects invalid ranges and bad values", function()
            local leaves = make_leaves(4)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 0, 2)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 2, 5)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 4, 2)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 1, 2.5)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, "short")
            end, "invalid hash size")
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, hash_tree.frontier_forest(2, "keccak256"))
            end, "not full")
            local sub1 = hash_tree.frontier_forest(1, "keccak256")
            hash_tree.frontier_forest_append(sub1, leaves, 1, 2)
            local sub2 = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_append(sub2, leaves)
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, { sub1, sub2 })
            end, "a value is not a hash")
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, sub2, 1)
            end, "height mismatch")
        end)

        it("rejects completed forests built with another hash function", function()
            local sha_forest = hash_tree.frontier_forest(2, "sha256")
            hash_tree.frontier_forest_append(sha_forest, {
                cartesi.sha256("one"),
                cartesi.sha256("two"),
                cartesi.sha256("three"),
                cartesi.sha256("four"),
            })
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, sha_forest)
            end, "hash function mismatch")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, sha_forest, 4)
            end, "hash function mismatch")
        end)

        it("rejects non-integer counts and heights without mutation", function()
            local leaves = make_leaves(MAX4)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, leaves[1], 1.5)
            end, "invalid pad count")
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, leaves[1], -1)
            end, "invalid value height")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 1.5, 2)
            end, "invalid range")
            hash_tree.frontier_forest_append(forest, leaves)
            expect_matches_reference(forest, leaves)
        end)

        it("rejects values the leaf count is not aligned to", function()
            local leaves = make_leaves(2)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(forest, leaves[1])
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, leaves[2], 1)
            end, "not aligned")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, leaves[2], 1, 1)
            end, "not aligned")
        end)

        it("rejects overflow without mutating the forest", function()
            local pad = keccak("pad")
            local leaves = make_leaves(3)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_append(forest, leaves)
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, pad, MAX4)
            end, "too many leaves")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, make_leaves(MAX4))
            end, "too many leaves")
            expect.fail(function()
                hash_tree.frontier_forest_get_root_hash(forest)
            end, "not full")
            -- the rejected appends changed nothing: completing still matches the reference
            hash_tree.frontier_forest_pad_back(forest, pad, MAX4 - 3)
            local expected = { leaves[1], leaves[2], leaves[3] }
            for i = 4, MAX4 do
                expected[i] = pad
            end
            expect_matches_reference(forest, expected)
            expect.fail(function()
                hash_tree.frontier_forest_push_back(forest, pad)
            end, "too many leaves")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, pad, 1)
            end, "too many leaves")
        end)

        it("handles the height-62 mcycle claim shape", function()
            local H62 = 62
            local first_leaf, pad = keccak("first"), keccak("pad")
            local forest = hash_tree.frontier_forest(H62, "keccak256")
            hash_tree.frontier_forest_push_back(forest, first_leaf)
            hash_tree.frontier_forest_pad_back(forest, pad, (1 << H62) - 1)
            -- reference: fold the lone leaf against doubling all-pad subtrees
            local root, level_pad = first_leaf, pad
            for _ = 1, H62 do
                root = keccak(root, level_pad)
                level_pad = keccak(level_pad, level_pad)
            end
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
            expect.equal(hash_tree.frontier_forest_get_node(forest, 0, 0), first_leaf)
            expect.equal(hash_tree.frontier_forest_get_node(forest, (1 << H62) - 1, 0), pad)
            hash_tree.verify_slice({
                target_address = (1 << H62) - 1,
                log2_target_size = 0,
                target_hash = pad,
                log2_root_size = H62,
                root_hash = root,
                sibling_hashes = hash_tree.frontier_forest_get_siblings(forest, (1 << H62) - 1, 0),
            })
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, pad, 1)
            end, "too many leaves")
        end)

        it("uses the hash function selected by the constructor", function()
            local leaves = { cartesi.sha256("left"), cartesi.sha256("right") }
            local forest = hash_tree.frontier_forest(1, "sha256")
            hash_tree.frontier_forest_append(forest, leaves)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), cartesi.sha256(leaves[1], leaves[2]))
        end)
    end)

    describe("verify_slice", function()
        it("verifies proofs at the outputs Merkle tree depth", function()
            local proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), make_leaves(10))
            for _, proof in ipairs(proofs) do
                expect.equal(proof.log2_root_size, H)
                hash_tree.verify_slice(proof)
            end
        end)

        it("rejects a proof with a tampered target", function()
            local proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), make_leaves(4))
            local proof = proofs[2]
            proof.target_hash = string.rep("\0", cartesi.HASH_SIZE)
            expect.fail(function()
                hash_tree.verify_slice(proof)
            end)
        end)
    end)
end)

lester.report()
lester.exit()
