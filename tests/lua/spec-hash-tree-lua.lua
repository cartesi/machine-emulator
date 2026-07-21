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
        it("produces proofs that verify and share the reference root", function()
            for _, n in ipairs(counts) do
                local leaves = make_leaves(n)
                local proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H), leaves)
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
            local frontier = hash_tree.frontier(H)
            local leaves = {}
            expect.equal(hash_tree.frontier_get_root_hash(frontier), reference_root(leaves))
            for k = 1, 100 do
                leaves[k] = leaf(k)
                hash_tree.frontier_push_back(frontier, leaves[k])
                expect.equal(hash_tree.frontier_get_root_hash(frontier), reference_root(leaves))
            end
        end)

        it("resumes from the previous epoch's last proof (epoch-split equivalence)", function()
            for _, n in ipairs({ 5, 8, 16, 33, 100 }) do
                local leaves = make_leaves(n)
                local single = hash_tree.frontier_next_proofs(hash_tree.frontier(H), leaves)
                for split = 1, n - 1 do
                    local first, second = {}, {}
                    for k = 1, split do
                        first[k] = leaves[k]
                    end
                    for k = split + 1, n do
                        second[#second + 1] = leaves[k]
                    end
                    local first_proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H), first)
                    -- the previous epoch's last proof seeds the next epoch
                    local seed = hash_tree.frontier(first_proofs[#first_proofs])
                    local second_proofs = hash_tree.frontier_next_proofs(seed, second)
                    for j = 1, #second do
                        expect_same_proof(second_proofs[j], single[split + j])
                    end
                end
            end
        end)

        it("has nothing to prove for an empty epoch", function()
            expect.equal(#hash_tree.frontier_next_proofs(hash_tree.frontier(H), {}), 0)
        end)

        it("rejects a frontier leaf count that exceeds 64 bits", function()
            local frontier = hash_tree.frontier(64)
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
                    local frontier = hash_tree.frontier(SMALL_H)
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
            local frontier = hash_tree.frontier(SMALL_H)
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
            local padded = hash_tree.frontier(SMALL_H)
            hash_tree.frontier_pad_back(padded, pad, SMALL_MAX)
            expect.equal(padded[SMALL_H + 1], reference_padded_root({}, pad, SMALL_MAX))
            expect.equal(hash_tree.frontier_get_root_hash(padded), reference_padded_root({}, pad, SMALL_MAX))
            -- filled by pushing
            local pushed = hash_tree.frontier(SMALL_H)
            local leaves = make_leaves(SMALL_MAX)
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(pushed, l)
            end
            expect.equal(hash_tree.frontier_get_root_hash(pushed), reference_padded_root(leaves, pad, 0))
        end)

        it("rejects padding past the end of the tree", function()
            local frontier = hash_tree.frontier(SMALL_H)
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, SMALL_MAX)
            end)
        end)

        it("fills a tree taller than a Lua integer without materializing its capacity", function()
            local height = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
                + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
            local frontier = hash_tree.frontier(height)
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
                    local frontier = hash_tree.frontier(SMALL_H)
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
            local frontier = hash_tree.frontier(SMALL_H)
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, 1, 2)
            end, "frontier is not aligned to the pad size")
        end)

        it("rejects a subtree pad past the end of the tree", function()
            local frontier = hash_tree.frontier(SMALL_H)
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
            local frontier = hash_tree.frontier(SMALL_H)
            hash_tree.frontier_push_back(frontier, leaves[1])
            hash_tree.frontier_push_back(frontier, leaves[2])
            hash_tree.frontier_push_back(frontier, cartesi.keccak256(leaves[3], leaves[4]), 1)
            local reference = hash_tree.frontier(SMALL_H)
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(reference, l)
            end
            expect.equal(
                hash_tree.frontier_get_root_hash(frontier, pad),
                hash_tree.frontier_get_root_hash(reference, pad)
            )
        end)

        it("rejects a subtree push when the frontier is not aligned to it", function()
            local frontier = hash_tree.frontier(4)
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_push_back(frontier, leaf(2), 1)
            end, "frontier is not aligned to the hash size")
        end)
    end)

    describe("frontier_get_root_hash", function()
        local H4 = 4
        local MAX4 = 1 << H4
        local pad = cartesi.keccak256("pad")

        -- Root of the tree over the pushed leaves with every empty leaf taking pad_leaf: the same
        -- result as filling the tree with an explicit pad_back and reading it with no pad_leaf.
        local function fill_and_read(leaves)
            local frontier = hash_tree.frontier(H4)
            for _, l in ipairs(leaves) do
                hash_tree.frontier_push_back(frontier, l)
            end
            hash_tree.frontier_pad_back(frontier, pad, MAX4 - #leaves)
            return hash_tree.frontier_get_root_hash(frontier)
        end

        it("pads the empty leaves with pad_leaf", function()
            for n = 0, MAX4 do
                local leaves = make_leaves(n)
                local frontier = hash_tree.frontier(H4)
                for _, l in ipairs(leaves) do
                    hash_tree.frontier_push_back(frontier, l)
                end
                expect.equal(hash_tree.frontier_get_root_hash(frontier, pad), fill_and_read(leaves))
            end
        end)

        it("pads with the pristine leaf when pad_leaf is omitted", function()
            -- default path stays byte-for-byte what it was before pad_leaf existed
            local z = string.rep("\0", cartesi.HASH_SIZE)
            local frontier = hash_tree.frontier(H4)
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.equal(hash_tree.frontier_get_root_hash(frontier), hash_tree.frontier_get_root_hash(frontier, z))
        end)

        it("pads with a subtree root when log2_pad_size is given", function()
            local log2_pad_size = 2
            local pad_size = 1 << log2_pad_size
            for n = 0, MAX4 // pad_size do
                -- fill n complete subtrees of distinct leaves, so levels below log2_pad_size are empty
                local leaves = make_leaves(n * pad_size)
                local frontier = hash_tree.frontier(H4)
                for _, l in ipairs(leaves) do
                    hash_tree.frontier_push_back(frontier, l)
                end
                -- padding with the subtree root is padding with the subtree's own leaves
                local subtree = { leaf(100), leaf(101), leaf(102), leaf(103) }
                local subtree_root = cartesi.keccak256(
                    cartesi.keccak256(subtree[1], subtree[2]),
                    cartesi.keccak256(subtree[3], subtree[4])
                )
                local expected_frontier = hash_tree.frontier(H4)
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
            local frontier = hash_tree.frontier(H4)
            hash_tree.frontier_push_back(frontier, leaf(1))
            expect.fail(function()
                hash_tree.frontier_get_root_hash(frontier, pad, 2)
            end, "frontier is not aligned to the pad size")
        end)
    end)

    describe("verify_slice", function()
        it("verifies proofs at the outputs Merkle tree depth", function()
            local proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H), make_leaves(10))
            for _, proof in ipairs(proofs) do
                expect.equal(proof.log2_root_size, H)
                hash_tree.verify_slice(proof)
            end
        end)

        it("rejects a proof with a tampered target", function()
            local proofs = hash_tree.frontier_next_proofs(hash_tree.frontier(H), make_leaves(4))
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
