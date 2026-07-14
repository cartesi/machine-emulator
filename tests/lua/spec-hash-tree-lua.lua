--[[
Test suite for the Lua hash-tree module.
Specifically, it provides test coverage for:
    src/cartesi/hash-tree.lua
It covers the outputs-tree frontier accumulator and the proof verifier at the outputs-tree depth.
Can be run independently during development of the mentioned file.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")

local H = cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT

-- Independent reference for the height-H pristine-padded keccak outputs root, mirroring
-- check_outputs_root_hash in tests/lua/cmio-test.lua. The leaves are already keccak256(output).
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
    end)

    describe("verify_slice", function()
        it("verifies proofs at the outputs-tree depth", function()
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
