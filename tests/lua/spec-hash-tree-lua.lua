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
local fs = require("cartesi.filesystem")
local tabular = require("cartesi.tabular")
local tests_util = require("cartesi.tests.util")

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
-- A new empty directory, removed with its files when the returned owner closes.
local function new_scope_directory()
    local directory = fs.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "cartesi-test-")
    return tests_util.scope_exit(function()
        for _, name in ipairs(fs.list_directory(directory)) do
            fs.remove_file(directory .. "/" .. name)
        end
        fs.remove_directory(directory)
    end),
        directory
end

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

        it("rejects invalid subtree heights without changing the frontier", function()
            local hash = leaf(1)
            local operations = {
                function(f, height)
                    hash_tree.frontier_push_back(f, hash, height)
                end,
                function(f, height)
                    hash_tree.frontier_append(f, { hash }, nil, nil, height)
                end,
                function(f, height)
                    hash_tree.frontier_append(f, {}, nil, nil, height)
                end,
                function(f, height)
                    hash_tree.frontier_pad_back(f, hash, 1, height)
                end,
                function(f, height)
                    hash_tree.frontier_pad_back(f, hash, 0, height)
                end,
                function(f, height)
                    hash_tree.frontier_pad_back(f, hash, nil, height)
                end,
                function(f, height)
                    hash_tree.frontier_get_root_hash(f, hash, height)
                end,
                hash_tree.frontier_get_leaf_count,
            }
            for _, count in ipairs({ 0, 1, 8 }) do
                local frontier = hash_tree.frontier(3, "keccak256")
                hash_tree.frontier_pad_back(frontier, hash, count)
                local before = hash_tree.frontier_copy(frontier)
                for _, height in ipairs({ -1, 1.5, 4, "2" }) do
                    for _, operation in ipairs(operations) do
                        expect.fail(function()
                            operation(frontier, height)
                        end, "invalid subtree height")
                        expect.equal(frontier, before)
                    end
                end
            end
        end)

        it("accepts subtrees as tall as the frontier", function()
            local hash = leaf(1)
            for _, height in ipairs({ 0, 3, 72 }) do
                local frontier = hash_tree.frontier(height, "keccak256")
                expect.equal(hash_tree.frontier_get_root_hash(frontier, hash, height), hash)
                hash_tree.frontier_push_back(frontier, hash, height)
                expect.equal(hash_tree.frontier_get_root_hash(frontier), hash)
                expect.equal(hash_tree.frontier_get_leaf_count(frontier, height), 1)
                frontier = hash_tree.frontier(height, "keccak256")
                hash_tree.frontier_append(frontier, { hash }, nil, nil, height)
                expect.equal(hash_tree.frontier_get_root_hash(frontier), hash)
                frontier = hash_tree.frontier(height, "keccak256")
                hash_tree.frontier_pad_back(frontier, hash, 1, height)
                expect.equal(hash_tree.frontier_get_root_hash(frontier), hash)
                frontier = hash_tree.frontier(height, "keccak256")
                hash_tree.frontier_pad_back(frontier, hash, nil, height)
                expect.equal(hash_tree.frontier_get_root_hash(frontier), hash)
            end
        end)

        it("rejects unsupported frontier and forest hash functions", function()
            for _, hash_type in ipairs({ "tohex", "HASH_SIZE", "unknown" }) do
                expect.fail(function()
                    hash_tree.frontier(3, hash_type)
                end, "unsupported hash function")
                expect.fail(function()
                    hash_tree.frontier_forest(3, hash_type)
                end, "unsupported hash function")
            end
        end)

        it("rejects hashes that are not hash-sized strings", function()
            for _, bad in ipairs({ "", string.rep("a", cartesi.HASH_SIZE - 1), 1 }) do
                local frontier = hash_tree.frontier(H, "keccak256")
                hash_tree.frontier_push_back(frontier, leaf(1))
                expect.fail(function()
                    hash_tree.frontier_push_back(frontier, bad)
                end, "invalid hash")
                expect.fail(function()
                    hash_tree.frontier_append(frontier, { leaf(2), bad })
                end, "invalid hash")
                expect.fail(function()
                    hash_tree.frontier_pad_back(frontier, bad, 1)
                end, "invalid hash")
                expect.fail(function()
                    hash_tree.frontier_next_proofs(frontier, { leaf(2), bad })
                end, "invalid hash")
                expect.fail(function()
                    hash_tree.frontier_get_root_hash(frontier, bad)
                end, "invalid pad hash")
                expect.equal(hash_tree.frontier_get_leaf_count(frontier), 1)
            end
        end)

        it("counts leaves and aligned subtrees, including tall frontiers", function()
            local frontier = hash_tree.frontier(72, "keccak256")
            expect.equal(hash_tree.frontier_get_leaf_count(frontier, 48), 0)
            hash_tree.frontier_pad_back(frontier, leaf(1), 3 << 48)
            expect.equal(hash_tree.frontier_get_leaf_count(frontier, 48), 3)
            expect.equal(hash_tree.frontier_get_leaf_count(frontier), 3 << 48)
            hash_tree.frontier_push_back(frontier, leaf(2))
            expect.fail(function()
                hash_tree.frontier_get_leaf_count(frontier, 48)
            end, "frontier is not aligned to the subtree size")
            hash_tree.frontier_pad_back(frontier, leaf(3))
            expect.equal(hash_tree.frontier_get_leaf_count(frontier, 48), 1 << 24)
            expect.fail(function()
                hash_tree.frontier_get_leaf_count(frontier)
            end, "frontier leaf count exceeds 64 bits")
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

        it("rejects invalid last proofs before constructing a frontier or forest", function()
            -- Repeated leaves keep the root valid when address bits change, isolating the range check.
            local frontier = hash_tree.frontier(4, "keccak256")
            hash_tree.frontier_pad_back(frontier, leaf(1), 15)
            local proof = hash_tree.frontier_next_proofs(frontier, { leaf(1) })[1]
            local cases = {
                { "target_address", 16, "proof target address is out of range" },
                { "target_address", -1, "proof target address is out of range" },
                { "target_address", 1.5, "invalid proof target address" },
                { "target_address", "2", "invalid proof target address" },
                { "log2_target_size", 1, "proof target is not a leaf" },
                { "log2_root_size", -1, "invalid proof sizes" },
                { "log2_root_size", 65, "invalid proof sizes" },
                { "log2_root_size", 4.5, "invalid proof sizes" },
                { "root_hash", leaf(99), "target node not in tree" },
                { "target_hash", leaf(99), "target node not in tree" },
                { "target_hash", "", "invalid target hash" },
                { "sibling_hashes", { leaf(1) }, "wrong number of siblings" },
                { "sibling_hashes", { leaf(1), leaf(2), leaf(3), leaf(4), leaf(5) }, "wrong number of siblings" },
            }
            for _, case in ipairs(cases) do
                local corrupted = tabular.deep_copy(proof)
                corrupted[case[1]] = case[2]
                expect.fail(function()
                    hash_tree.frontier(corrupted, "keccak256")
                end, case[3])
                expect.fail(function()
                    hash_tree.frontier_forest(corrupted, "keccak256")
                end, case[1] == "log2_root_size" and "unsupported forest height" or case[3])
            end
        end)

        it("reconstructs full frontiers from last proofs through height 64", function()
            -- Bound the regression test so the former infinite loop fails instead of hanging the suite.
            local _ <close> = tests_util.scope_exit(function()
                debug.sethook()
            end)
            debug.sethook(function()
                error("frontier construction did not terminate")
            end, "", 1000000)
            for _, hash_type in ipairs({ "keccak256", "sha256" }) do
                for _, height in ipairs({ 0, 1, 4, 63, 64 }) do
                    local hash, siblings = leaf(1), {}
                    for level = 1, height do
                        siblings[level] = hash
                        hash = cartesi[hash_type](hash, hash)
                    end
                    local proof = {
                        log2_root_size = height,
                        log2_target_size = 0,
                        target_address = (1 << height) - 1,
                        target_hash = leaf(1),
                        root_hash = hash,
                        sibling_hashes = siblings,
                    }
                    local frontier = hash_tree.frontier(proof, hash_type)
                    expect.equal(#frontier, height + 1)
                    expect.equal(frontier[height + 1], hash)
                    expect.equal(hash_tree.frontier_get_root_hash(frontier), hash)
                    for level = 1, height do
                        expect.equal(frontier[level], false)
                    end
                    expect.fail(function()
                        hash_tree.frontier_push_back(frontier, leaf(2))
                    end, "too many leaves")
                    if height == 63 then
                        proof.target_address = -1
                        expect.fail(function()
                            hash_tree.frontier(proof, hash_type)
                        end, "proof target address is out of range")
                    end
                end
            end
        end)

        it("has nothing to prove for an empty epoch", function()
            expect.equal(#hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), {}), 0)
        end)

        it("rejects proving more leaves than the tree has room for", function()
            local frontier = hash_tree.frontier(2, "keccak256")
            hash_tree.frontier_append(frontier, make_leaves(3))
            expect.equal(#hash_tree.frontier_next_proofs(frontier, { leaf(4) }), 1)
            expect.fail(function()
                hash_tree.frontier_next_proofs(frontier, { leaf(4), leaf(5) })
            end, "too many leaves")
            hash_tree.frontier_push_back(frontier, leaf(4))
            expect.fail(function()
                hash_tree.frontier_next_proofs(frontier, { leaf(5) })
            end, "too many leaves")
        end)

        it("proves leaves across 2^63 in a tree of height 64", function()
            local frontier = hash_tree.frontier(64, "keccak256")
            hash_tree.frontier_pad_back(frontier, leaf(1), (1 << 63) - 1)
            local leaves = { leaf(2), leaf(3), leaf(4) }
            local proofs = hash_tree.frontier_next_proofs(frontier, leaves)
            local full = hash_tree.frontier_copy(frontier)
            hash_tree.frontier_append(full, leaves)
            local root_hash = hash_tree.frontier_get_root_hash(full)
            for i, proof in ipairs(proofs) do
                expect.equal(proof.target_address, (1 << 63) + i - 2)
                expect.equal(proof.root_hash, root_hash)
                hash_tree.verify_slice(proof)
            end
        end)

        it("refuses proofs in trees taller than 64", function()
            expect.fail(function()
                hash_tree.frontier_next_proofs(hash_tree.frontier(65, "keccak256"), { leaf(1) })
            end, "tree too tall for proofs")
        end)

        it("rejects a frontier leaf count that exceeds 64 bits", function()
            local frontier = hash_tree.frontier(64, "keccak256")
            frontier[65] = leaf(1)
            expect.fail(function()
                hash_tree.frontier_next_proofs(frontier, { leaf(2) })
            end, "frontier leaf count exceeds 64 bits")
        end)
    end)

    describe("frontier_store", function()
        it("loads the frontier it stored, empty, partial, or full", function()
            local _ <close>, directory = new_scope_directory()
            local path = directory .. "/frontier.json"
            local full = hash_tree.frontier(2, "keccak256")
            hash_tree.frontier_append(full, make_leaves(4))
            local partial = hash_tree.frontier(H, "keccak256")
            hash_tree.frontier_append(partial, make_leaves(5))
            for _, frontier in ipairs({ hash_tree.frontier(H, "keccak256"), partial, full }) do
                hash_tree.frontier_store(frontier, path)
                local loaded = hash_tree.frontier_load(path, #frontier - 1, "keccak256")
                expect.equal(#loaded, #frontier)
                expect.equal(hash_tree.frontier_get_leaf_count(loaded), hash_tree.frontier_get_leaf_count(frontier))
                expect.equal(hash_tree.frontier_get_root_hash(loaded), hash_tree.frontier_get_root_hash(frontier))
                expect.equal(loaded.hash_function, cartesi.keccak256)
            end
            expect.equal(table.concat(fs.list_directory(directory), ","), "frontier.json")
        end)

        it("rejects a frontier of another height, invalid entries, or a full frontier with other levels", function()
            local _ <close>, directory = new_scope_directory()
            local path = directory .. "/frontier.json"
            hash_tree.frontier_store(hash_tree.frontier(4, "keccak256"), path)
            expect.fail(function()
                hash_tree.frontier_load(path, 3, "keccak256")
            end, "frontier height does not match")
            for _, hash_type in ipairs({ "tohex", "HASH_SIZE", "unknown" }) do
                expect.fail(function()
                    hash_tree.frontier_load(path, 4, hash_type)
                end, "unsupported hash function")
            end
            fs.write_file(cartesi.tojson({ false, "short", false }, 2, "Base64Array"), path)
            expect.fail(function()
                hash_tree.frontier_load(path, 2, "keccak256")
            end, "invalid frontier entry")
            fs.write_file(cartesi.tojson({ leaf(1), false, leaf(2) }, 2, "Base64Array"), path)
            expect.fail(function()
                hash_tree.frontier_load(path, 2, "keccak256")
            end, "invalid complete frontier")
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

        it("fills all remaining positions when count is omitted", function()
            for _, pad_height in ipairs({ 0, 2 }) do
                local pad_size = 1 << pad_height
                local pad_root = pad
                for _ = 1, pad_height do
                    pad_root = cartesi.keccak256(pad_root, pad_root)
                end
                for n = 0, SMALL_MAX, pad_size do
                    local leaves = make_leaves(n)
                    local frontier = hash_tree.frontier(SMALL_H, "keccak256")
                    hash_tree.frontier_append(frontier, leaves)
                    hash_tree.frontier_pad_back(frontier, pad_root, nil, pad_height)
                    local expected = reference_padded_root(leaves, pad, SMALL_MAX - n)
                    expect.equal(frontier[SMALL_H + 1], expected)
                    for level = 1, SMALL_H do
                        expect.equal(frontier[level], false)
                    end
                    hash_tree.frontier_pad_back(frontier, pad_root, nil, pad_height)
                    expect.equal(frontier[SMALL_H + 1], expected)
                    expect.fail(function()
                        hash_tree.frontier_push_back(frontier, pad)
                    end, "too many leaves")
                end
            end
        end)

        it("fills to the root without a leaf count at integer boundaries", function()
            for _, height in ipairs({ 0, 63, 64, 72 }) do
                for _, count in ipairs({ 0, 1 }) do
                    local frontier = hash_tree.frontier(height, "keccak256")
                    hash_tree.frontier_pad_back(frontier, pad, count)
                    hash_tree.frontier_pad_back(frontier, pad)
                    local expected = pad
                    for _ = 1, height do
                        expected = cartesi.keccak256(expected, expected)
                    end
                    expect.equal(frontier[height + 1], expected)
                    for level = 1, height do
                        expect.equal(frontier[level], false)
                    end
                    expect.fail(function()
                        hash_tree.frontier_pad_back(frontier, pad, 1)
                    end, "too many leaves")
                end
            end
        end)

        it("pads tall frontiers with unsigned 64-bit counts", function()
            for _, hash_type in ipairs({ "keccak256", "sha256" }) do
                for _, pad_height in ipairs({ 0, 3 }) do
                    for _, count in ipairs({ 1 << 63, -1 }) do
                        local frontier = hash_tree.frontier(66 + pad_height, hash_type)
                        local split = hash_tree.frontier(66 + pad_height, hash_type)
                        -- Leave the lower slots empty beneath an occupied slot beyond the count's bits.
                        hash_tree.frontier_push_back(frontier, leaf(1), 65 + pad_height)
                        hash_tree.frontier_push_back(split, leaf(1), 65 + pad_height)
                        -- Split the unsigned count into parts that each fit a positive Lua integer.
                        hash_tree.frontier_pad_back(split, pad, count >> 1, pad_height)
                        hash_tree.frontier_pad_back(split, pad, count >> 1, pad_height)
                        hash_tree.frontier_pad_back(split, pad, count & 1, pad_height)
                        hash_tree.frontier_pad_back(frontier, pad, count, pad_height)
                        for level = 1, #frontier do
                            expect.equal(frontier[level], split[level])
                        end
                        expect.equal(
                            hash_tree.frontier_get_root_hash(frontier),
                            hash_tree.frontier_get_root_hash(split)
                        )
                    end
                end
            end
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

        it("pads with subtree roots at a given height", function()
            local pad_height = 2
            local pad_size = 1 << pad_height
            local pad_root = cartesi.keccak256(cartesi.keccak256(pad, pad), cartesi.keccak256(pad, pad))
            -- every aligned fill and every subtree pad count that still fits
            for n = 0, SMALL_MAX // pad_size do
                for k = 0, SMALL_MAX // pad_size - n do
                    local leaves = make_leaves(n * pad_size)
                    local frontier = hash_tree.frontier(SMALL_H, "keccak256")
                    for _, l in ipairs(leaves) do
                        hash_tree.frontier_push_back(frontier, l)
                    end
                    hash_tree.frontier_pad_back(frontier, pad_root, k, pad_height)
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
            expect.fail(function()
                hash_tree.frontier_pad_back(frontier, pad, nil, 2)
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

        it("pushes a subtree root at a given height", function()
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
            end, "frontier is not aligned to the subtree size")
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

        it("appends a slice with an exclusive end index", function()
            local leaves = make_leaves(10)
            local expected = hash_tree.frontier(4, "keccak256")
            for k = 3, 7 do
                hash_tree.frontier_push_back(expected, leaves[k])
            end
            local frontier = hash_tree.frontier(4, "keccak256")
            hash_tree.frontier_append(frontier, leaves, 1, 1) -- empty at the start
            hash_tree.frontier_append(frontier, leaves, 3, 8)
            hash_tree.frontier_append(frontier, leaves, 8, 8) -- an empty range is a no-op
            hash_tree.frontier_append(frontier, leaves, #leaves + 1, #leaves + 1) -- empty past the end
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
            hash_tree.frontier_append(frontier, roots, 1, 4, 1)
            expect.equal(
                hash_tree.frontier_get_root_hash(frontier, pad),
                hash_tree.frontier_get_root_hash(expected, pad)
            )
        end)

        it("rejects invalid ranges and overflow", function()
            local leaves = make_leaves(4)
            local frontier = hash_tree.frontier(2, "keccak256")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 0, 3)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 3, 2)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 1, 2.5)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 1, 6)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_append(frontier, make_leaves(5))
            end, "too many leaves")
            hash_tree.frontier_append(frontier, leaves, 1, 5)
            expect.fail(function()
                hash_tree.frontier_push_back(frontier, leaves[1])
            end, "too many leaves")
            expect.fail(function()
                hash_tree.frontier_append(frontier, leaves, 1, 2)
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

        it("pads with a subtree root at a given height", function()
            local pad_height = 2
            local pad_size = 1 << pad_height
            for n = 0, MAX4 // pad_size do
                -- fill n complete subtrees of distinct leaves, so levels below pad_height are empty
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
                    hash_tree.frontier_get_root_hash(frontier, subtree_root, pad_height),
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
        local function reference_levels(leaves, hash_type)
            assert(#leaves == MAX4)
            local hash_function = cartesi[hash_type or "keccak256"]
            local levels = { [0] = leaves }
            for log2_size = 1, H4 do
                local parents = {}
                local children = levels[log2_size - 1]
                for i = 1, #children, 2 do
                    parents[#parents + 1] = hash_function(children[i], children[i + 1])
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
                    expect.equal(hash_tree.frontier_forest_get_node_hash(forest, position, log2_size), target_hash)
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

        it("restores coverage and the last leaf's path from a proof", function()
            local leaves = make_leaves(MAX4)
            for _, hash_type in ipairs({ "keccak256", "sha256" }) do
                local levels = reference_levels(leaves, hash_type)
                for position = 0, MAX4 - 1 do
                    local siblings = {}
                    for height = 0, H4 - 1 do
                        siblings[height + 1] = levels[height][((position >> height) ~ 1) + 1]
                    end
                    local proof = {
                        log2_root_size = H4,
                        log2_target_size = 0,
                        target_address = position,
                        target_hash = leaves[position + 1],
                        root_hash = levels[H4][1],
                        sibling_hashes = siblings,
                    }
                    local forest = hash_tree.frontier_forest(proof, hash_type)
                    expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), position + 1)
                    hash_tree.frontier_forest_append(forest, leaves, position + 2)
                    expect.equal(hash_tree.frontier_forest_get_root_hash(forest), proof.root_hash)
                    expect.equal(hash_tree.frontier_forest_get_node_hash(forest, position, 0), proof.target_hash)
                    expect.equal(hash_tree.frontier_forest_get_siblings(forest, position, 0), siblings)
                    for level = 1, H4 do
                        expect.equal(forest[level], false)
                    end
                end
            end
        end)

        it("retains the rightmost path through storage without opening its siblings", function()
            local leaves = make_leaves(MAX4)
            local levels = reference_levels(leaves)
            local siblings = {}
            for height = 0, H4 - 1 do
                siblings[height + 1] = levels[height][(MAX4 >> height) - 1]
            end
            local proof = {
                log2_root_size = H4,
                log2_target_size = 0,
                target_address = MAX4 - 1,
                target_hash = leaves[MAX4],
                root_hash = levels[H4][1],
                sibling_hashes = siblings,
            }
            local forest = hash_tree.frontier_forest(proof, "keccak256")
            local _ <close>, directory = new_scope_directory()
            local path = directory .. "/frontier.json"
            hash_tree.frontier_forest_store(forest, directory, path)
            forest = hash_tree.frontier_forest_load(directory, path)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), proof.root_hash)
            expect.equal(hash_tree.frontier_forest_get_node_hash(forest, MAX4 - 1, 0), leaves[MAX4])
            expect.equal(hash_tree.frontier_forest_get_siblings(forest, MAX4 - 1, 0), siblings)
            expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 0, H4 - 1), siblings[H4])
            local hash, err = hash_tree.frontier_forest_get_node_hash(forest, 0, 0)
            expect.equal(hash, nil)
            expect.equal(err, "the node is below an opaque hash")
        end)

        it("restores full forests from last proofs at the supported height boundaries", function()
            for _, height in ipairs({ 0, 1, 62 }) do
                local hash, siblings = leaf(1), {}
                for level = 1, height do
                    siblings[level] = hash
                    hash = keccak(hash, hash)
                end
                local proof = {
                    log2_root_size = height,
                    log2_target_size = 0,
                    target_address = (1 << height) - 1,
                    target_hash = leaf(1),
                    root_hash = hash,
                    sibling_hashes = siblings,
                }
                local forest = hash_tree.frontier_forest(proof, "keccak256")
                expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), 1 << height)
                expect.equal(hash_tree.frontier_forest_get_root_hash(forest), hash)
                expect.equal(hash_tree.frontier_forest_get_siblings(forest, proof.target_address, 0), siblings)
                for level = 1, height do
                    expect.equal(forest[level], false)
                end
                expect.fail(function()
                    hash_tree.frontier_forest_push_back(forest, leaf(2))
                end, "too many leaves")
                proof.log2_root_size = 63
                expect.fail(function()
                    hash_tree.frontier_forest(proof, "keccak256")
                end, "unsupported forest height")
            end
        end)

        it("fills to capacity with raw hashes and retained subtrees", function()
            for _, height in ipairs({ 0, 2, H4 }) do
                local width = 1 << height
                local pad_leaves = make_leaves(width)
                local subtree = hash_tree.frontier_forest(height, "keccak256")
                hash_tree.frontier_forest_append(subtree, pad_leaves)
                local root = hash_tree.frontier_forest_get_root_hash(subtree)
                for _, opaque in ipairs({ false, true }) do
                    for prefix_count = 0, MAX4, width do
                        local leaves = make_leaves(prefix_count)
                        local forest = hash_tree.frontier_forest(H4, "keccak256")
                        hash_tree.frontier_forest_append(forest, leaves)
                        local value = opaque and root or subtree
                        hash_tree.frontier_forest_pad_back(forest, value, nil, height)
                        expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), MAX4)
                        -- Filling a full forest again leaves its root and retained nodes unchanged.
                        hash_tree.frontier_forest_pad_back(forest, value, nil, height)
                        for position = prefix_count, MAX4 - 1, width do
                            if opaque then
                                expect.equal(hash_tree.frontier_forest_get_node_hash(forest, position, height), root)
                                if height > 0 then
                                    -- Expansion authenticates and preserves the repeated padding's descendants.
                                    local hash = hash_tree.frontier_forest_get_node_hash(forest, position, 0)
                                    if not hash then
                                        hash_tree.frontier_forest_expand_leaf(forest, position, subtree)
                                    end
                                end
                            end
                            for _, hash in ipairs(pad_leaves) do
                                leaves[#leaves + 1] = hash
                            end
                        end
                        expect_matches_reference(forest, leaves)
                    end
                end
            end
        end)

        it("validates implicit padding before changing the forest", function()
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(forest, leaf(1))
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, leaf(2), nil, 1)
            end, "the forest is not aligned to the given height")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, leaf(2), nil, H4 + 1)
            end, "value height exceeds forest height")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, "short")
            end, "invalid hash size")
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, hash_tree.frontier_forest(0, "keccak256"))
            end, "a forest value is not full")
            local wrong_hash = hash_tree.frontier_forest(0, "sha256")
            hash_tree.frontier_forest_push_back(wrong_hash, leaf(2))
            expect.fail(function()
                hash_tree.frontier_forest_pad_back(forest, wrong_hash)
            end, "value hash function mismatch")
            expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), 1)
            hash_tree.frontier_forest_pad_back(forest, leaf(2))
            local leaves = { leaf(1) }
            for i = 2, MAX4 do
                leaves[i] = leaf(2)
            end
            expect_matches_reference(forest, leaves)
        end)

        it("assembles a fixed-point tree with push_back and append", function()
            local leaves = make_leaves(MAX4)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_append(forest, leaves, 1, 1) -- empty at the start
            hash_tree.frontier_forest_push_back(forest, leaves[1])
            hash_tree.frontier_forest_append(forest, leaves, 2, 10)
            hash_tree.frontier_forest_append(forest, leaves, 10, 10) -- an empty range is a no-op
            hash_tree.frontier_forest_append(forest, leaves, 10, MAX4 + 1)
            hash_tree.frontier_forest_append(forest, leaves, MAX4 + 1, MAX4 + 1) -- empty after filling the tree
            expect_matches_reference(forest, leaves)
        end)

        it("pads explicit prefixes with repeated suffixes", function()
            local pad = keccak("pad")
            local prefix = make_leaves(3)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_append(forest, prefix)
            hash_tree.frontier_forest_pad_back(forest, pad, 6)
            hash_tree.frontier_forest_pad_back(forest, pad, 4) -- extends the same repetition
            local pad_count = forest.pending.pad_count
            hash_tree.frontier_forest_push_back(forest, pad) -- a matching push extends it too
            expect.equal(forest.pending.pad_count, pad_count + 1)
            hash_tree.frontier_forest_push_back(forest, prefix[1]) -- an incompatible push flushes it
            hash_tree.frontier_forest_pad_back(forest, prefix[2], 1) -- an incompatible pad
            local leaves = { prefix[1], prefix[2], prefix[3] }
            for i = 4, 14 do
                leaves[i] = pad
            end
            leaves[15], leaves[16] = prefix[1], prefix[2]
            expect_matches_reference(forest, leaves)
        end)

        it("appends opaque subtrees at their declared height", function()
            local roots = {}
            for i = 1, 4 do
                roots[i] = keccak("subtree-" .. i)
            end
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(forest, roots[1], 2)
            hash_tree.frontier_forest_append(forest, roots, 2, 4, 2)
            hash_tree.frontier_forest_pad_back(forest, roots[4], 1, 2)
            local frontier = hash_tree.frontier(H4, "keccak256")
            hash_tree.frontier_append(frontier, roots, 1, 5, 2)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), hash_tree.frontier_get_root_hash(frontier))
            expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 4, 2), roots[2])
            local node_hash, node_err = hash_tree.frontier_forest_get_node_hash(forest, 0, 1)
            expect.equal(node_hash, nil)
            expect.equal(node_err, "the node is below an opaque hash")
            expect.fail(function()
                hash_tree.frontier_forest_get_node_hash(forest, 1, 2)
            end, "not aligned")
            expect.fail(function()
                hash_tree.frontier_forest_get_siblings(forest, 1, 2)
            end, "not aligned")
            local into = { roots[1] }
            local siblings, err = hash_tree.frontier_forest_get_siblings(forest, 0, 0, into)
            expect.equal(siblings, nil)
            expect.equal(err, "the node is below an opaque hash")
            expect.equal(#into, 1)
            expect.equal(into[1], roots[1])
        end)

        it("retries node and sibling queries after expanding an opaque bundle", function()
            local bundle = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_pad_back(bundle, keccak("state"), 4)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_pad_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), 4, 2)
            local root = hash_tree.frontier_forest_get_root_hash(forest)
            local node_hash, node_err = hash_tree.frontier_forest_get_node_hash(forest, 13, 0)
            expect.equal(node_hash, nil)
            expect.equal(node_err, "the node is below an opaque hash")
            local siblings, err = hash_tree.frontier_forest_get_siblings(forest, 13, 0)
            expect.equal(siblings, nil)
            expect.equal(err, "the node is below an opaque hash")
            hash_tree.frontier_forest_expand_leaf(forest, 12, bundle)
            for _, position in ipairs({ 12, 13, 15, 0 }) do
                siblings, err = hash_tree.frontier_forest_get_siblings(forest, position, 0)
                expect.equal(err, nil)
                node_hash, node_err = hash_tree.frontier_forest_get_node_hash(forest, position, 0)
                expect.equal(node_hash, keccak("state"))
                expect.equal(node_err, nil)
                hash_tree.verify_slice({
                    target_address = position,
                    log2_target_size = 0,
                    target_hash = hash_tree.frontier_forest_get_node_hash(forest, position, 0),
                    log2_root_size = H4,
                    root_hash = root,
                    sibling_hashes = siblings,
                })
            end
            expect.equal(#hash_tree.frontier_forest_get_siblings(forest, 0, H4), 0)
            for _, position in ipairs({ -1, 1 << H4, 0.5, "0" }) do
                expect.fail(function()
                    hash_tree.frontier_forest_get_siblings(forest, position, 0)
                end, "invalid node position")
                expect.fail(function()
                    hash_tree.frontier_forest_get_node_hash(forest, position, 0)
                end, "invalid node position")
            end
            expect.fail(function()
                hash_tree.frontier_forest_get_node_hash(forest, 0, -1)
            end, "invalid node height")
            expect.fail(function()
                hash_tree.frontier_forest_get_node_hash(hash_tree.frontier_forest(H4, "keccak256"), 0, 0)
            end, "the forest is not full")
            expect.fail(function()
                hash_tree.frontier_forest_get_siblings(forest, 0, -1)
            end, "invalid node height")
            expect.fail(function()
                hash_tree.frontier_forest_get_siblings(hash_tree.frontier_forest(H4, "keccak256"), 0, 0)
            end, "the forest is not full")
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
                hash_tree.frontier_forest_append(forest, leaves, 0, 3)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 2, 6)
            end, "invalid range")
            expect.fail(function()
                hash_tree.frontier_forest_append(forest, leaves, 4, 3)
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
            hash_tree.frontier_forest_append(sub1, leaves, 1, 3)
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
                hash_tree.frontier_forest_append(forest, leaves, 1.5, 3)
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
            hash_tree.frontier_forest_pad_back(forest, pad)
            -- reference: fold the lone leaf against doubling all-pad subtrees
            local root, level_pad = first_leaf, pad
            for _ = 1, H62 do
                root = keccak(root, level_pad)
                level_pad = keccak(level_pad, level_pad)
            end
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
            expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 0, 0), first_leaf)
            expect.equal(hash_tree.frontier_forest_get_node_hash(forest, (1 << H62) - 1, 0), pad)
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

        it("expands opaque bundles without changing roots or coverage", function()
            local leaves = make_leaves(MAX4)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            local bundles = {}
            for i = 1, 4 do
                local bundle = hash_tree.frontier_forest(2, "keccak256")
                hash_tree.frontier_forest_append(bundle, leaves, 4 * i - 3, 4 * i + 1)
                bundles[i] = bundle
                hash_tree.frontier_forest_push_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), 2)
            end
            local root = hash_tree.frontier_forest_get_root_hash(forest)
            for _, i in ipairs({ 4, 1, 3, 2 }) do
                hash_tree.frontier_forest_expand_leaf(forest, (i - 1) * 4, bundles[i])
                expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
                expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), MAX4)
            end
            expect_matches_reference(forest, leaves)
        end)

        it("expands nested padding through mixed trees and implicit repetitions", function()
            local leaves = make_leaves(6)
            local bundle = hash_tree.frontier_forest(1, "keccak256")
            hash_tree.frontier_forest_append(bundle, leaves, 5, 7)
            local group = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_pad_back(group, hash_tree.frontier_forest_get_root_hash(bundle), 2, 1)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_append(forest, leaves, 1, 5)
            hash_tree.frontier_forest_pad_back(forest, group, 3)
            hash_tree.frontier_forest_expand_leaf(forest, 14, bundle)
            local expected = { leaves[1], leaves[2], leaves[3], leaves[4] }
            for i = 5, MAX4 do
                expected[i] = leaves[5 + ((i - 5) % 2)]
            end
            expect_matches_reference(forest, expected)
        end)

        it("expands a whole opaque root and accepts a wrapped completed subtree", function()
            local leaves = make_leaves(MAX4)
            local bundle = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_append(bundle, leaves)
            local wrapper = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(wrapper, bundle)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_push_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), H4)
            hash_tree.frontier_forest_expand_leaf(forest, 0, wrapper)
            expect_matches_reference(forest, leaves)
        end)

        it("expands a height-62 repeated forest without materializing repetitions", function()
            local leaves = make_leaves(2)
            local bundle = hash_tree.frontier_forest(1, "keccak256")
            hash_tree.frontier_forest_append(bundle, leaves)
            local forest = hash_tree.frontier_forest(62, "keccak256")
            hash_tree.frontier_forest_pad_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), 1 << 61, 1)
            local root = hash_tree.frontier_forest_get_root_hash(forest)
            hash_tree.frontier_forest_expand_leaf(forest, (1 << 62) - 2, bundle)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
            expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), 1 << 62)
            for _, position in ipairs({ 0, 1, (1 << 62) - 2, (1 << 62) - 1 }) do
                local target = leaves[(position % 2) + 1]
                expect.equal(hash_tree.frontier_forest_get_node_hash(forest, position, 0), target)
                hash_tree.verify_slice({
                    target_address = position,
                    log2_target_size = 0,
                    target_hash = target,
                    log2_root_size = 62,
                    root_hash = root,
                    sibling_hashes = hash_tree.frontier_forest_get_siblings(forest, position, 0),
                })
            end
        end)

        for _, stored in ipairs({ false, true }) do
            it("merges a retained proof with an expansion " .. (stored and "after storing" or "in memory"), function()
                local _ <close>, directory = new_scope_directory()
                local leaves = make_leaves(MAX4)
                local reference = hash_tree.frontier_forest(H4, "keccak256")
                hash_tree.frontier_forest_append(reference, leaves)
                local forest = hash_tree.frontier_forest({
                    target_address = MAX4 - 1,
                    log2_target_size = 0,
                    log2_root_size = H4,
                    target_hash = leaves[MAX4],
                    root_hash = hash_tree.frontier_forest_get_root_hash(reference),
                    sibling_hashes = hash_tree.frontier_forest_get_siblings(reference, MAX4 - 1, 0),
                }, "keccak256")
                local frontier_path = directory .. "/frontier.json"
                if stored then
                    hash_tree.frontier_forest_store(forest, directory, frontier_path)
                    forest = hash_tree.frontier_forest_load(directory, frontier_path)
                end
                local left = hash_tree.frontier_forest(H4, "keccak256")
                hash_tree.frontier_forest_append(left, leaves, 1, MAX4 // 2 + 1)
                hash_tree.frontier_forest_push_back(
                    left,
                    hash_tree.frontier_forest_get_node_hash(reference, MAX4 // 2, H4 - 1),
                    H4 - 1
                )
                hash_tree.frontier_forest_expand_leaf(forest, 0, left)
                if stored then
                    forest = hash_tree.frontier_forest_load(directory, frontier_path)
                end
                expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 0, 0), leaves[1])
                expect.equal(hash_tree.frontier_forest_get_node_hash(forest, MAX4 - 1, 0), leaves[MAX4])
                expect.equal(hash_tree.frontier_forest_get_node_hash(forest, MAX4 // 2, 0), nil)
                hash_tree.frontier_forest_expand_leaf(forest, 0, reference)
                if stored then
                    forest = hash_tree.frontier_forest_load(directory, frontier_path)
                end
                expect_matches_reference(forest, leaves)
            end)
        end

        it("rejects invalid expansions before mutation", function()
            local leaves = make_leaves(MAX4)
            local bundle = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_append(bundle, leaves, 1, 5)
            local bundle_root = hash_tree.frontier_forest_get_root_hash(bundle)
            local forest = hash_tree.frontier_forest(H4, "keccak256")
            hash_tree.frontier_forest_pad_back(forest, bundle_root, 4, 2)
            local root = hash_tree.frontier_forest_get_root_hash(forest)
            for _, position in ipairs({ -1, 1, 2.5, MAX4 }) do
                expect.fail(function()
                    hash_tree.frontier_forest_expand_leaf(forest, position, bundle)
                end)
            end
            local wrong_hash = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_append(wrong_hash, leaves, 5, 9)
            local wrong_height = hash_tree.frontier_forest(1, "keccak256")
            hash_tree.frontier_forest_append(wrong_height, leaves, 1, 3)
            local wrong_type = hash_tree.frontier_forest(2, "sha256")
            hash_tree.frontier_forest_append(wrong_type, leaves, 1, 5)
            local incomplete = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_push_back(incomplete, leaves[1])
            local opaque = hash_tree.frontier_forest(2, "keccak256")
            hash_tree.frontier_forest_push_back(opaque, bundle_root, 2)
            for _, replacement in ipairs({ wrong_hash, wrong_height, wrong_type, incomplete, opaque, bundle_root }) do
                expect.fail(function()
                    hash_tree.frontier_forest_expand_leaf(forest, 0, replacement)
                end)
                expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
                expect.equal(hash_tree.frontier_forest_get_leaf_count(forest), MAX4)
                local node_hash, err = hash_tree.frontier_forest_get_node_hash(forest, 0, 0)
                expect.equal(node_hash, nil)
                expect.equal(err, "the node is below an opaque hash")
            end
            expect.fail(function()
                hash_tree.frontier_forest_expand_leaf(incomplete, 0, bundle)
            end, "not full")
            expect.fail(function()
                hash_tree.frontier_forest_expand_leaf(opaque, 0, opaque)
            end, "replacement leaf is opaque")
            hash_tree.frontier_forest_expand_leaf(forest, 0, bundle)
            hash_tree.frontier_forest_expand_leaf(forest, 0, bundle)
            local expected = {}
            for i = 1, MAX4 do
                expected[i] = leaves[((i - 1) % 4) + 1]
            end
            expect_matches_reference(forest, expected)
        end)

        it("uses the hash function selected by the constructor", function()
            local leaves = { cartesi.sha256("left"), cartesi.sha256("right") }
            local forest = hash_tree.frontier_forest(1, "sha256")
            hash_tree.frontier_forest_append(forest, leaves)
            expect.equal(hash_tree.frontier_forest_get_root_hash(forest), cartesi.sha256(leaves[1], leaves[2]))
        end)

        describe("frontier_forest_store", function()
            local function tree_path(directory, hash)
                return directory .. "/" .. cartesi.tohex(hash) .. ".json"
            end

            -- Every node and sibling query, including opaque results, must agree between two full forests.
            local function expect_same_queries(a, b)
                expect.equal(hash_tree.frontier_forest_get_root_hash(a), hash_tree.frontier_forest_get_root_hash(b))
                for log2_size = 0, H4 do
                    for index = 0, (MAX4 >> log2_size) - 1 do
                        local position = index << log2_size
                        local a_hash, a_err = hash_tree.frontier_forest_get_node_hash(a, position, log2_size)
                        local b_hash, b_err = hash_tree.frontier_forest_get_node_hash(b, position, log2_size)
                        expect.equal(a_hash, b_hash)
                        expect.equal(a_err, b_err)
                        local a_siblings = hash_tree.frontier_forest_get_siblings(a, position, log2_size)
                        local b_siblings = hash_tree.frontier_forest_get_siblings(b, position, log2_size)
                        expect.equal(a_siblings == nil, b_siblings == nil)
                        for i = 1, #(a_siblings or {}) do
                            expect.equal(a_siblings[i], b_siblings[i])
                        end
                    end
                end
            end

            local leaves = make_leaves(MAX4)

            local function new_bundle(first)
                local bundle = hash_tree.frontier_forest(2, "keccak256")
                hash_tree.frontier_forest_append(bundle, leaves, first, first + 4)
                return bundle
            end

            -- Forests covering each tree shape: fixed-point leaves, a repeated suffix, completed
            -- forests as base values, opaque bundles, and opaque bundles expanded before storing.
            local fixtures = {
                leaves = function()
                    local forest = hash_tree.frontier_forest(H4, "keccak256")
                    hash_tree.frontier_forest_append(forest, leaves)
                    return forest
                end,
                repetition = function()
                    local forest = hash_tree.frontier_forest(H4, "keccak256")
                    hash_tree.frontier_forest_append(forest, leaves, 1, 6)
                    hash_tree.frontier_forest_pad_back(forest, leaves[6])
                    return forest
                end,
                forests = function()
                    local forest = hash_tree.frontier_forest(H4, "keccak256")
                    for i = 1, 3 do
                        hash_tree.frontier_forest_push_back(forest, new_bundle(4 * i - 3))
                    end
                    hash_tree.frontier_forest_pad_back(forest, new_bundle(13), 1)
                    return forest
                end,
                opaque = function()
                    local forest = hash_tree.frontier_forest(H4, "keccak256")
                    hash_tree.frontier_forest_append(forest, leaves, 1, 9)
                    for i = 3, 4 do
                        local root = hash_tree.frontier_forest_get_root_hash(new_bundle(4 * i - 3))
                        hash_tree.frontier_forest_push_back(forest, root, 2)
                    end
                    return forest
                end,
                expanded = function()
                    local forest = hash_tree.frontier_forest(H4, "keccak256")
                    for i = 1, 4 do
                        local root = hash_tree.frontier_forest_get_root_hash(new_bundle(4 * i - 3))
                        hash_tree.frontier_forest_push_back(forest, root, 2)
                    end
                    hash_tree.frontier_forest_expand_leaf(forest, 4, new_bundle(5))
                    hash_tree.frontier_forest_expand_leaf(forest, 12, new_bundle(13))
                    return forest
                end,
            }

            for _, name in ipairs({ "leaves", "repetition", "forests", "opaque", "expanded" }) do
                it("answers every query the same after a round trip of " .. name, function()
                    local _ <close>, directory = new_scope_directory()
                    local forest = fixtures[name]()
                    local frontier_path = directory .. "/frontier.json"
                    hash_tree.frontier_forest_store(forest, directory, frontier_path)
                    local loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                    expect_same_queries(fixtures[name](), loaded)
                    expect_same_queries(forest, loaded)
                end)
            end

            it("stores an expansion without rewriting its parent and loads it when reached", function()
                local _ <close>, directory = new_scope_directory()
                local frontier_path = directory .. "/frontier.json"
                hash_tree.frontier_forest_store(fixtures.opaque(), directory, frontier_path)
                local forest = hash_tree.frontier_forest_load(directory, frontier_path)
                local node_hash, err = hash_tree.frontier_forest_get_node_hash(forest, 12, 0)
                expect.equal(node_hash, nil)
                expect.equal(err, "the node is below an opaque hash")
                local before = {}
                for _, name in ipairs(fs.list_directory(directory)) do
                    before[name] = fs.read_file(directory .. "/" .. name)
                end
                local bundle = new_bundle(13)
                hash_tree.frontier_forest_expand_leaf(forest, 12, bundle)
                expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 12, 0), leaves[13])
                for name, contents in pairs(before) do
                    expect.equal(fs.read_file(directory .. "/" .. name), contents)
                end
                expect.truthy(io.open(tree_path(directory, hash_tree.frontier_forest_get_root_hash(bundle))))
                -- The unchanged frontier reopens the forest with the stored expansion.
                local reopened = hash_tree.frontier_forest_load(directory, frontier_path)
                expect_same_queries(forest, reopened)
                expect.equal(hash_tree.frontier_forest_get_node_hash(reopened, 15, 0), leaves[16])
            end)

            it("keeps a failed expansion uninstalled and allows retrying it", function()
                for _, operation in ipairs({ "write_durable_file", "sync_directory" }) do
                    local _ <close>, directory = new_scope_directory()
                    local frontier_path = directory .. "/frontier.json"
                    local forest = fixtures.opaque()
                    hash_tree.frontier_forest_store(forest, directory, frontier_path)
                    local root = hash_tree.frontier_forest_get_root_hash(forest)
                    local bundle = new_bundle(13)
                    local original = fs[operation]
                    fs[operation] = function()
                        error("injected expansion persistence failure")
                    end
                    local ok, err = pcall(hash_tree.frontier_forest_expand_leaf, forest, 12, bundle)
                    fs[operation] = original
                    expect.falsy(ok)
                    expect.truthy(err:find("injected expansion persistence failure", 1, true))
                    expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 12, 0), nil)
                    expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
                    hash_tree.frontier_forest_store(forest, directory, frontier_path)
                    local loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                    expect.equal(hash_tree.frontier_forest_get_node_hash(loaded, 12, 0), nil)
                    hash_tree.frontier_forest_expand_leaf(forest, 12, bundle)
                    expect.equal(hash_tree.frontier_forest_get_node_hash(forest, 12, 0), leaves[13])
                    expect.equal(hash_tree.frontier_forest_get_root_hash(forest), root)
                    loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                    expect_same_queries(forest, loaded)
                end
            end)

            it("flushes pending values and shares trees between snapshots of a growing forest", function()
                local _ <close>, directory = new_scope_directory()
                local forest = hash_tree.frontier_forest(H4, "keccak256")
                hash_tree.frontier_forest_append(forest, leaves, 1, 6)
                hash_tree.frontier_forest_store(forest, directory, directory .. "/first.json")
                local first = {}
                for _, name in ipairs(fs.list_directory(directory)) do
                    first[name] = fs.read_file(directory .. "/" .. name)
                end
                hash_tree.frontier_forest_append(forest, leaves, 6, 12)
                hash_tree.frontier_forest_store(forest, directory, directory .. "/second.json")
                for _, name in ipairs(fs.list_directory(directory)) do
                    expect.falsy(name:find(".tmp.", 1, true))
                end
                for name, contents in pairs(first) do
                    expect.equal(fs.read_file(directory .. "/" .. name), contents)
                end
                for _, snapshot in ipairs({ { "first.json", 6 }, { "second.json", 12 } }) do
                    local loaded = hash_tree.frontier_forest_load(directory, directory .. "/" .. snapshot[1])
                    expect.equal(hash_tree.frontier_forest_get_leaf_count(loaded), snapshot[2] - 1)
                    hash_tree.frontier_forest_append(loaded, leaves, snapshot[2])
                    expect_matches_reference(loaded, leaves)
                end
                hash_tree.frontier_forest_append(forest, leaves, 12)
                expect_matches_reference(forest, leaves)
                local _ <close>, other_directory = new_scope_directory()
                expect.fail(function()
                    hash_tree.frontier_forest_store(forest, other_directory, directory .. "/third.json")
                end, "stored in another directory")
            end)

            it("commits no file when writing a tree file fails", function()
                local _ <close>, directory = new_scope_directory()
                local frontier_path = directory .. "/frontier.json"
                local _ <close>, script = fs.write_scope_temp_file(string.format(
                    [[
                        local cartesi = require("cartesi")
                        local hash_tree = require("cartesi.hash-tree")
                        local forest = hash_tree.frontier_forest(9, "keccak256")
                        for k = 1, 512 do
                            hash_tree.frontier_forest_push_back(forest, cartesi.keccak256("output-" .. k))
                        end
                        hash_tree.frontier_forest_store(forest, %q, %q)
                    ]],
                    directory,
                    frontier_path
                ))
                -- Writes past 16 KiB fail with EFBIG, taking the same short-write path as a full disk.
                local child = assert(
                    io.popen(string.format("bash -c 'trap \"\" XFSZ; ulimit -f 16; exec %s %s' 2>&1", arg[-1], script))
                )
                local output = child:read("a")
                expect.falsy(child:close())
                expect.truthy(output:find("File too large", 1, true))
                expect.equal(#fs.list_directory(directory), 0)
                local forest = hash_tree.frontier_forest(9, "keccak256")
                hash_tree.frontier_forest_append(forest, make_leaves(512), 1)
                hash_tree.frontier_forest_store(forest, directory, frontier_path)
                local loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                expect.equal(
                    hash_tree.frontier_forest_get_root_hash(loaded),
                    hash_tree.frontier_forest_get_root_hash(forest)
                )
                expect.equal(hash_tree.frontier_forest_get_node_hash(loaded, 0, 0), leaf(1))
            end)

            it("keeps expansions of values that were flushed alone", function()
                local function new_tagged_bundle(tag)
                    local bundle = hash_tree.frontier_forest(2, "keccak256")
                    for i = 0, 3 do
                        hash_tree.frontier_forest_push_back(bundle, cartesi.keccak256(tag .. i))
                    end
                    return bundle
                end
                local function tagged_root(tag)
                    return hash_tree.frontier_forest_get_root_hash(new_tagged_bundle(tag))
                end
                -- Stores and reloads a forest, then queries a leaf below its expansion.
                local function expect_expansion_kept(forest, position, expected)
                    expect.equal(hash_tree.frontier_forest_get_node_hash(forest, position, 0), expected)
                    local siblings = hash_tree.frontier_forest_get_siblings(forest, position, 0)
                    local _ <close>, directory = new_scope_directory()
                    local frontier_path = directory .. "/frontier.json"
                    hash_tree.frontier_forest_store(forest, directory, frontier_path)
                    local loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                    expect.equal(hash_tree.frontier_forest_get_node_hash(loaded, position, 0), expected)
                    expect.equal(hash_tree.frontier_forest_get_siblings(loaded, position, 0), siblings)
                end
                -- A bundle root flushed alone by a height change, expanded before the first store.
                local function new_alone()
                    local alone = hash_tree.frontier_forest(3, "keccak256")
                    hash_tree.frontier_forest_push_back(alone, tagged_root("a"), 2)
                    hash_tree.frontier_forest_pad_back(alone, cartesi.keccak256("other"), 2, 1)
                    hash_tree.frontier_forest_expand_leaf(alone, 0, new_tagged_bundle("a"))
                    return alone
                end
                expect_expansion_kept(new_alone(), 1, cartesi.keccak256("a1"))
                -- The same expansion nested in a replacement that a stored forest stores on expansion.
                local alone = new_alone()
                local nested = hash_tree.frontier_forest(4, "keccak256")
                hash_tree.frontier_forest_pad_back(nested, hash_tree.frontier_forest_get_root_hash(alone), 2, 3)
                local _ <close>, directory = new_scope_directory()
                hash_tree.frontier_forest_store(nested, directory, directory .. "/frontier.json")
                hash_tree.frontier_forest_expand_leaf(nested, 0, alone)
                expect.equal(hash_tree.frontier_forest_get_node_hash(nested, 1, 0), cartesi.keccak256("a1"))
                local reloaded = hash_tree.frontier_forest_load(directory, directory .. "/frontier.json")
                expect.equal(hash_tree.frontier_forest_get_node_hash(reloaded, 1, 0), cartesi.keccak256("a1"))
                -- Input bundles followed by pad bundles, flushed as 4 + 1, with the lone pad bundle opened.
                local roots = { tagged_root("b1"), tagged_root("b2"), tagged_root("b3") }
                local claim = hash_tree.frontier_forest(5, "keccak256")
                hash_tree.frontier_forest_append(claim, roots, 1, 4, 2)
                hash_tree.frontier_forest_pad_back(claim, tagged_root("pad"), 2, 2)
                hash_tree.frontier_forest_append(claim, roots, 1, 4, 2)
                hash_tree.frontier_forest_pad_back(claim, tagged_root("pad"), nil, 2)
                hash_tree.frontier_forest_expand_leaf(claim, 16, new_tagged_bundle("pad"))
                expect_expansion_kept(claim, 17, cartesi.keccak256("pad1"))
            end)

            it("rejects stored and loaded forests as values", function()
                local _ <close>, directory = new_scope_directory()
                local frontier_path = directory .. "/inner.json"
                local stored = hash_tree.frontier_forest(3, "keccak256")
                hash_tree.frontier_forest_append(stored, leaves, 1, 3, 0)
                hash_tree.frontier_forest_pad_back(stored, leaves[3], nil, 1)
                local root = hash_tree.frontier_forest_get_root_hash(stored)
                hash_tree.frontier_forest_store(stored, directory, frontier_path)
                local loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                local _ <close>, other_directory = new_scope_directory()
                for _, value in ipairs({ stored, loaded }) do
                    local outer = hash_tree.frontier_forest(4, "keccak256")
                    expect.fail(function()
                        hash_tree.frontier_forest_push_back(outer, value)
                    end, "a stored or loaded forest cannot be a value")
                    expect.fail(function()
                        hash_tree.frontier_forest_pad_back(outer, value, 2)
                    end, "a stored or loaded forest cannot be a value")
                    for _, outer_directory in ipairs({ directory, other_directory }) do
                        local stored_outer = hash_tree.frontier_forest(4, "keccak256")
                        hash_tree.frontier_forest_store(stored_outer, outer_directory, outer_directory .. "/outer.json")
                        expect.fail(function()
                            hash_tree.frontier_forest_push_back(stored_outer, value)
                        end, "a stored or loaded forest cannot be a value")
                    end
                    hash_tree.frontier_forest_pad_back(outer, root, nil, 3)
                    expect.fail(function()
                        hash_tree.frontier_forest_expand_leaf(outer, 0, value)
                    end, "a stored or loaded forest cannot be a value")
                    expect.equal(hash_tree.frontier_forest_get_node_hash(outer, 0, 3), root)
                    expect.falsy(hash_tree.frontier_forest_get_node_hash(outer, 0, 0))
                end
            end)

            it("keeps what every tree stored under a hash knows below it", function()
                local a, b = leaves[1], leaves[2]
                -- The same height-2 subtree, as two opaque height-1 values or as four leaves.
                local function new_coarse(height)
                    local forest = hash_tree.frontier_forest(height, "keccak256")
                    hash_tree.frontier_forest_pad_back(forest, cartesi.keccak256(a, b), 2, 1)
                    return forest
                end
                local function append_fine(forest)
                    hash_tree.frontier_forest_append(forest, { a, b, a, b })
                    return forest
                end
                local function expect_leaves(forest, first)
                    for position = first, first + 3 do
                        expect.equal(
                            hash_tree.frontier_forest_get_node_hash(forest, position, 0),
                            position % 2 == 0 and a or b
                        )
                        expect.truthy(hash_tree.frontier_forest_get_siblings(forest, position, 0))
                    end
                end
                -- Two forests in one directory, stored in either order.
                for _, order in ipairs({ { "coarse", "fine" }, { "fine", "coarse" } }) do
                    local _ <close>, directory = new_scope_directory()
                    local forests =
                        { coarse = new_coarse(2), fine = append_fine(hash_tree.frontier_forest(2, "keccak256")) }
                    for _, name in ipairs(order) do
                        hash_tree.frontier_forest_store(forests[name], directory, directory .. "/" .. name .. ".json")
                    end
                    expect_leaves(hash_tree.frontier_forest_load(directory, directory .. "/fine.json"), 0)
                    expect_leaves(hash_tree.frontier_forest_load(directory, directory .. "/coarse.json"), 0)
                end
                -- One forest holding both representations side by side.
                local _ <close>, directory = new_scope_directory()
                local forest = append_fine(new_coarse(3))
                hash_tree.frontier_forest_store(forest, directory, directory .. "/frontier.json")
                local loaded = hash_tree.frontier_forest_load(directory, directory .. "/frontier.json")
                expect_leaves(loaded, 0)
                expect_leaves(loaded, 4)
            end)

            it("merges trees of any shape stored under a hash", function()
                local symbols = { cartesi.keccak256("x"), cartesi.keccak256("y") }
                local function new_fine(values, first, height)
                    local forest = hash_tree.frontier_forest(height, "keccak256")
                    hash_tree.frontier_forest_append(forest, values, first, first + (1 << height))
                    return forest
                end
                -- Splits the leaves into random aligned blocks, each raw, appended, padded, or opened.
                local function new_shaped(values, known)
                    local forest = hash_tree.frontier_forest(H4, "keccak256")
                    local opened = {}
                    local function add_block(first, height)
                        if height > 0 and math.random(3) == 1 then
                            add_block(first, height - 1)
                            add_block(first + (1 << (height - 1)), height - 1)
                            return
                        end
                        local mode = math.random(height > 0 and 5 or 4)
                        local count = 1 << height
                        if mode == 1 then
                            hash_tree.frontier_forest_push_back(forest, new_fine(values, first, height))
                        elseif mode == 4 then
                            -- Padding the trailing run of equal leaves makes it a repeated suffix.
                            local last = values[first + count - 1]
                            local run = 1
                            while run < count and values[first + count - 1 - run] == last do
                                run = run + 1
                            end
                            hash_tree.frontier_forest_append(forest, values, first, first + count - run)
                            hash_tree.frontier_forest_pad_back(forest, last, run)
                        elseif mode == 2 or mode == 5 then
                            hash_tree.frontier_forest_push_back(
                                forest,
                                hash_tree.frontier_forest_get_root_hash(new_fine(values, first, height)),
                                height
                            )
                            if mode == 5 then
                                opened[#opened + 1] = { first, height }
                            end
                        else
                            hash_tree.frontier_forest_append(forest, values, first, first + count)
                        end
                        if mode ~= 2 then
                            for position = first - 1, first + count - 2 do
                                known[position] = true
                            end
                        end
                    end
                    add_block(1, H4)
                    for _, block in ipairs(opened) do
                        hash_tree.frontier_forest_expand_leaf(
                            forest,
                            block[1] - 1,
                            new_fine(values, block[1], block[2])
                        )
                    end
                    return forest
                end
                math.randomseed(14)
                for _ = 1, 100 do
                    local values = {}
                    for i = 1, MAX4 do
                        values[i] = symbols[math.random(i > MAX4 // 2 and 1 or 2)]
                    end
                    local reference = new_fine(values, 1, H4)
                    local known = {}
                    local forests = {}
                    for i = 1, 3 do
                        forests[i] = new_shaped(values, known)
                    end
                    local _ <close>, directory = new_scope_directory()
                    for i = 3, 1, -1 do
                        local j = math.random(i)
                        forests[i], forests[j] = forests[j], forests[i]
                        hash_tree.frontier_forest_store(forests[i], directory, directory .. "/" .. i .. ".json")
                    end
                    for i = 1, 3 do
                        local loaded = hash_tree.frontier_forest_load(directory, directory .. "/" .. i .. ".json")
                        expect.equal(
                            hash_tree.frontier_forest_get_root_hash(loaded),
                            hash_tree.frontier_forest_get_root_hash(reference)
                        )
                        for position = 0, MAX4 - 1 do
                            local hash = hash_tree.frontier_forest_get_node_hash(loaded, position, 0)
                            if known[position] then
                                expect.equal(hash, values[position + 1])
                                expect.equal(
                                    hash_tree.frontier_forest_get_siblings(loaded, position, 0),
                                    hash_tree.frontier_forest_get_siblings(reference, position, 0)
                                )
                            else
                                expect.truthy(hash == nil or hash == values[position + 1])
                            end
                        end
                    end
                end
            end)

            it("rewrites the files an interrupted store left missing", function()
                local _ <close>, directory = new_scope_directory()
                local frontier_path = directory .. "/frontier.json"
                hash_tree.frontier_forest_store(fixtures.forests(), directory, frontier_path)
                -- A crash can make a parent's file durable without a child's. Storing the same
                -- forest again, as after a restart, must restore the child despite the parent's file.
                local bundle_path = tree_path(directory, hash_tree.frontier_forest_get_root_hash(new_bundle(1)))
                assert(os.remove(bundle_path))
                local forest = fixtures.forests()
                hash_tree.frontier_forest_store(forest, directory, frontier_path)
                expect.truthy(fs.exists(bundle_path))
                expect_same_queries(forest, hash_tree.frontier_forest_load(directory, frontier_path))
            end)

            it("rejects tampered, misplaced, and mismatched stored trees", function()
                local _ <close>, directory = new_scope_directory()
                local frontier_path = directory .. "/frontier.json"
                local forest = fixtures.forests()
                hash_tree.frontier_forest_store(forest, directory, frontier_path)
                local bundle_path = tree_path(directory, hash_tree.frontier_forest_get_root_hash(new_bundle(1)))
                local original = fs.read_file(bundle_path)
                local function expect_query_fails(message)
                    local loaded = hash_tree.frontier_forest_load(directory, frontier_path)
                    expect.fail(function()
                        hash_tree.frontier_forest_get_node_hash(loaded, 0, 0)
                    end, message)
                end
                fs.write_file(
                    (original:gsub(cartesi.tohex(leaves[1]):sub(3), cartesi.tohex(leaves[2]):sub(3))),
                    bundle_path
                )
                expect_query_fails("stored tree hash mismatch")
                fs.write_file(
                    fs.read_file(tree_path(directory, hash_tree.frontier_forest_get_root_hash(new_bundle(5)))),
                    bundle_path
                )
                expect_query_fails("stored tree hash mismatch")
                fs.write_file((original:gsub('"height":2', '"height":3')), bundle_path)
                expect_query_fails("stored tree height mismatch")
                fs.write_file(original, bundle_path)
                expect_same_queries(forest, hash_tree.frontier_forest_load(directory, frontier_path))
                -- A raw hash at another height must not open the tree stored under that hash.
                local other = hash_tree.frontier_forest(H4, "keccak256")
                hash_tree.frontier_forest_pad_back(other, hash_tree.frontier_forest_get_root_hash(new_bundle(1)), 8, 1)
                hash_tree.frontier_forest_store(other, directory, directory .. "/other.json")
                expect.fail(function()
                    hash_tree.frontier_forest_get_node_hash(other, 0, 0)
                end, "stored tree height mismatch")
                local frontier = fs.read_file(frontier_path)
                fs.write_file((frontier:gsub('"leaf_count":16', '"leaf_count":15')), frontier_path)
                expect.fail(function()
                    hash_tree.frontier_forest_load(directory, frontier_path)
                end, "does not match leaf count")
            end)
        end)
    end)

    describe("get_data_root_hash", function()
        it("hashes empty data as a pristine tree", function()
            local zero_word = string.rep("\0", 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE)
            for _, log2_root_size in ipairs({ cartesi.HASH_TREE_LOG2_WORD_SIZE, 12, 62 }) do
                expect.equal(
                    hash_tree.get_data_root_hash("", log2_root_size),
                    hash_tree.get_data_root_hash(zero_word, log2_root_size)
                )
            end
        end)

        it("rejects tree sizes outside the supported range", function()
            for _, log2_root_size in ipairs({ cartesi.HASH_TREE_LOG2_WORD_SIZE - 1, 63, 64 }) do
                expect.fail(function()
                    hash_tree.get_data_root_hash("data", log2_root_size)
                end, "invalid tree size")
            end
            expect.fail(function()
                local log2_root_size = cartesi.HASH_TREE_LOG2_WORD_SIZE
                hash_tree.get_data_root_hash(string.rep("\0", (1 << log2_root_size) + 1), log2_root_size)
            end, "data does not fit in the tree")
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

        it("rejects proofs whose shape does not match their sizes", function()
            local machine <close> = cartesi.machine({ ram = { length = 0x1000 } })
            local frontier_proof = hash_tree.frontier_next_proofs(hash_tree.frontier(H, "keccak256"), make_leaves(4))[3]
            local word_proof = machine:get_proof(cartesi.AR_RAM_START, 5)
            local cases = {
                {
                    word_proof,
                    "target address not aligned",
                    function(p)
                        p.target_address = p.target_address | 7
                    end,
                },
                {
                    frontier_proof,
                    "wrong number of siblings",
                    function(p)
                        p.sibling_hashes[#p.sibling_hashes + 1] = p.sibling_hashes[1]
                    end,
                },
                {
                    frontier_proof,
                    "invalid proof sizes",
                    function(p)
                        p.log2_target_size, p.target_hash, p.sibling_hashes = H + 1, p.root_hash, {}
                    end,
                },
            }
            for _, case in ipairs(cases) do
                local proof, expected_error, corrupt = table.unpack(case)
                hash_tree.verify_slice(proof)
                local corrupted = tabular.deep_copy(proof)
                corrupt(corrupted)
                expect.fail(function()
                    hash_tree.verify_slice(corrupted)
                end, expected_error)
            end
            -- Address bits above the root size locate the tree and take no part in verification
            local located = tabular.deep_copy(frontier_proof)
            located.target_address = located.target_address | (1 << H)
            hash_tree.verify_slice(located)
        end)
    end)
end)

lester.report()
lester.exit()
