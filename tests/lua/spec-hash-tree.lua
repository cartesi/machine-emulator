--[[
Test suite for hash trees.
Specifically, it provides test coverage for:
    hash-tree.cpp
    page-hash-tree-cache.h
Can be run independently during development the mentioned files.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local hash_tree = require("cartesi.hash-tree")
local tests_util = require("cartesi.tests.util")

local LOG2_ROOT_SIZE = 64
local LOG2_PAGE_SIZE = 12
local PAGE_SIZE = 1 << LOG2_PAGE_SIZE
local LOG2_WORD_SIZE = 5
local WORD_SIZE = 1 << LOG2_WORD_SIZE

local function bit_ceil(n)
    if n == 0 then
        return 0
    end
    n = n - 1
    n = n | (n >> 1)
    n = n | (n >> 2)
    n = n | (n >> 4)
    n = n | (n >> 8)
    n = n | (n >> 16)
    n = n | (n >> 32)
    return n + 1
end

local function get_sibling_address(address, log2_size)
    local bit = 1 << log2_size
    local mask = ~(bit - 1)
    return (address ~ bit) & mask
end

local function get_aligned_address(address, log2_size)
    local bit = 1 << log2_size
    local mask = ~(bit - 1)
    return address & mask
end

local function get_proof(m, target_address, log2_target_size)
    local proof = {
        log2_root_size = LOG2_ROOT_SIZE,
        log2_target_size = log2_target_size,
        root_hash = m:get_root_hash(),
        target_address = target_address,
        target_hash = m:get_node_hash(target_address, log2_target_size),
        sibling_hashes = {},
    }
    for log2_size = log2_target_size, 63 do
        table.insert(proof.sibling_hashes, m:get_node_hash(get_sibling_address(target_address, log2_size), log2_size))
    end
    return proof
end

local function expect_consistent_proof(proof, hash_fn)
    local hash = proof.target_hash
    for log2_size = proof.log2_target_size, proof.log2_root_size - 1 do
        local bit = 1 << log2_size
        local first, second
        local sibling_hash = proof.sibling_hashes[log2_size - proof.log2_target_size + 1]
        if (proof.target_address & bit) ~= 0 then
            first, second = sibling_hash, hash
        else
            first, second = hash, sibling_hash
        end
        hash = cartesi[hash_fn](first, second)
    end
    expect.equal(proof.root_hash, hash)
end

local function expect_consistent_root_hash(machine)
    expect.truthy(machine:verify_hash_tree())
    local root_hash = machine:get_root_hash()
    local external_root_hash = tests_util.calculate_emulator_hash(machine)
    expect.truthy(machine:verify_hash_tree())
    local node_hash = machine:get_node_hash(0, cartesi.HASH_TREE_LOG2_ROOT_SIZE)
    expect.truthy(root_hash == node_hash)
    expect.equal(root_hash, external_root_hash)
end

describe("hash tree", function()
    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        local pristine_hashes = { [LOG2_WORD_SIZE] = cartesi[hash_function](string.rep("\0", WORD_SIZE)) }
        for log2_size = LOG2_WORD_SIZE + 1, LOG2_ROOT_SIZE do
            local previous = pristine_hashes[log2_size - 1]
            pristine_hashes[log2_size] = cartesi[hash_function](previous, previous)
        end

        local function make_machine_config(o)
            return {
                hash_tree = {
                    hash_function = hash_function,
                    phtc_size = o and o.phtc_size,
                },
                ram = {
                    backing_store = {
                        data_filename = tests_util.tests_path .. "rv64ui-p-addi.bin",
                    },
                    length = 0x10000,
                },
                flash_drive = {
                    { start = 0x90000000, length = o and o.flash_drive_length or 0x20000 },
                    { start = 0xa0000000, length = 0x200000 },
                },
            }
        end

        local variants = {
            {
                name = "local",
                is_local = true,
                make_machine = function(o)
                    return cartesi.machine(make_machine_config(o))
                end,
            },
            {
                name = "remote",
                is_local = false,
                make_machine = function(o)
                    local jsonrpc = require("cartesi.jsonrpc")
                    return jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(make_machine_config(o))
                end,
            },
        }

        for _, variant in ipairs(variants) do
            describe(hash_function .. " (" .. variant.name .. ")", function()
                local function make_machine(o)
                    return variant.make_machine(o)
                end
                local machine <close> = make_machine()

                it("should return pristine word proofs for range padding", function()
                    local start = 0x90000000
                    for _, page_count in ipairs({ 3, 5 }) do
                        local length = page_count * PAGE_SIZE
                        local log2_span = page_count == 3 and 14 or 15
                        local data = string.rep("\x01", length)
                        local padded <close> = make_machine({ flash_drive_length = length, phtc_size = 1 })
                        padded:write_memory(cartesi.AR_RAM_START, string.rep("\xa5", PAGE_SIZE))
                        padded:write_memory(start, data)
                        local root_hash = padded:get_root_hash()
                        expect.equal(root_hash, tests_util.calculate_emulator_hash(padded))
                        local drive_hash = hash_tree.get_data_root_hash(data, log2_span, hash_function)
                        local real_proof = padded:get_proof(cartesi.AR_RAM_START, LOG2_WORD_SIZE)
                        expect.equal(real_proof.target_hash, cartesi[hash_function](string.rep("\xa5", WORD_SIZE)))
                        expect.equal(real_proof.root_hash, root_hash)
                        expect_consistent_proof(real_proof, hash_function)
                        for log2_size = LOG2_WORD_SIZE, LOG2_PAGE_SIZE - 1 do
                            for _, offset in ipairs({ length + 2 * WORD_SIZE, bit_ceil(length) - WORD_SIZE }) do
                                local address = get_aligned_address(start + offset, log2_size)
                                for _, log2_root in ipairs({
                                    log2_size,
                                    LOG2_PAGE_SIZE - 1,
                                    LOG2_PAGE_SIZE,
                                    log2_span,
                                    LOG2_ROOT_SIZE,
                                }) do
                                    -- Fill the only cache entry with non-pristine data before each proof.
                                    padded:get_node_hash(cartesi.AR_RAM_START, LOG2_WORD_SIZE)
                                    local proof = padded:get_proof(address, log2_size, log2_root)
                                    expect.equal(proof.target_hash, pristine_hashes[log2_size])
                                    local expected_root = log2_root <= LOG2_PAGE_SIZE and pristine_hashes[log2_root]
                                        or log2_root == log2_span and drive_hash
                                        or root_hash
                                    expect.equal(proof.root_hash, expected_root)
                                    expect_consistent_proof(proof, hash_function)
                                end
                            end
                        end
                        expect.equal(padded:get_root_hash(), root_hash)
                    end
                end)

                it("should return pristine sub-page node hashes for range padding", function()
                    local start = 0x90000000
                    for _, page_count in ipairs({ 3, 5 }) do
                        local length = page_count * PAGE_SIZE
                        local padded <close> = make_machine({ flash_drive_length = length, phtc_size = 1 })
                        local data = string.rep("\xa5", PAGE_SIZE)
                        padded:write_memory(cartesi.AR_RAM_START, data)
                        padded:write_memory(start, string.rep("\x01", length))
                        local root_hash = padded:get_root_hash()
                        for log2_size = LOG2_WORD_SIZE, LOG2_PAGE_SIZE - 1 do
                            for _, offset in ipairs({ length + 2 * WORD_SIZE, bit_ceil(length) - WORD_SIZE }) do
                                local address = get_aligned_address(start + offset, log2_size)
                                padded:get_node_hash(cartesi.AR_RAM_START, LOG2_WORD_SIZE)
                                expect.equal(padded:get_node_hash(address, log2_size), pristine_hashes[log2_size])
                            end
                        end
                        expect.equal(
                            padded:get_node_hash(cartesi.AR_RAM_START, LOG2_WORD_SIZE),
                            cartesi[hash_function](data:sub(1, WORD_SIZE))
                        )
                        expect.equal(padded:get_root_hash(), root_hash)
                    end
                end)

                it("should return pristine node hashes for range padding", function()
                    local start = 0x90000000
                    for _, page_count in ipairs({ 3, 5 }) do
                        local length = page_count * PAGE_SIZE
                        local padded <close> = make_machine({ flash_drive_length = length, phtc_size = 1 })
                        padded:write_memory(start, string.rep("\x01", length))
                        local root_hash = padded:get_root_hash()
                        expect.equal(root_hash, tests_util.calculate_emulator_hash(padded))
                        for log2_size = LOG2_PAGE_SIZE, 14 do
                            local size = 1 << log2_size
                            local first = get_aligned_address(start + length + size - 1, log2_size)
                            local pristine =
                                hash_tree.get_data_root_hash(string.rep("\0", WORD_SIZE), log2_size, hash_function)
                            for address = first, start + bit_ceil(length) - 1, size do
                                expect.equal(padded:get_node_hash(address, log2_size), pristine)
                                local proof = padded:get_proof(address, log2_size)
                                expect.equal(proof.target_hash, pristine)
                                expect.equal(proof.root_hash, root_hash)
                                expect_consistent_proof(proof, hash_function)
                            end
                        end
                        expect.equal(padded:get_root_hash(), root_hash)
                    end
                end)

                it("should log and verify a load beside range padding", function()
                    for _, page_count in ipairs({ 3, 5 }) do
                        local length = page_count * PAGE_SIZE
                        local reference <close> = make_machine({ flash_drive_length = length, phtc_size = 1 })
                        local logged <close> = make_machine({ flash_drive_length = length, phtc_size = 1 })
                        local address = 0x90000000 + length - PAGE_SIZE
                        for _, m in ipairs({ reference, logged }) do
                            -- ld t0,0(a0); jal zero,0
                            m:write_memory(cartesi.AR_RAM_START, string.pack("<I4I4", 0x00053283, 0x0000006f))
                            m:write_memory(address, string.pack("<I8", 42))
                            m:write_reg("pc", cartesi.AR_RAM_START)
                            m:write_reg("x10", address)
                        end
                        local initial_hash = logged:get_root_hash()
                        expect.equal(reference:get_root_hash(), initial_hash)
                        expect.equal(reference:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                        local final_hash = reference:get_root_hash()
                        local filename = filesystem.temp_pathname()
                        local _ <close> = tests_util.scope_exit(function()
                            os.remove(filename)
                        end)
                        expect.equal(logged:log_step(1, filename), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                        expect.equal(logged:read_reg("x5"), 42)
                        expect.equal(logged:get_root_hash(), final_hash)
                        expect.equal(logged:verify_step(initial_hash, filename, 1), final_hash)
                    end
                end)

                it("should have consistent root hash", function()
                    expect_consistent_root_hash(machine)
                    machine:run()
                    expect_consistent_root_hash(machine)
                    expect.equal(machine:get_root_hash(), machine:get_node_hash(0, LOG2_ROOT_SIZE))
                end)

                if variant.is_local then
                    it("should have consistent root hash when using different phct sizes", function()
                        for _, phtc_size in pairs({ 1, 2, 3, 4 }) do
                            local temp_machine <close> = make_machine({ phtc_size = phtc_size })
                            expect_consistent_root_hash(temp_machine)
                            temp_machine:run()
                            expect_consistent_root_hash(temp_machine)
                        end
                    end)
                end

                it("should fail on invalid API calls", function()
                    expect.fail(function()
                        machine:get_proof(0, LOG2_WORD_SIZE, LOG2_ROOT_SIZE + 1)
                    end, "log2_root_size is too large")
                    expect.fail(function()
                        machine:get_proof(0, LOG2_WORD_SIZE, LOG2_WORD_SIZE - 1)
                    end, "log2_root_size is too small")
                    expect.fail(function()
                        machine:get_proof(0, LOG2_ROOT_SIZE + 1)
                    end, "log2_target_size is larger than log2_root_size")
                    expect.fail(function()
                        machine:get_proof(0, LOG2_WORD_SIZE - 1)
                    end, "log2_target_size is too small")
                    expect.fail(function()
                        machine:get_proof(1, LOG2_ROOT_SIZE)
                    end, "address not aligned to log2_target_size")
                    expect.fail(function()
                        machine:get_proof(LOG2_WORD_SIZE + 1, LOG2_WORD_SIZE)
                    end, "address not aligned to log2_target_size")
                    expect.fail(function()
                        machine:get_node_hash(0, LOG2_ROOT_SIZE + 1)
                    end, "invalid log2_size")
                    expect.fail(function()
                        machine:get_node_hash(0, LOG2_WORD_SIZE - 1)
                    end, "invalid log2_size")
                    expect.fail(function()
                        machine:get_node_hash(1, LOG2_ROOT_SIZE)
                    end, "address not aligned to log2_size")
                    expect.fail(function()
                        machine:get_node_hash(LOG2_WORD_SIZE + 1, LOG2_WORD_SIZE)
                    end, "address not aligned to log2_size")
                    expect.fail(function()
                        cartesi.machine({
                            ram = { length = 0x1000 },
                            hash_tree = {
                                hash_function = hash_function,
                                phtc_size = 0,
                            },
                        })
                    end, "page hash-tree cache must have at least one entry")
                end)

                it("should retrieve hash tree stats", function()
                    local hash_tree_stats = machine:get_hash_tree_stats(true)
                    expect.equal(#hash_tree_stats.dense_node_hashes, 64)
                    expect.truthy(hash_tree_stats.sparse_node_hashes > 0)
                    expect.truthy(hash_tree_stats.phtc.inner_page_hashes > 0)
                    expect.truthy((hash_tree_stats.phtc.page_hits + hash_tree_stats.phtc.page_misses) > 0)
                    expect.truthy((hash_tree_stats.phtc.word_hits + hash_tree_stats.phtc.word_misses) > 0)
                    expect.truthy((hash_tree_stats.phtc.pristine_pages + hash_tree_stats.phtc.non_pristine_pages) > 0)
                    hash_tree_stats = machine:get_hash_tree_stats()
                    expect.equal(#hash_tree_stats.dense_node_hashes, 64)
                    expect.equal(hash_tree_stats.sparse_node_hashes, 0)
                    expect.equal(hash_tree_stats.phtc.inner_page_hashes, 0)
                    expect.equal((hash_tree_stats.phtc.page_hits + hash_tree_stats.phtc.page_misses), 0)
                    expect.equal((hash_tree_stats.phtc.word_hits + hash_tree_stats.phtc.word_misses), 0)
                    expect.equal((hash_tree_stats.phtc.pristine_pages + hash_tree_stats.phtc.non_pristine_pages), 0)
                end)

                if variant.is_local then
                    it("should have consistent page hashes", function()
                        for _, v in ipairs(machine:get_address_ranges()) do
                            for address = v.start, v.start + v.length - 1, PAGE_SIZE do
                                local node_hash = machine:get_node_hash(address, LOG2_PAGE_SIZE)
                                local external_node_hash = hash_tree.get_data_root_hash(
                                    machine:read_memory(address, PAGE_SIZE),
                                    LOG2_PAGE_SIZE,
                                    hash_function
                                )
                                expect.equal(node_hash, external_node_hash)
                            end
                        end
                    end)
                end

                local interesting_pages = {}
                do -- fill interesting pages
                    -- add first, middle, and last page of each range and gap
                    local last_end = 0
                    for _, v in ipairs(machine:get_address_ranges()) do
                        assert(not math.ult(v.start, last_end))
                        if last_end < v.start then
                            local gap = { start = last_end, length = v.start - last_end, description = "gap" }
                            local s = last_end
                            local e = v.start - PAGE_SIZE
                            local m = (((s + e) / 2) >> LOG2_PAGE_SIZE) << LOG2_PAGE_SIZE
                            table.insert(interesting_pages, { s, gap })
                            if not math.ult(s + PAGE_SIZE, m) then
                                table.insert(interesting_pages, { m, gap })
                            end
                            if not math.ult(m + PAGE_SIZE, e) then
                                table.insert(interesting_pages, { e, gap })
                            end
                        end
                        local s = v.start
                        local e = s + v.length - PAGE_SIZE
                        local m = (((s + e) / 2) >> LOG2_PAGE_SIZE) << LOG2_PAGE_SIZE
                        if m ~= s and not math.ult(s + PAGE_SIZE, m) then
                            table.insert(interesting_pages, { m, v })
                        end
                        if e ~= s and e ~= m and not math.ult(m + PAGE_SIZE, e) then
                            table.insert(interesting_pages, { e, v })
                        end
                        table.insert(interesting_pages, { s, v })
                        last_end = v.start + bit_ceil(v.length)
                    end
                    table.insert(
                        interesting_pages,
                        { last_end, { start = last_end, length = -last_end, description = "pad" } }
                    )
                    table.insert(
                        interesting_pages,
                        { -PAGE_SIZE, { start = last_end, length = -last_end, description = "pad" } }
                    )
                end

                if variant.is_local then
                    it("should have consistent hashes in the page hash tree for a few pages", function()
                        local clone_machine <close> = make_machine({ phtc_size = 1 })
                        clone_machine:run()
                        for _, p in ipairs(interesting_pages) do
                            local page = table.unpack(p)
                            local hashes = {}
                            for address = page, page + PAGE_SIZE - 1, WORD_SIZE do
                                local node_hash = machine:get_node_hash(address, LOG2_WORD_SIZE)
                                local clone_node_hash = clone_machine:get_node_hash(address, LOG2_WORD_SIZE)
                                local word = machine:read_memory(address, WORD_SIZE)
                                local external_node_hash = cartesi[hash_function](word)
                                expect.equal(node_hash, external_node_hash)
                                expect.equal(node_hash, clone_node_hash)
                                hashes[#hashes + 1] = external_node_hash
                            end
                            for log2_size = LOG2_WORD_SIZE + 1, LOG2_PAGE_SIZE do
                                local new_hashes = {}
                                for i = 1, #hashes - 1, 2 do
                                    new_hashes[#new_hashes + 1] = cartesi[hash_function](hashes[i], hashes[i + 1])
                                end
                                hashes = new_hashes
                                for i = 1, #hashes do
                                    local address = page + (i - 1) * (1 << log2_size)
                                    local node_hash = machine:get_node_hash(address, log2_size)
                                    local clone_node_hash = clone_machine:get_node_hash(address, log2_size)
                                    local external_node_hash = hashes[i]
                                    expect.equal(node_hash, external_node_hash)
                                    expect.equal(node_hash, clone_node_hash)
                                end
                            end
                        end
                    end)
                end

                it("should have consistent sliced proofs", function()
                    local word_index = 0
                    for _, p in ipairs(interesting_pages) do
                        local page, range = table.unpack(p)
                        local range_log2_size = math.ceil(math.log(bit_ceil(range.length), 2))
                        local interesting_sizes = {
                            LOG2_WORD_SIZE,
                            LOG2_WORD_SIZE + 1,
                            LOG2_PAGE_SIZE - 1,
                            LOG2_PAGE_SIZE,
                            LOG2_PAGE_SIZE + 1,
                            range_log2_size - 1,
                            range_log2_size,
                            range_log2_size + 1,
                            LOG2_ROOT_SIZE,
                        }
                        local address = get_aligned_address(page + (word_index * WORD_SIZE % PAGE_SIZE), LOG2_WORD_SIZE)
                        word_index = word_index + 17
                        local full_proof = machine:get_proof(address, LOG2_WORD_SIZE)
                        for _, log2_root_size in ipairs(interesting_sizes) do
                            for _, log2_target_size in ipairs(interesting_sizes) do
                                if
                                    log2_target_size >= LOG2_WORD_SIZE
                                    and log2_root_size > log2_target_size
                                    and log2_root_size <= LOG2_ROOT_SIZE
                                then
                                    local sproof = tests_util.slice_proof(
                                        full_proof,
                                        log2_root_size,
                                        log2_target_size,
                                        hash_function
                                    )
                                    expect_consistent_proof(sproof, hash_function)
                                    local aligned = get_aligned_address(address, log2_target_size)
                                    local mproof = machine:get_proof(aligned, log2_target_size, log2_root_size)
                                    expect.equal(sproof, mproof)
                                end
                            end
                        end
                    end
                end)

                if variant.is_local then
                    it("should have consistent proofs for all words (and up) in a few pages", function()
                        local clone_machine <close> = make_machine({ phtc_size = 1 })
                        clone_machine:run()
                        for log2_size = LOG2_WORD_SIZE, LOG2_ROOT_SIZE - 1 do
                            local size = 1 << log2_size
                            local last_address = -1
                            for _, p in ipairs(interesting_pages) do
                                local page = table.unpack(p)
                                local base = get_aligned_address(page, log2_size)
                                if math.ult(last_address, base) or last_address == -1 then
                                    if base ~= last_address then
                                        for address = base, base + size - 1, size do
                                            if address ~= last_address then
                                                local mproof = machine:get_proof(address, log2_size)
                                                local cproof = clone_machine:get_proof(address, log2_size)
                                                local oproof = get_proof(machine, address, log2_size)
                                                expect_consistent_proof(oproof, hash_function)
                                                expect_consistent_proof(mproof, hash_function)
                                                expect_consistent_proof(cproof, hash_function)
                                                expect.equal(mproof, oproof)
                                                expect.equal(mproof, cproof)
                                            end
                                            last_address = address
                                        end
                                    end
                                    last_address = get_aligned_address(base + size - 1, log2_size)
                                end
                            end
                        end
                    end)
                end
            end)
        end
    end
end)

lester.report()
lester.exit()
