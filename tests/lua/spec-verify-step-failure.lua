-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

--[[
Tests that verify_step correctly rejects corrupted binary step log files.
This exercises the validation error paths in replay-step-state-access.h
(the constructor that parses the binary log format).
]]

local cartesi = require("cartesi")
local lester = require("cartesi.third-party.lester")
local test_util = require("cartesi.tests.util")

local describe, it, expect = lester.describe, lester.it, lester.expect

local HASH_SIZE = cartesi.HASH_SIZE -- 32
local LOG2_PAGE_SIZE = 12
local PAGE_SIZE = 1 << LOG2_PAGE_SIZE -- 4096
local LOG2_ROOT_SIZE = 64
local PAGE_ENTRY_SIZE = 8 + PAGE_SIZE + HASH_SIZE -- page_index + data + scratch_hash

-- Field offsets in the binary step log
local OFFSET_ROOT_HASH_BEFORE = 0
local OFFSET_MCYCLE_COUNT = OFFSET_ROOT_HASH_BEFORE + HASH_SIZE -- 32
local OFFSET_ROOT_HASH_AFTER = OFFSET_MCYCLE_COUNT + 8 -- 40
local OFFSET_HASH_FUNCTION = OFFSET_ROOT_HASH_AFTER + HASH_SIZE -- 72
local OFFSET_PAGE_COUNT = OFFSET_HASH_FUNCTION + 8 -- 80
local OFFSET_FIRST_PAGE = OFFSET_PAGE_COUNT + 8 -- 88

-- Produce a valid step log and return (root_hash_before, mcycle_count, root_hash_after, log_data)
local function produce_valid_step_log()
    local machine <close> = cartesi.machine({
        ram = { length = 0x20000 },
    }, {})
    local root_hash_before = machine:get_root_hash()
    local log_filename = os.tmpname()
    os.remove(log_filename) -- log_step requires the file not to exist
    local mcycle_count = 1
    machine:log_step(mcycle_count, log_filename)
    local root_hash_after = machine:get_root_hash()
    -- Read the binary log file
    local f <close> = assert(io.open(log_filename, "rb"))
    local log_data = f:read("a")
    os.remove(log_filename)
    return root_hash_before, mcycle_count, root_hash_after, log_data
end

-- Write log_data to a temp file, call verify_step, clean up
local function verify_step_with_data(root_hash_before, mcycle_count, root_hash_after, log_data)
    local log_filename = os.tmpname()
    local f <close> = assert(io.open(log_filename, "wb"))
    f:write(log_data)
    f:close()
    local ok, err = pcall(function()
        cartesi.machine:verify_step(root_hash_before, log_filename, mcycle_count, root_hash_after)
    end)
    os.remove(log_filename)
    return ok, err
end

-- Helper: produce a valid log, corrupt it, verify it fails with expected error
local function should_fail(expected_error, corrupt)
    local root_hash_before, mcycle_count, root_hash_after, log_data = produce_valid_step_log()
    local corrupted = corrupt(log_data, root_hash_before, mcycle_count, root_hash_after)
    if type(corrupted) == "table" then
        -- corrupt() returned {log_data, root_hash_before, mcycle_count, root_hash_after}
        log_data = corrupted[1]
        root_hash_before = corrupted[2]
        mcycle_count = corrupted[3]
        root_hash_after = corrupted[4]
    else
        log_data = corrupted
    end
    local ok, err = verify_step_with_data(root_hash_before, mcycle_count, root_hash_after, log_data)
    expect.falsy(ok)
    expect.truthy(err and err:find(expected_error, 1, true), err)
end

-- Helper: verify the happy path works
local function should_succeed()
    local root_hash_before, mcycle_count, root_hash_after, log_data = produce_valid_step_log()
    local ok, err = verify_step_with_data(root_hash_before, mcycle_count, root_hash_after, log_data)
    expect.truthy(ok, err)
end

-- Replace bytes at a given offset in a string
local function replace_at(data, offset, replacement)
    return data:sub(1, offset) .. replacement .. data:sub(offset + #replacement + 1)
end

-- Compute sibling hashes for a given subset of page indices using the machine's
-- hash tree. This implements the same tree walk as compute_root_hash_impl in
-- replay-step-state-access.h, but uses get_node_hash for subtrees that contain
-- no selected pages instead of consuming from a sibling array.
local function get_siblings_for_pages(machine, page_indices)
    table.sort(page_indices)
    local log2_page_count = LOG2_ROOT_SIZE - LOG2_PAGE_SIZE
    local siblings = {}
    local next_page = 1

    local function walk(first_page_index, lpc)
        local range_size = 1 << lpc
        -- Check if any selected pages fall in this range
        local has_page = next_page <= #page_indices
            and page_indices[next_page] >= first_page_index
            and page_indices[next_page] < first_page_index + range_size
        if not has_page then
            -- No pages in range: get the subtree hash from the machine
            local addr = first_page_index << LOG2_PAGE_SIZE
            local log2_size = lpc + LOG2_PAGE_SIZE
            table.insert(siblings, machine:get_node_hash(addr, log2_size))
            return
        end
        if lpc > 0 then
            walk(first_page_index, lpc - 1)
            walk(first_page_index + (range_size >> 1), lpc - 1)
        else
            -- Leaf: this page is present, skip it
            next_page = next_page + 1
        end
    end

    walk(0, log2_page_count)
    return siblings
end

-- Build a binary step log from components
local function build_step_log(root_hash_before, mcycle_count, root_hash_after, hash_function, pages, siblings)
    local parts = {
        root_hash_before,
        string.pack("<I8", mcycle_count),
        root_hash_after,
        string.pack("<I8", hash_function),
        string.pack("<I8", #pages),
    }
    for _, page in ipairs(pages) do
        parts[#parts + 1] = string.pack("<I8", page.index)
        parts[#parts + 1] = page.data
        parts[#parts + 1] = string.rep("\0", HASH_SIZE) -- scratch hash area
    end
    parts[#parts + 1] = string.pack("<I8", #siblings)
    for _, s in ipairs(siblings) do
        parts[#parts + 1] = s
    end
    return table.concat(parts)
end

-- Parse pages from a binary step log
local function parse_pages(log_data)
    local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
    local pages = {}
    for i = 0, page_count - 1 do
        local entry_offset = OFFSET_FIRST_PAGE + i * PAGE_ENTRY_SIZE
        local index = string.unpack("<I8", log_data, entry_offset + 1)
        local data = log_data:sub(entry_offset + 8 + 1, entry_offset + 8 + PAGE_SIZE)
        pages[#pages + 1] = { index = index, data = data }
    end
    return pages
end

--------------------------------------------------------------------------------

describe("verify_step", function()
    describe("happy path", function()
        it("should accept a valid step log", function()
            should_succeed()
        end)
    end)

    describe("constructor: truncation errors", function()
        it("should reject empty log", function()
            -- An empty file (0 bytes) fails at mmap level before the constructor runs.
            -- A file with just a few bytes reaches the constructor's first check.
            should_fail("root hash before past end of step log", function()
                return string.rep("\0", 4) -- too short for root_hash_before
            end)
        end)

        it("should reject log truncated before mcycle_count", function()
            should_fail("mcycle count past end of step log", function(log_data)
                return log_data:sub(1, OFFSET_MCYCLE_COUNT)
            end)
        end)

        it("should reject log truncated before root_hash_after", function()
            should_fail("root hash after past end of step log", function(log_data)
                return log_data:sub(1, OFFSET_ROOT_HASH_AFTER)
            end)
        end)

        it("should reject log truncated before hash_function", function()
            should_fail("hash function type past end of step log", function(log_data)
                return log_data:sub(1, OFFSET_HASH_FUNCTION)
            end)
        end)

        it("should reject log truncated before page_count", function()
            should_fail("page count past end of step log", function(log_data)
                return log_data:sub(1, OFFSET_PAGE_COUNT)
            end)
        end)

        it("should reject log truncated in the middle of page data", function()
            -- Truncate one byte into the first page entry
            should_fail("page data past end of step log", function(log_data)
                return log_data:sub(1, OFFSET_FIRST_PAGE + 1)
            end)
        end)

        it("should reject log truncated before sibling_count", function()
            -- Parse page_count to find where sibling_count should be
            should_fail("sibling count past end of step log", function(log_data)
                local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
                local sibling_count_offset = OFFSET_FIRST_PAGE + PAGE_ENTRY_SIZE * page_count
                return log_data:sub(1, sibling_count_offset)
            end)
        end)

        it("should reject log truncated in the middle of sibling hashes", function()
            should_fail("sibling hashes past end of step log", function(log_data)
                local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
                local sibling_count_offset = OFFSET_FIRST_PAGE + PAGE_ENTRY_SIZE * page_count
                local sibling_count = string.unpack("<I8", log_data, sibling_count_offset + 1)
                assert(sibling_count > 0, "test requires at least one sibling hash")
                -- Keep only the sibling_count field but truncate the sibling hashes
                return log_data:sub(1, sibling_count_offset + 8 + 1)
            end)
        end)
    end)

    describe("constructor: format validation errors", function()
        it("should reject unsupported hash function type", function()
            should_fail("unsupported hash function type", function(log_data)
                -- Replace hash_function field (at offset 72) with an invalid value (0xFF)
                local bad_hash_fn = string.pack("<I8", 0xFF)
                return replace_at(log_data, OFFSET_HASH_FUNCTION, bad_hash_fn)
            end)
        end)

        it("should reject page count of zero", function()
            -- Build a log with page_count = 0. We need to also adjust the file
            -- size to match (remove all page data and sibling hashes).
            should_fail("page count is zero", function(log_data)
                -- header (88 bytes) with page_count = 0, then sibling_count = 0
                local header = log_data:sub(1, OFFSET_PAGE_COUNT)
                    .. string.pack("<I8", 0) -- page_count = 0
                    .. string.pack("<I8", 0) -- sibling_count = 0
                return header
            end)
        end)

        it("should reject extra data at end of step log", function()
            should_fail("extra data at end of step log", function(log_data)
                return log_data .. "\0"
            end)
        end)

        it("should reject page index not in increasing order", function()
            should_fail("page index is not in increasing order", function(log_data)
                local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
                if page_count < 2 then
                    error("test requires at least 2 pages")
                end
                -- Swap the page indices of the first two pages
                -- (make the first page index larger than the second)
                local idx1_offset = OFFSET_FIRST_PAGE
                local idx2_offset = OFFSET_FIRST_PAGE + PAGE_ENTRY_SIZE
                local idx1 = string.unpack("<I8", log_data, idx1_offset + 1)
                local idx2 = string.unpack("<I8", log_data, idx2_offset + 1)
                -- Set both to the same value (not increasing)
                local corrupted = replace_at(log_data, idx1_offset, string.pack("<I8", idx2))
                corrupted = replace_at(corrupted, idx2_offset, string.pack("<I8", idx1))
                return corrupted
            end)
        end)

        it("should reject page scratch hash area that is not zero", function()
            should_fail("page scratch hash area is not zero", function(log_data)
                -- The scratch hash is at offset 8 + PAGE_SIZE within each page entry
                local scratch_offset = OFFSET_FIRST_PAGE + 8 + PAGE_SIZE
                return replace_at(log_data, scratch_offset, string.rep("\xff", HASH_SIZE))
            end)
        end)

        it("should reject initial root hash mismatch", function()
            should_fail("initial root hash mismatch", function(log_data)
                -- Corrupt a byte in the first page's data so the computed hash won't match
                local data_offset = OFFSET_FIRST_PAGE + 8 -- skip page_index
                local byte_val = log_data:byte(data_offset + 1)
                local new_byte = string.char((byte_val + 1) % 256)
                return replace_at(log_data, data_offset, new_byte)
            end)
        end)
    end)

    describe("finish: final root hash", function()
        it("should reject final root hash mismatch", function()
            -- Pass a wrong root_hash_after to verify_step
            local bad_hash = string.rep("\xba", HASH_SIZE)
            local root_hash_before, mcycle_count, _, log_data = produce_valid_step_log()
            local ok, err = verify_step_with_data(root_hash_before, mcycle_count, bad_hash, log_data)
            expect.falsy(ok)
            -- The error could be "root hash after mismatch" (from machine::verify_step)
            -- or "final root hash mismatch" (from replay_step_state_access::finish)
            expect.truthy(err and (err:find("root hash", 1, true) or err:find("hash", 1, true)), err)
        end)
    end)

    describe("verify_step wrapper: argument validation", function()
        it("should reject root hash before mismatch with log header", function()
            local bad_hash = string.rep("\xba", HASH_SIZE)
            local _, mcycle_count, root_hash_after, log_data = produce_valid_step_log()
            local ok, err = verify_step_with_data(bad_hash, mcycle_count, root_hash_after, log_data)
            expect.falsy(ok)
            expect.truthy(err and err:find("root hash before mismatch", 1, true), err)
        end)

        it("should reject mcycle count mismatch with log header", function()
            local root_hash_before, mcycle_count, root_hash_after, log_data = produce_valid_step_log()
            local ok, err = verify_step_with_data(root_hash_before, mcycle_count + 1, root_hash_after, log_data)
            expect.falsy(ok)
            expect.truthy(err and err:find("mcycle count mismatch", 1, true), err)
        end)
    end)

    describe("interpret: adversarial log with missing page", function()
        -- An adversary can produce a log that has a valid Merkle tree (pages +
        -- siblings hash to the agreed root) while omitting a page the interpreter
        -- needs. The constructor passes but find_page fails during interpret().
        -- We craft such a log by using get_node_hash to build a different tree
        -- cut that excludes one required page.
        it("should reject log with a required page omitted", function()
            -- Create two identical machines: one to produce the valid log,
            -- one to stay in the initial state for get_node_hash queries.
            local config = { ram = { length = 0x20000 } }
            local log_machine <close> = cartesi.machine(config, {})
            local root_hash_before = log_machine:get_root_hash()

            -- Produce a valid step log to learn which pages are needed
            local log_filename = os.tmpname()
            os.remove(log_filename)
            local mcycle_count = 1
            log_machine:log_step(mcycle_count, log_filename)
            local root_hash_after = log_machine:get_root_hash()

            local f <close> = assert(io.open(log_filename, "rb"))
            local log_data = f:read("a")
            f:close()
            os.remove(log_filename)

            -- Parse pages from the valid log
            local pages = parse_pages(log_data)
            assert(#pages >= 2, "test requires at least 2 pages")

            -- Remove the last page -- the interpreter will still need it
            local reduced_pages = {}
            for i = 1, #pages - 1 do
                reduced_pages[i] = pages[i]
            end

            -- Collect page indices for the reduced set
            local reduced_indices = {}
            for i, p in ipairs(reduced_pages) do
                reduced_indices[i] = p.index
            end

            -- Use a fresh machine (still in initial state) to compute siblings
            local fresh_machine <close> = cartesi.machine(config, {})
            local siblings = get_siblings_for_pages(fresh_machine, reduced_indices)

            -- Read hash_function from the original log
            local hash_function = string.unpack("<I8", log_data, OFFSET_HASH_FUNCTION + 1)

            -- Build the adversarial log
            local adversarial_log =
                build_step_log(root_hash_before, mcycle_count, root_hash_after, hash_function, reduced_pages, siblings)

            -- verify_step should pass the constructor (initial hash matches)
            -- but fail during interpret() when it accesses the missing page
            local ok, err = verify_step_with_data(root_hash_before, mcycle_count, root_hash_after, adversarial_log)
            expect.falsy(ok)
            expect.truthy(err and err:find("required page not found", 1, true), err)
        end)
    end)

    describe("interpret: corrupted PMA data", function()
        it("should reject log with invalid PMA entries", function()
            -- Craft a log where the PMA page has garbage istart/ilength.
            -- The Merkle tree is self-consistent (root hash matches the
            -- corrupted data), but make_mock_address_range rejects the values.
            local config = { ram = { length = 0x20000 } }
            local log_machine <close> = cartesi.machine(config, {})

            local log_filename = os.tmpname()
            os.remove(log_filename)
            local mcycle_count = 1
            log_machine:log_step(mcycle_count, log_filename)
            local root_hash_after = log_machine:get_root_hash()

            local f <close> = assert(io.open(log_filename, "rb"))
            local log_data = f:read("a")
            f:close()
            os.remove(log_filename)

            local pages = parse_pages(log_data)
            local hash_function = string.unpack("<I8", log_data, OFFSET_HASH_FUNCTION + 1)
            local hash_fn = hash_function == 0 and "keccak256" or "sha256"

            -- Find the PMA page (address 0x10000 = page index 16)
            local pma_page_index = cartesi.AR_PMAS_START >> LOG2_PAGE_SIZE
            local pma_page_pos = nil
            for i, p in ipairs(pages) do
                if p.index == pma_page_index then
                    pma_page_pos = i
                    break
                end
            end
            assert(pma_page_pos, "PMA page not found in log")

            -- Corrupt the PMA page: fill with 0xFF so istart/ilength are garbage
            pages[pma_page_pos].data = string.rep("\xff", PAGE_SIZE)

            -- Compute the new root hash by walking up from the corrupted page.
            -- Get the proof path from the real machine (siblings at each level).
            local fresh_machine <close> = cartesi.machine(config, {})
            local pma_page_addr = pma_page_index << LOG2_PAGE_SIZE
            -- Start with the Merkle tree hash of the corrupted page data
            local node_hash = test_util.merkle_hash(pages[pma_page_pos].data, 0, LOG2_PAGE_SIZE, hash_fn)
            -- Walk up from page level to root, combining with sibling hashes
            for log2_size = LOG2_PAGE_SIZE, LOG2_ROOT_SIZE - 1 do
                local bit = 1 << log2_size
                local sibling_addr = (pma_page_addr ~ bit) & ~(bit - 1)
                local sibling_hash = fresh_machine:get_node_hash(sibling_addr, log2_size)
                if (pma_page_addr & bit) ~= 0 then
                    node_hash = cartesi[hash_fn](sibling_hash, node_hash)
                else
                    node_hash = cartesi[hash_fn](node_hash, sibling_hash)
                end
            end
            local new_root_hash = node_hash

            -- Build the log with the corrupted page and the new root hash
            local page_indices = {}
            for i, p in ipairs(pages) do
                page_indices[i] = p.index
            end
            local siblings = get_siblings_for_pages(fresh_machine, page_indices)
            local adversarial_log =
                build_step_log(new_root_hash, mcycle_count, root_hash_after, hash_function, pages, siblings)

            local ok, err = verify_step_with_data(new_root_hash, mcycle_count, root_hash_after, adversarial_log)
            expect.falsy(ok)
            -- The abrt lambda (L463) is invoked through ABRTF in the
            -- address_range constructor, called from make_mock_address_range
            expect.truthy(err and err:find("when initializing", 1, true), err)
        end)
    end)

    describe("compute_root_hash: page/sibling count errors", function()
        it("should reject too many pages in log", function()
            -- Add an extra page with index >= 2^52 (beyond the tree's page index
            -- range). The tree walk never reaches it, so next_page < page_count.
            should_fail("too many pages in log", function(log_data)
                local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
                local sibling_count_offset = OFFSET_FIRST_PAGE + PAGE_ENTRY_SIZE * page_count

                -- Build a fake page entry: index beyond tree range, zero data, zero scratch
                local oob_index = 1 << 52 -- beyond the 2^52 page index range
                local extra_page = string.pack("<I8", oob_index)
                    .. string.rep("\0", PAGE_SIZE)
                    .. string.rep("\0", HASH_SIZE)

                -- Insert the extra page before sibling_count, update page_count
                local result = replace_at(log_data, OFFSET_PAGE_COUNT, string.pack("<I8", page_count + 1))
                result = result:sub(1, sibling_count_offset) .. extra_page .. result:sub(sibling_count_offset + 1)
                return result
            end)
        end)

        it("should reject too few sibling hashes (internal level)", function()
            should_fail("too few sibling hashes in log", function(log_data)
                local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
                local sibling_count_offset = OFFSET_FIRST_PAGE + PAGE_ENTRY_SIZE * page_count
                local sibling_count = string.unpack("<I8", log_data, sibling_count_offset + 1)
                assert(sibling_count > 0, "test requires at least one sibling hash")
                -- Set sibling_count to 0 and remove all sibling hashes
                local truncated = log_data:sub(1, sibling_count_offset) .. string.pack("<I8", 0)
                return truncated
            end)
        end)

        it("should reject too few sibling hashes (leaf level)", function()
            -- Pages at indices [0, 3] with 0 siblings. The tree walk recurses
            -- down to leaf 0 (consumed), then leaf 1: page[next].index=3 != 1,
            -- so it needs a sibling at the LEAF level (L374), not an internal
            -- level (L358).
            local dummy_hash = string.rep("\0", HASH_SIZE)
            local dummy_page_data = string.rep("\0", PAGE_SIZE)
            local pages = {
                { index = 0, data = dummy_page_data },
                { index = 3, data = dummy_page_data },
            }
            local log_data = build_step_log(dummy_hash, 1, dummy_hash, 0, pages, {})
            local ok, err = verify_step_with_data(dummy_hash, 1, dummy_hash, log_data)
            expect.falsy(ok)
            expect.truthy(err and err:find("too few sibling hashes in log", 1, true), err)
        end)

        it("should reject too many sibling hashes", function()
            should_fail("too many sibling hashes in log", function(log_data)
                local page_count = string.unpack("<I8", log_data, OFFSET_PAGE_COUNT + 1)
                local sibling_count_offset = OFFSET_FIRST_PAGE + PAGE_ENTRY_SIZE * page_count
                local sibling_count = string.unpack("<I8", log_data, sibling_count_offset + 1)
                -- Add one extra sibling hash and increase the count
                local new_count = string.pack("<I8", sibling_count + 1)
                local result = log_data:sub(1, sibling_count_offset)
                    .. new_count
                    .. log_data:sub(sibling_count_offset + 8 + 1)
                    .. string.rep("\0", HASH_SIZE) -- extra sibling hash
                return result
            end)
        end)
    end)
end)
