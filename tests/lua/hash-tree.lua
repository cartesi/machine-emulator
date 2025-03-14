#!/usr/bin/env lua5.4

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
local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")
local tohex = test_util.tohex

local function stderr(...)
    io.stderr:write((string.format(...)))
end

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

local LOG2_ROOT_SIZE = 64
local LOG2_PAGE_SIZE = 12
local PAGE_SIZE = 1 << LOG2_PAGE_SIZE
local LOG2_WORD_SIZE = 5
local WORD_SIZE = 1 << LOG2_WORD_SIZE

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

local function compare_proofs(p1, p2, padding)
    padding = padding or ""
    if p1.target_address ~= p2.target_address then
        stderr("%starget address mismatch\n", padding)
        return false
    end
    if p1.log2_target_size ~= p2.log2_target_size then
        stderr("%slog2_size mismatch\n", padding)
        return false
    end
    if p1.root_hash ~= p2.root_hash then
        stderr("%sroot hash mismatch\n", padding)
        return false
    end
    if p1.target_hash ~= p2.target_hash then
        stderr("%starget hash mismatch\n", padding)
        return false
    end
    if #p1.sibling_hashes ~= #p2.sibling_hashes then
        stderr("%starget hash mismatch\n", padding)
        return false
    end
    for i = 1, #p1.sibling_hashes do
        if p1.sibling_hashes[i] ~= p2.sibling_hashes[i] then
            stderr("%ssibling hash mismatch (%d)\n", padding, i + p1.log2_target_size - 1)
            return false
        end
    end
    return true
end

local function check_proof(proof)
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
        hash = cartesi.keccak(first, second)
    end
    return hash == proof.root_hash
end

local config = {
    hash_tree = {
        phtc_size = 0x800, -- default
    },
    ram = {
        backing_store = {
            data_filename = test_util.tests_path .. "rv64ui-p-addi.bin",
        },
        length = 0x10000,
    },
    flash_drive = {
        { start = 0x90000000, length = 0x100000 },
        { start = 0xa0000000, length = 0x100000 },
    },
}

local function check_root_hash(m)
    local sh = test_util.calculate_emulator_hash(m)
    local rh = m:get_root_hash()
    local nh = m:get_node_hash(0, LOG2_ROOT_SIZE)
    if sh ~= nh or sh ~= rh then
        stderr("    0x%.16s state hash \n", tohex(sh))
        stderr("    0x%.16s root hash \n", tohex(rh))
        stderr("    0x%.16s node hash \n", tohex(nh))
        os.exit(1)
    end
end

local machine = cartesi.machine(config)
check_root_hash(machine)
machine:run(math.maxinteger)
check_root_hash(machine)

local interesting_pages = {}
-- add first, middle, and last page of each range and gap
local last_end = 0
for _, v in ipairs(machine:get_address_ranges()) do
    if math.ult(v.start, last_end) then
        stderr("range %s, when rounded up to power of two length, overlaps with previous range", v.description)
        os.exit(1)
    end
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
    if not math.ult(s + PAGE_SIZE, m) then
        table.insert(interesting_pages, { m, v })
    end
    if not math.ult(m + PAGE_SIZE, e) then
        table.insert(interesting_pages, { e, v })
    end
    table.insert(interesting_pages, { s, v })
    last_end = v.start + bit_ceil(v.length)
end
table.insert(interesting_pages, { last_end, { start = last_end, length = -last_end, description = "pad" } })
table.insert(interesting_pages, { -PAGE_SIZE, { start = last_end, length = -last_end, description = "pad" } })

-- check all page hashes
print("checking all page hashes")
for _, v in ipairs(machine:get_address_ranges()) do
    for address = v.start, v.start + v.length - 1, PAGE_SIZE do
        local h1 = machine:get_node_hash(address, LOG2_PAGE_SIZE)
        local h2 = test_util.merkle_hash(machine:read_memory(address, PAGE_SIZE), 0, LOG2_PAGE_SIZE)
        if h1 ~= h2 then
            stderr("hash mismatch on page 0x%016x (offset 0x%016x in %s)\n", address, address - v.start, v.description)
            stderr("    0x%.16s... vs 0x%.16s...\n", tohex(h1), tohex(h2))
            os.exit(1)
        end
    end
end

stderr("checking all hashes in the page hash tree for a few pages\n")
for _, p in ipairs(interesting_pages) do
    local page, v = table.unpack(p)
    stderr("    page 0x%016x is in %s 0x%016x:0x%x\n", page, v.description, v.start, v.length)
    local hashes = {}
    for address = page, page + PAGE_SIZE - 1, WORD_SIZE do
        local h1 = machine:get_node_hash(address, LOG2_WORD_SIZE)
        local word = machine:read_memory(address, WORD_SIZE)
        local h2 = cartesi.keccak(word)
        if h1 ~= h2 then
            stderr("        hash mismatch on word 0x%016x (%u)\n", address, address)
            stderr("            0x%.16s... vs 0x%.16s...\n", tohex(h1), tohex(h2))
            os.exit(1)
        end
        hashes[#hashes + 1] = h2
    end
    for log2_size = LOG2_WORD_SIZE + 1, LOG2_PAGE_SIZE do
        local new_hashes = {}
        for i = 1, #hashes - 1, 2 do
            new_hashes[#new_hashes + 1] = cartesi.keccak(hashes[i], hashes[i + 1])
        end
        hashes = new_hashes
        for i = 1, #hashes do
            local address = page + (i - 1) * (1 << log2_size)
            local h1 = machine:get_node_hash(address, log2_size)
            local h2 = hashes[i]
            if h1 ~= h2 then
                stderr("        hash mismatch on 0x%016x:%d\n", address, log2_size)
                stderr("            0x%.16s... vs 0x%.16s...\n", tohex(h1), tohex(h2))
                os.exit(1)
            end
        end
    end
end

stderr("checking proofs for all words (and up) in a few pages\n")
for log2_size = LOG2_WORD_SIZE, LOG2_ROOT_SIZE - 1 do
    stderr("  checking log2 size %u ---\n", log2_size)
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
                        local oproof = get_proof(machine, address, log2_size)
                        if not compare_proofs(mproof, oproof, "        ") then
                            stderr("    proof mismatch for offset 0x%016x (%u)\n", address, address)
                        end
                        if not check_proof(oproof) then
                            stderr("    test proof for offset 0x%016x (%u) failed\n", address, address)
                            os.exit(1)
                        end
                        if not check_proof(mproof) then
                            stderr("    machine proof for offset 0x%016x (%u) failed\n", address, address)
                            os.exit(1)
                        end
                    end
                    last_address = address
                end
            end
            last_address = get_aligned_address(base + size - 1, log2_size)
        end
    end
end

stderr("ok\n")
