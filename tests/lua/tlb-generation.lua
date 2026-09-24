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

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")
local ram = cartesi.AR_RAM_START
local data = ram + 0x4000
local generation_regs = { "tlb_generation_code", "tlb_generation_read", "tlb_generation_write" }
local instructions = {
    0x0020b023, -- sd x2,0(x1)
    0x0000b183, -- ld x3,0(x1)
    0x12000073, -- sfence.vma
    0x0000b183, -- ld x3,0(x1)
    0x30021073, -- csrrw x0,mstatus,x4
    0x0020b023, -- sd x2,0(x1)
    0x12008073, -- sfence.vma x1,x0
    0x18029073, -- csrrw x0,satp,x5
    0x0000b183, -- ld x3,0(x1)
}

local function new_machine(generation, hash_function)
    local m = cartesi.machine({
        ram = { length = 1 << 20 },
        hash_tree = { hash_function = hash_function },
    })
    local code = {}
    for _, insn in ipairs(instructions) do
        code[#code + 1] = string.pack("<I4", insn)
    end
    m:write_memory(ram, table.concat(code))
    m:write_reg("x1", data)
    m:write_reg("x2", 42)
    m:write_reg("x4", m:read_reg("mstatus") | (1 << 19) | (1 << 18))
    m:write_reg("x5", (8 << 60) | 0x80000)
    for _, reg in ipairs(generation_regs) do
        m:write_reg(reg, generation)
    end
    return m
end

local function step(m, mode)
    local target = m:read_reg("mcycle") + 1
    if mode == "native" then
        m:run(target)
    elseif mode == "record" then
        local before = m:get_root_hash()
        local log = m:log_step(1)
        assert(cartesi.machine:verify_step(before, log, 1) == m:get_root_hash())
    elseif mode == "uarch" then
        local before = m:get_root_hash()
        local log = m:log_step_uarch(1 << 20)
        assert(m:read_reg("uarch_halt") ~= 0)
        assert(cartesi.machine:verify_step_uarch(before, log, 1 << 20) == m:get_root_hash())
        m:reset_uarch()
    elseif mode == "collect" then
        local result = m:collect_mcycle_root_hashes(target, 0)
        assert(#result.hashes == 1 and result.hashes[1] == m:get_root_hash())
    end
    assert(m:read_reg("mcycle") == target)
    return m:get_root_hash()
end

for _, hash_function in ipairs({ "keccak256", "sha256" }) do
    for _, generation in ipairs({ 0, -2, -1 }) do
        local reference = {}
        local modes = hash_function == "keccak256" and { "native", "record", "uarch", "collect" }
            or { "native", "record", "collect" }
        for _, mode in ipairs(modes) do
            local m <close> = new_machine(generation, hash_function)
            for i = 1, #instructions do
                local tlb_before = m:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH)
                local code_generation = m:read_reg("tlb_generation_code")
                local hash = step(m, mode)
                if mode == "native" then
                    reference[i] = hash
                else
                    assert(hash == reference[i], mode .. " diverged at instruction " .. i)
                end
                if i == 3 or i == 7 then
                    assert(m:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH) == tlb_before)
                    assert(m:read_reg("tlb_generation_code") == (code_generation == -1 and -1 or code_generation + 1))
                elseif i == 5 then
                    assert(m:read_reg("tlb_generation_code") == code_generation, "MXR/SUM flushed code set")
                end
            end
            assert(m:read_reg("x3") == 42)
        end
        -- Hash only after a store followed by invalidation, so the flush must preserve dirty tracking.
        local n <close> = new_machine(generation, hash_function)
        n:get_root_hash()
        n:run(#instructions)
        assert(n:get_root_hash() == reference[#instructions], "batched native dirty tracking diverged")
        assert(n:get_root_hash() == test_util.calculate_emulator_hash(n), "incremental hash missed dirty RAM")
        if hash_function == "keccak256" then
            local collected <close> = new_machine(generation, hash_function)
            collected:collect_uarch_cycle_root_hashes(#instructions, 0, { string.rep("\0", 32), string.rep("\0", 32) })
            assert(collected:get_root_hash() == reference[#instructions], "uarch collector diverged")
        end
    end
end

for _, mode in ipairs({ "native", "record", "uarch", "collect" }) do
    for _, mask in ipairs({ 1 << 19, 1 << 18 }) do
        local partial <close> = new_machine(0, "keccak256")
        partial:run(4)
        local code_generation = partial:read_reg("tlb_generation_code")
        local read_generation = partial:read_reg("tlb_generation_read")
        local write_generation = partial:read_reg("tlb_generation_write")
        partial:write_reg("x4", partial:read_reg("mstatus") | mask)
        step(partial, mode)
        assert(partial:read_reg("tlb_generation_code") == code_generation)
        assert(partial:read_reg("tlb_generation_read") == read_generation + 1)
        assert(partial:read_reg("tlb_generation_write") == write_generation + (mask == 1 << 18 and 1 or 0))
    end
end

local function replace_shadow_word(m, address, value)
    local shadow = m:read_memory(cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_STATE_LENGTH)
    local offset = address - cartesi.AR_SHADOW_STATE_START
    m:write_memory(
        cartesi.AR_SHADOW_STATE_START,
        shadow:sub(1, offset) .. string.pack("<I8", value) .. shadow:sub(offset + 9)
    )
end

-- A stale translation redirects the load to a different valid RAM page if wrongly promoted.
for _, mode in ipairs({ "native", "record", "uarch", "collect" }) do
    local m <close> = new_machine(0, "keccak256")
    m:run(2)
    local slot = cartesi.AR_SHADOW_TLB_START + 8192 + (((data >> 12) & 255) * 32)
    m:write_memory(data + 4096, string.pack("<I8", 99))
    replace_shadow_word(m, slot + 8, 4096)
    m:write_reg("tlb_generation_read", 1)
    m:write_reg("pc", ram + 12)
    local snapshot = os.tmpname()
    assert(os.remove(snapshot))
    m:store(snapshot)
    local loaded <close> = cartesi.machine(snapshot)
    assert(loaded:get_root_hash() == m:get_root_hash())
    local hash = step(m, mode)
    assert(step(loaded, mode) == hash)
    assert(m:read_reg("x3") == 42 and loaded:read_reg("x3") == 42, "stale slot was promoted")
    loaded:destroy()
    assert(os.execute("rm -rf -- " .. string.format("%q", snapshot)))
end

-- Changing the counter through the host API must invalidate an already promoted hot entry.
local m <close> = new_machine(0, "keccak256")
m:run(2)
m:write_reg("tlb_generation_read", 1)
m:write_reg("pc", ram + 12)
m:run(3)
local read_slot = cartesi.AR_SHADOW_TLB_START + 8192 + (((data >> 12) & 255) * 32)
assert(string.unpack("<I8", m:read_memory(read_slot + 24, 8)) == 1, "hot slot survived generation write")
print("TLB generation: native/uarch/replay/collect, saturation, partial flushes, snapshots, and dirty RAM passed")
