#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")
local ram = cartesi.AR_RAM_START
local data = ram + 0x4000
local invalid_slot = string.pack("<I8I8I8I8", -1, 0, -1, 0)
local invalid_set = invalid_slot:rep(256)
local batch_size = cartesi.UARCH_TLB_FLUSH_BATCH_SIZE
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

local function new_machine(hash_function)
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
    local modes = hash_function == "keccak256" and { "native", "record", "uarch", "collect" }
        or { "native", "record", "collect" }
    local reference = {}
    for _, mode in ipairs(modes) do
        local m <close> = new_machine(hash_function)
        for i = 1, #instructions do
            local hash = step(m, mode)
            if mode == "native" then
                reference[i] = hash
            else
                assert(hash == reference[i], mode .. " diverged at instruction " .. i)
            end
            if i == 3 or i == 7 or i == 8 then
                assert(m:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH) == invalid_set:rep(3))
            end
        end
        assert(m:read_reg("x3") == 42)
    end
    local n <close> = new_machine(hash_function)
    n:get_root_hash()
    n:run(#instructions)
    assert(n:get_root_hash() == reference[#instructions], "dirty tracking diverged")
    assert(n:get_root_hash() == test_util.calculate_emulator_hash(n), "incremental hash missed dirty RAM")
    local mixed <close> = new_machine(hash_function)
    for i = 1, #instructions do
        assert(step(mixed, modes[(i - 1) % #modes + 1]) == reference[i], "accessor switch diverged")
    end
    if hash_function == "keccak256" then
        local collected <close> = new_machine(hash_function)
        collected:collect_uarch_cycle_root_hashes(#instructions, 0, { string.rep("\0", 32), string.rep("\0", 32) })
        assert(collected:get_root_hash() == reference[#instructions])
    end
end

local partial_roots = {}
for _, mode in ipairs({ "native", "record", "uarch", "collect" }) do
    for case_index, mask in ipairs({ 1 << 19, 1 << 18, 1 << 17, 1 << 11 }) do
        local m <close> = new_machine("keccak256")
        if mask == 1 << 11 then
            m:write_reg("mstatus", m:read_reg("mstatus") | (1 << 17) | (3 << 11))
        end
        m:run(4)
        m:write_reg("pc", ram)
        m:run(5)
        m:write_reg("pc", ram + 16)
        local before = m:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH)
        assert(before:sub(8193, 16384) ~= invalid_set and before:sub(16385) ~= invalid_set)
        local mstatus = m:read_reg("mstatus")
        m:write_reg("x4", mask == 1 << 11 and ((mstatus & ~(3 << 11)) | mask) or (mstatus | mask))
        local hash = step(m, mode)
        if mode == "native" then
            partial_roots[case_index] = hash
        else
            assert(hash == partial_roots[case_index], "partial-flush roots diverged")
        end
        local after = m:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH)
        assert(after:sub(1, 8192) == before:sub(1, 8192), "data-only invalidation flushed code")
        assert(after:sub(8193, 16384) == invalid_set)
        assert(after:sub(16385) == (mask == 1 << 19 and before:sub(16385) or invalid_set))
    end
end

local function plant_batch(m, set_index, slot_index)
    m:write_memory(m:read_reg("uarch_pc"), string.pack("<I4", 0x00000073))
    m:write_reg("uarch_x17", cartesi.UARCH_ECALL_FN_FLUSH_TLB_BATCH)
    m:write_reg("uarch_x10", set_index)
    m:write_reg("uarch_x11", slot_index)
end

for set_index = 0, 2 do
    for _, slot_index in ipairs({ 0, 128 - batch_size, 128, 256 - batch_size }) do
        local expected_hash
        for _, record in ipairs({ false, true }) do
            local m <close> = new_machine("keccak256")
            local slots = {}
            for i = 1, 3 * 256 do
                slots[i] = string.pack("<I8I8I8I8", -1, i * 4096, -1, i)
            end
            local tlb = table.concat(slots)
            local shadow = m:read_memory(cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_STATE_LENGTH)
            local offset = cartesi.AR_SHADOW_TLB_START - cartesi.AR_SHADOW_STATE_START
            m:write_memory(cartesi.AR_SHADOW_STATE_START, shadow:sub(1, offset) .. tlb .. shadow:sub(offset + #tlb + 1))
            plant_batch(m, set_index, slot_index)
            local before = m:get_root_hash()
            if record then
                local log = m:log_step_uarch(1)
                assert(cartesi.machine:verify_step_uarch(before, log, 1) == m:get_root_hash())
                assert(m:get_root_hash() == expected_hash)
            else
                m:run_uarch(1)
                expected_hash = m:get_root_hash()
            end
            offset = (set_index * 256 + slot_index) * 32
            local expected = tlb:sub(1, offset) .. invalid_slot:rep(batch_size) .. tlb:sub(offset + batch_size * 32 + 1)
            assert(m:read_memory(cartesi.AR_SHADOW_TLB_START, #tlb) == expected, "batch touched the wrong slots")
            assert(m:read_reg("uarch_cycle") == 1)
        end
    end
end

for _, args in ipairs({ { 3, 0 }, { 1 << 51, 0 }, { -1, 0 }, { 0, 256 }, { 0, -1 }, { 0, 1 }, { 0, 255 } }) do
    for _, method in ipairs({ "run_uarch", "log_step_uarch" }) do
        local m <close> = new_machine("keccak256")
        plant_batch(m, args[1], args[2])
        local before = m:get_root_hash()
        local ok, err = pcall(m[method], m, 1)
        assert(not ok and tostring(err):find("TLB batch index out of range or unaligned", 1, true))
        assert(m:get_root_hash() == before, "invalid batch mutated state")
    end
end

for _, mode in ipairs({ "native", "record", "uarch", "collect" }) do
    local m <close> = new_machine("keccak256")
    m:run(2)
    local path = os.tmpname()
    assert(os.remove(path))
    m:store(path)
    do
        local loaded <close> = cartesi.machine(path)
        assert(loaded:get_root_hash() == m:get_root_hash())
        for _ = 3, #instructions do
            assert(step(loaded, mode) == step(m, mode), "snapshot continuation diverged")
        end
    end
    m:remove_stored(path)
end

print("TLB flush: batches, bounds, roots, partial flushes, dirty RAM, snapshots, and accessor switches passed")
