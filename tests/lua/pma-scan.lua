#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local cases = 0
for _, flash_count in ipairs({ 0, 1, 8 }) do
    for _, nvram_count in ipairs({ 0, 8 }) do
        local config = { ram = { length = 1 << 20 }, flash_drive = {}, nvram = {} }
        for i = 1, flash_count do
            config.flash_drive[i] = { start = 0x90000000 + i * 4096, length = 4096 }
        end
        for i = 1, nvram_count do
            config.nvram[i] = { start = 0xa0000000 + i * 4096, length = 4096 }
        end
        local addresses = { 0x300000000 } -- Unmapped: exhaust the search and raise a load access fault.
        if flash_count > 0 then
            addresses[#addresses + 1] = config.flash_drive[flash_count].start
        end
        if nvram_count > 0 then
            addresses[#addresses + 1] = config.nvram[nvram_count].start
        end
        for funct3 = 0, 3 do -- LB, LH, LW, LD: test cold and warm TLB entries at each width.
            local native <close> = cartesi.machine(config)
            local uarch <close> = cartesi.machine(config)
            for _, address in ipairs(addresses) do
                for _ = 1, 2 do
                    for _, m in ipairs({ native, uarch }) do
                        m:write_reg("pc", cartesi.AR_RAM_START)
                        m:write_memory(cartesi.AR_RAM_START, string.pack("<I4", 0x00008103 | (funct3 << 12)))
                        m:write_reg("x1", address)
                    end
                    local before = uarch:get_root_hash()
                    local log = uarch:log_step_uarch(1 << 20)
                    assert(uarch:read_reg("uarch_halt") ~= 0)
                    assert(cartesi.machine:verify_step_uarch(before, log, 1 << 20) == uarch:get_root_hash())
                    uarch:reset_uarch()
                    local native_before = native:get_root_hash()
                    local native_log = native:log_step(1)
                    assert(cartesi.machine:verify_step(native_before, native_log, 1) == native:get_root_hash())
                    assert(native:get_root_hash() == uarch:get_root_hash(), "PMA scan roots differ")
                    if address == 0x300000000 then
                        assert(native:read_reg("mcause") == 5)
                    else
                        assert(native:read_reg("pc") == cartesi.AR_RAM_START + 4)
                        assert(native:read_reg("x2") == 0)
                    end
                    cases = cases + 1
                end
            end
        end
    end
end
print(string.format("PMA scan: %d native/uarch/record/replay root comparisons passed", cases))

-- Only probed descriptors are validated. For this unmapped LD, PMA self at
-- index 1 is unprobed; RAM at index 0 is probed. Both verifiers must agree.
-- Recompute the witness root so malformed metadata reaches interpretation.
local util = require("cartesi.tests.util")
local function create()
    local m = cartesi.machine({ ram = { length = 1 << 20 } })
    m:write_memory(cartesi.AR_RAM_START, string.pack("<I4", 0x0000b103))
    m:write_reg("x1", 0x300000000)
    return m
end
local n <close> = create()
local u <close> = create()
local logs = { { name = "native", data = n:log_step(1) }, { name = "uarch", data = u:log_step_uarch(1 << 20) } }
local accepted, rejected = 0, 0
for _, fixture in ipairs(logs) do
    for _, target in ipairs({ cartesi.AR_PMAS_START, cartesi.AR_RAM_START }) do
        local log = util.parse_step_log(fixture.data)
        local found
        for _, page in ipairs(log.pages) do
            if page.index == cartesi.AR_PMAS_START >> 12 then
                for index = 0, 31 do
                    local istart, length = string.unpack("<I8I8", page.data, index * 16 + 1)
                    if length > 0 and istart & ~4095 == target then
                        page.data = page.data:sub(1, index * 16 + 8)
                            .. string.pack("<I8", 4095)
                            .. page.data:sub(index * 16 + 17)
                        found = index
                        break
                    end
                end
            end
        end
        assert(found)
        local root = util.recompute_step_log_root(log, "keccak256")
        local serialized = util.serialize_step_log(log)
        local ok, err = pcall(function()
            if fixture.name == "native" then
                return cartesi.machine:verify_step(root, serialized, 1)
            else
                return cartesi.machine:verify_step_uarch(root, serialized, 1 << 20)
            end
        end)
        assert(ok == (target == cartesi.AR_PMAS_START), tostring(err))
        if ok then
            accepted = accepted + 1
        else
            rejected = rejected + 1
        end
    end
end
print(string.format("PMA malformed witnesses: %d unprobed accepted, %d probed rejected", accepted, rejected))

-- Compact guest PMAs must keep the original device callbacks and access widths.
local device_cases = 0
for _, address in ipairs({
    cartesi.AR_CLINT_START,
    cartesi.AR_CLINT_START + 0x4000,
    cartesi.AR_PLIC_START + 0x200004,
    cartesi.AR_HTIF_START + 8,
}) do
    for funct3 = 0, 3 do
        for _, store in ipairs({ false, true }) do
            local device_native <close> = cartesi.machine({ ram = { length = 1 << 20 } })
            local device_uarch <close> = cartesi.machine({ ram = { length = 1 << 20 } })
            local instruction = (store and 0x00208023 or 0x00008103) | (funct3 << 12)
            for _, machine in ipairs({ device_native, device_uarch }) do
                machine:write_memory(cartesi.AR_RAM_START, string.pack("<I4", instruction))
                machine:write_reg("pc", cartesi.AR_RAM_START)
                machine:write_reg("x1", address)
                machine:write_reg("x2", 1)
                machine:write_reg("plic_girqpend", 2)
            end
            local before = device_native:get_root_hash()
            local device_native_log = device_native:log_step(1)
            assert(cartesi.machine:verify_step(before, device_native_log, 1) == device_native:get_root_hash())
            local device_uarch_log = device_uarch:log_step_uarch(1 << 20)
            assert(device_uarch:read_reg("uarch_halt") ~= 0)
            assert(cartesi.machine:verify_step_uarch(before, device_uarch_log, 1 << 20) == device_uarch:get_root_hash())
            device_uarch:reset_uarch()
            assert(device_native:get_root_hash() == device_uarch:get_root_hash(), "device PMA roots differ")
            device_cases = device_cases + 1
        end
    end
end
print(string.format("PMA devices: %d native/uarch/record/replay root comparisons passed", device_cases))

-- Constructor order is independent of drive configuration order.
for _, count in ipairs({ 0, 2, 4, 8 }) do
    local config = { ram = { length = 1 << 20 }, flash_drive = {}, nvram = {} }
    for i = 1, count do
        -- Deliberately reverse configuration order relative to physical starts.
        config.flash_drive[i] = { start = 0x90000000 + (count + 1 - i) * 0x10000, length = 0x10000 }
        config.nvram[i] = { start = 0xa0000000 + (count + 1 - i) * 0x10000, length = 0x10000 }
    end
    local m <close> = cartesi.machine(config)
    local bytes = m:read_memory(cartesi.AR_PMAS_START, cartesi.AR_PMAS_LENGTH)
    local last, empty, n = 0, false, 0
    for index = 0, 31 do
        local start, length = string.unpack("<I8I8", bytes, index * 16 + 1)
        start = start & ~4095
        if index == 0 then
            assert(start == cartesi.AR_RAM_START and length == config.ram.length)
        elseif length > 0 then
            assert(not empty and start >= last)
            last = start + length
        end
        if length == 0 then
            empty = true
        else
            n = n + 1
        end
    end
    assert(n == 8 + 2 * count)
    local ok = pcall(function()
        m:write_memory(cartesi.AR_PMAS_START, bytes:sub(1, 8))
    end)
    assert(not ok, "PMA table must remain host-read-only")
    print(
        string.format("%d drives: RAM0, sorted nonoverlapping tail, %d PMAs, empty suffix, immutable API", 2 * count, n)
    )
end
