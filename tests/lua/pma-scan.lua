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
        local addresses = { 0x300000000 } -- Unmapped: scan every PMA and raise a load access fault.
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

-- A nonmatching PMA must still be rejected if its metadata is malformed.
-- Recompute the witness root so these cases reach interpretation, not a root mismatch.
local util = require("cartesi.tests.util")
local native <close> = cartesi.machine({ ram = { length = 1 << 20 } })
local uarch <close> = cartesi.machine({ ram = { length = 1 << 20 } })
for _, m in ipairs({ native, uarch }) do
    m:write_memory(cartesi.AR_RAM_START, string.pack("<I4", 0x00008103))
    m:write_reg("x1", 0x300000000)
end
local native_log = native:log_step(1)
local uarch_log = uarch:log_step_uarch(1 << 20)
local rejected = 0
for _, length in ipairs({ 4096, 0, 4095, 4097, -4096 }) do
    for _, fixture in ipairs({ { native_log, false }, { uarch_log, true } }) do
        local log = util.parse_step_log(fixture[1])
        local found = false
        for _, page in ipairs(log.pages) do
            if page.index == cartesi.AR_PMAS_START >> 12 then
                -- Entry 1 is DTB, after RAM and before the remaining ranges.
                local istart = string.unpack("<I8", page.data, 17)
                assert((istart & ~4095) == cartesi.AR_DTB_START and (istart & 1) ~= 0)
                page.data = page.data:sub(1, 24) .. string.pack("<I8", length) .. page.data:sub(33)
                found = true
            end
        end
        assert(found)
        local root = util.recompute_step_log_root(log, "keccak256")
        local ok, err = pcall(function()
            local serialized = util.serialize_step_log(log)
            if fixture[2] then
                return cartesi.machine:verify_step_uarch(root, serialized, 1 << 20)
            end
            return cartesi.machine:verify_step(root, serialized, 1)
        end)
        if length == 4096 then -- Valid nonmatching range: the altered witness must replay.
            assert(ok, err)
        else
            assert(not ok, "malformed nonmatching PMA was accepted")
            rejected = rejected + 1
        end
    end
end
print(string.format("PMA scan: %d malformed native/uarch replay witnesses rejected", rejected))

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
