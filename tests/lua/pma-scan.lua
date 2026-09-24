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
        local native <close> = cartesi.machine(config)
        local uarch <close> = cartesi.machine(config)
        local addresses = { 0x300000000 } -- Unmapped: scan every PMA and raise a load access fault.
        if flash_count > 0 then
            addresses[#addresses + 1] = config.flash_drive[flash_count].start
        end
        if nvram_count > 0 then
            addresses[#addresses + 1] = config.nvram[nvram_count].start
        end
        for _, address in ipairs(addresses) do
            for _, m in ipairs({ native, uarch }) do
                m:write_reg("pc", cartesi.AR_RAM_START)
                m:write_memory(cartesi.AR_RAM_START, string.pack("<I4", 0x00008103)) -- lb x2, 0(x1)
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
print(string.format("PMA scan: %d native/uarch/record/replay root comparisons passed", cases))
