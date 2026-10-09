#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local cases = 0
-- Sv57 is disabled by NO_SATP_MODE_SV57 in the current emulator.
for _, mode in ipairs({ 8, 9 }) do
    for _, operation in ipairs({ "load", "store", "fault", "split", "amo", "amo-split", "amo-split-store-fault" }) do
        local config = { ram = { length = 1 << 20 }, flash_drive = {}, nvram = {} }
        for i = 1, 8 do
            config.flash_drive[i] = { start = 0x90000000 + i * 4096, length = 4096 }
            config.nvram[i] = { start = 0xa0000000 + i * 4096, length = 4096 }
        end
        local levels = mode - 5
        local code = cartesi.AR_RAM_START + 4096
        local tables = cartesi.AR_RAM_START + 0x10000
        local data = config.nvram[1].start
        local atomic = operation:find("amo", 1, true) ~= nil
        local split = operation:find("split", 1, true) ~= nil
        local store_fault = operation == "amo-split-store-fault"
        local pc = split and 0x1ffe or 0x1000
        -- amoadd.d x2,x2,(x1), sd x2,0(x1), or ld x2,0(x1).
        local instruction = atomic and 0x0020b12f or (operation == "store" and 0x0020b023 or 0x0000b103)
        local function initialize(m)
            for i = 0, levels - 2 do
                local at = tables - i * 4096
                m:write_memory(at, string.pack("<I8", ((at - 4096) >> 2) | 1))
            end
            local leaf = tables - (levels - 1) * 4096
            -- A/D bits initially clear: each successful walk must update the PTE.
            m:write_memory(leaf + 8, string.pack("<I8", (code >> 2) | 0x0b))
            m:write_memory(leaf + 16, string.pack("<I8", ((code - 4096) >> 2) | 0x0b))
            local target = operation == "fault" and 0x300000000 or data
            m:write_memory(leaf + 24, string.pack("<I8", (target >> 2) | (store_fault and 0x03 or 0x07)))
            if split then
                m:write_memory(code + 4094, string.pack("<I2", instruction & 0xffff))
                m:write_memory(code - 4096, string.pack("<I2", instruction >> 16))
            else
                m:write_memory(code, string.pack("<I4", instruction))
            end
            m:write_memory(data, string.pack("<I8", 0x1122334455667788))
            m:write_reg("pc", pc)
            m:write_reg("x1", 0x3000)
            m:write_reg("x2", 0x8877665544332211)
            m:write_reg("iprv", 1)
            m:write_reg("satp", (mode << 60) | (tables >> 12))
        end
        local m <close> = cartesi.machine(config)
        local n <close> = cartesi.machine(config)
        initialize(m)
        initialize(n)
        for _ = 1, 2 do -- Repeat with the PTE access bits and TLB entries warmed.
            for _, machine in ipairs({ m, n }) do
                machine:write_reg("pc", pc)
                machine:write_reg("iprv", 1)
                machine:write_reg("x2", 0x8877665544332211)
            end
            local data_before = string.unpack("<I8", m:read_memory(data, 8))
            local before = m:get_root_hash()
            local log = m:log_step_uarch(1 << 20)
            assert(m:read_reg("uarch_halt") ~= 0)
            local after = m:get_root_hash()
            assert(cartesi.machine:verify_step_uarch(before, log, 1 << 20) == after)
            m:reset_uarch()
            local native_log = n:log_step(1)
            assert(cartesi.machine:verify_step(before, native_log, 1) == n:get_root_hash())
            assert(n:get_root_hash() == m:get_root_hash(), "page-walk roots differ")
            if operation == "fault" or store_fault then
                assert(n:read_reg("mcause") == (store_fault and 15 or 5))
                assert(n:read_memory(data, 8) == string.pack("<I8", data_before))
            else
                assert(n:read_reg("pc") == pc + 4)
                if operation == "store" then
                    assert(n:read_memory(data, 8) == string.pack("<I8", 0x8877665544332211))
                else
                    assert(n:read_reg("x2") == data_before)
                    if atomic then
                        assert(n:read_memory(data, 8) == string.pack("<I8", data_before + 0x8877665544332211))
                    end
                end
            end
            cases = cases + 1
        end
    end
end
print(string.format("PMA page walks: %d native/uarch/record/replay root comparisons passed", cases))
