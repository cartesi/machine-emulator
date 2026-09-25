#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local setup = require("cartesi.tests.pma-branches")
local cases = 0
for _, mode in ipairs({ 8, 9 }) do
    for _, layout in ipairs({ "spread", "clustered", "mixed" }) do
        for _, store_fault in ipairs({ false, true }) do
            local config, initialize, pc, data = setup(mode, layout == "clustered", store_fault, nil, layout == "mixed")
            local native <close> = cartesi.machine(config)
            local uarch <close> = cartesi.machine(config)
            initialize(native)
            initialize(uarch)
            for _ = 1, 2 do
                for _, m in ipairs({ native, uarch }) do
                    m:write_reg("pc", pc)
                    m:write_reg("iprv", 1)
                    m:write_reg("x2", 0x8877665544332211)
                end
                local value = string.unpack("<I8", native:read_memory(data, 8))
                local before = native:get_root_hash()
                local native_log = native:log_step(1)
                assert(cartesi.machine:verify_step(before, native_log, 1) == native:get_root_hash())
                local uarch_log = uarch:log_step_uarch(1 << 20)
                assert(uarch:read_reg("uarch_halt") ~= 0)
                assert(cartesi.machine:verify_step_uarch(before, uarch_log, 1 << 20) == uarch:get_root_hash())
                uarch:reset_uarch()
                assert(native:get_root_hash() == uarch:get_root_hash(), "branched page-walk roots differ")
                if store_fault then
                    assert(native:read_reg("mcause") == 15)
                    assert(native:read_memory(data, 8) == string.pack("<I8", value))
                else
                    assert(native:read_reg("pc") == pc + 4 and native:read_reg("x2") == value)
                    assert(native:read_memory(data, 8) == string.pack("<I8", value + 0x8877665544332211))
                end
                cases = cases + 1
            end
        end
    end
end
print(string.format("PMA branches: %d native/uarch/record/replay root comparisons passed", cases))
