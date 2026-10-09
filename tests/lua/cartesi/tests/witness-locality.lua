-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local util = require("cartesi.tests.util")

-- Fixed anchors from the whole-mcycle test recipes. Keep preparation separate
-- from the expectations so an image change cannot silently update the limits.
local function program(filename, mcycle)
    return function()
        local m = cartesi.machine({
            ram = { length = 32 << 20, backing_store = { data_filename = util.tests_path .. filename .. ".bin" } },
            flash_drive = { { start = 0x80000000000000, length = 0x40000 } },
        })
        m:run(mcycle)
        assert(m:read_reg("mcycle") == mcycle, "program did not reach locality anchor")
        return m
    end
end

-- sv48-load / sv48-amo: the existing pma-page-walk recipe, prefixed with
-- one ADDI to warm only the code TLB. Data A/D bits and both data TLBs stay
-- cold; four table levels occupy separate RAM pages.
local function sv48(instruction)
    return function()
        local config = { ram = { length = 1 << 20 }, flash_drive = {}, nvram = {} }
        for i = 1, 8 do
            config.flash_drive[i] = { start = 0x90000000 + i * 4096, length = 4096 }
            config.nvram[i] = { start = 0xa0000000 + i * 4096, length = 4096 }
        end
        local m = cartesi.machine(config)
        local code, tables, data = cartesi.AR_RAM_START + 4096, cartesi.AR_RAM_START + 0x10000, config.nvram[1].start
        for i = 0, 2 do
            local at = tables - i * 4096
            m:write_memory(at, string.pack("<I8", ((at - 4096) >> 2) | 1))
        end
        local leaf = tables - 3 * 4096
        m:write_memory(leaf + 8, string.pack("<I8", (code >> 2) | 0x0b))
        m:write_memory(leaf + 16, string.pack("<I8", ((code - 4096) >> 2) | 0x0b))
        m:write_memory(leaf + 24, string.pack("<I8", (data >> 2) | 0x07))
        m:write_memory(code, string.pack("<I4I4", 0x00000013, instruction))
        m:write_memory(data, string.pack("<I8", 0x1122334455667788))
        m:write_reg("pc", 0x1000)
        m:write_reg("x1", 0x3000)
        m:write_reg("x2", 0x8877665544332211)
        m:write_reg("iprv", 1)
        m:write_reg("satp", (9 << 60) | (tables >> 12))
        m:run(1)
        assert(m:read_reg("mcycle") == 1 and m:read_reg("pc") == 0x1004)
        return m
    end
end

return {
    { name = "ordinary-alu", program = "rv64ui-p-add", mcycle = 20, create = program("rv64ui-p-add", 20) },
    { name = "tlb-miss-load", program = "sv48-load", mcycle = 1, create = sv48(0x0000b103) }, -- ld x2,0(x1)
    { name = "amo-both-misses", program = "sv48-amo", mcycle = 1, create = sv48(0x0020b12f) }, -- amoadd.d x2,x2,(x1)
    { name = "trap-tlb-flush", program = "rv64ud-v-fdiv", mcycle = 1053, create = program("rv64ud-v-fdiv", 1053) },
}
