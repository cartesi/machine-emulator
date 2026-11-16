-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- minstret counts retired instructions. An instruction that raises an exception consumes an mcycle without retiring,
-- and an interrupt is taken between instructions without consuming an mcycle, so neither is counted.

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local tests_util = require("cartesi.tests.util")

local RAM_START = cartesi.AR_RAM_START
local MTVEC = RAM_START + 0x100
local MSTATUS_MIE = 1 << 3
local MIE_MTIE = 1 << 7
local MCAUSE_ILLEGAL_INSN = 2
local MCAUSE_MTI = (1 << 63) | 7

local ILLEGAL = 0x00000000
local ADDI_X1 = 0x00108093 -- addi x1,x1,1
local CSRR_X2_MINSTRET = 0xb0202173 -- csrrs x2,minstret,x0

-- The trap handler retires three instructions and then reads minstret
local HANDLER = { ADDI_X1, ADDI_X1, ADDI_X1, CSRR_X2_MINSTRET }

local cases = {
    {
        -- The interrupt is taken before the first fetch, so the four handler instructions take four mcycles
        name = "an interrupt is not counted",
        registers = { pc = RAM_START, mstatus = MSTATUS_MIE, mie = MIE_MTIE },
        clint = { mtimecmp = 0 },
        mcycle = 4,
        mcause = MCAUSE_MTI,
        icycleinstret = 0,
    },
    {
        -- The illegal instruction takes one mcycle without retiring, and the handler takes four more
        name = "an instruction that raises an exception is not counted",
        registers = { pc = RAM_START },
        mcycle = 5,
        mcause = MCAUSE_ILLEGAL_INSN,
        icycleinstret = 1,
    },
}

local function create_machine(case)
    local registers = { mtvec = MTVEC, clint = case.clint }
    for k, v in pairs(case.registers) do
        registers[k] = v
    end
    local machine = cartesi.machine({ ram = { length = 0x10000 }, processor = { registers = registers } })
    machine:write_memory(RAM_START, string.pack("<I4", ILLEGAL))
    for i, insn in ipairs(HANDLER) do
        machine:write_memory(MTVEC + (i - 1) * 4, string.pack("<I4", insn))
    end
    return machine
end

local function expect_result(machine, case)
    expect.equal(machine:read_reg("mcycle"), case.mcycle)
    expect.equal(machine:read_reg("mcause"), case.mcause)
    expect.equal(machine:read_reg("pc"), MTVEC + #HANDLER * 4)
    expect.equal(machine:read_reg("x1"), 3)
    -- The handler read minstret after its three instructions retired
    expect.equal(machine:read_reg("x2"), 3)
    expect.equal(machine:read_reg("icycleinstret"), case.icycleinstret)
end

describe("minstret", function()
    for _, case in ipairs(cases) do
        it(case.name, function()
            tests_util.expect_all_paths_agree(
                function()
                    return create_machine(case)
                end,
                case.mcycle,
                function(machine)
                    expect_result(machine, case)
                end
            )
        end)
    end
end)

lester.report()
lester.exit()
