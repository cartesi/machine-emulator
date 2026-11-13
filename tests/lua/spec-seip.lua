-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- A PLIC completion for an id that is not being served leaves the PLIC unchanged, so it does not clear a supervisor
-- external interrupt that M-mode set in mip.SEIP. Completing an id that is being served still updates mip.

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local tests_util = require("cartesi.tests.util")

local RAM_START = cartesi.AR_RAM_START
local STVEC = RAM_START + 0x100
local PLIC_CLAIM_COMPLETE = cartesi.AR_PLIC_START + 0x200004
local MIP_SEIP, MIP_MEIP = 1 << 9, 1 << 11
local MCAUSE_SEI = (1 << 63) | 9

local SW_X11_X10 = 0x00b52023 -- sw x11,0(x10)
local CSRSI_SSTATUS_SIE = 0x10016073 -- csrrsi x0,sstatus,2
local NOP = 0x00000013 -- addi x0,x0,0

local cases = {
    {
        -- S-mode completes id 1, which is not being served, and then enables the interrupt
        name = "completing an id that is not being served keeps SEIP set by M-mode",
        first = SW_X11_X10,
        plic = {},
        mip = MIP_SEIP,
    },
    {
        name = "SEIP set by M-mode is taken without a completion",
        first = NOP,
        plic = {},
        mip = MIP_SEIP,
    },
    {
        -- Id 1 is being served and id 2 is pending, so completing id 1 raises the PLIC signal
        name = "completing an id that is being served still updates mip",
        first = SW_X11_X10,
        plic = { girqpend = (1 << 1) | (1 << 2), girqsrvd = 1 << 1 },
        mip = 0,
        expected_mip = MIP_SEIP | MIP_MEIP,
    },
}

-- S-mode runs with the supervisor external interrupt delegated and enabled in sie, but sstatus.SIE clear
local function create_machine(case)
    local machine = cartesi.machine({
        ram = { length = 0x10000 },
        processor = {
            registers = {
                pc = RAM_START,
                iprv = 1,
                stvec = STVEC,
                mideleg = MIP_SEIP,
                mie = MIP_SEIP,
                mip = case.mip,
                x10 = PLIC_CLAIM_COMPLETE,
                x11 = 1,
                plic = case.plic,
            },
        },
    })
    machine:write_memory(RAM_START, string.pack("<I4I4", case.first, CSRSI_SSTATUS_SIE))
    machine:write_memory(STVEC, string.pack("<I4", 0x0000006f)) -- jal x0,0
    return machine
end

-- After the two instructions, the interrupt is taken and the handler runs one instruction
local MCYCLE = 3

local function expect_result(machine, case)
    expect.equal(machine:read_reg("mcycle"), MCYCLE)
    expect.equal(machine:read_reg("mip"), case.expected_mip or MIP_SEIP)
    expect.equal(machine:read_reg("scause"), MCAUSE_SEI)
    expect.equal(machine:read_reg("sepc"), RAM_START + 8)
    expect.equal(machine:read_reg("pc"), STVEC)
end

describe("supervisor external interrupt", function()
    for _, case in ipairs(cases) do
        it(case.name, function()
            local native <close> = create_machine(case)
            local initial_hash = native:get_root_hash()
            expect.equal(native:run(MCYCLE), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            expect_result(native, case)
            local expected_hash = native:get_root_hash()

            local logged <close> = create_machine(case)
            local _ <close>, filename = tests_util.scope_temp_pathname()
            expect.equal(logged:log_step(MCYCLE, filename), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            expect.equal(logged:verify_step(initial_hash, filename, MCYCLE), expected_hash)

            -- Each run_uarch executes one mcycle, and each reset is logged and verified
            local uarch <close> = create_machine(case)
            for _ = 1, MCYCLE do
                expect.equal(uarch:run_uarch(math.maxinteger), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
                local before_reset = uarch:get_root_hash()
                local log = uarch:log_reset_uarch()
                expect.equal(uarch:verify_reset_uarch(before_reset, log), uarch:get_root_hash())
            end
            expect.equal(uarch:get_root_hash(), expected_hash)
            expect_result(uarch, case)
        end)
    end
end)

lester.report()
lester.exit()
