-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Only SSIP is writable in sip. STIP and SEIP are read-only there, even when mideleg delegates them, and only the
-- execution environment sets and clears them.

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local tests_util = require("cartesi.tests.util")

local RAM_START = cartesi.AR_RAM_START
local CSR_SIP = 0x144
local SSIP, STIP, SEIP = 1 << 1, 1 << 5, 1 << 9
local ALL = SSIP | STIP | SEIP

-- Encodes csrrw, csrrs or csrrc x0, sip, x10
local function csr_insn(funct3)
    return (CSR_SIP << 20) | (10 << 15) | (funct3 << 12) | 0x73
end
local CSRW, CSRS, CSRC = csr_insn(1), csr_insn(2), csr_insn(3)

local cases = {
    { name = "csrs sets only SSIP", insn = CSRS, x10 = ALL, mip = 0, expected = SSIP },
    { name = "csrc clears only SSIP", insn = CSRC, x10 = ALL, mip = ALL, expected = STIP | SEIP },
    { name = "csrw of all ones sets only SSIP", insn = CSRW, x10 = -1, mip = 0, expected = SSIP },
    { name = "csrw of zero clears only SSIP", insn = CSRW, x10 = 0, mip = ALL, expected = STIP | SEIP },
}

-- The guest runs in S-mode with every supervisor interrupt delegated and none enabled, so no interrupt is taken
local function create_machine(case)
    local machine = cartesi.machine({
        ram = { length = 0x10000 },
        processor = {
            registers = { pc = RAM_START, iprv = 1, mideleg = ALL, mie = 0, mip = case.mip, x10 = case.x10 },
        },
    })
    machine:write_memory(RAM_START, string.pack("<I4", case.insn))
    return machine
end

local function expect_result(machine, case)
    expect.equal(machine:read_reg("mcycle"), 1)
    expect.equal(machine:read_reg("pc"), RAM_START + 4)
    expect.equal(machine:read_reg("mip"), case.expected)
end

describe("sip writes", function()
    for _, case in ipairs(cases) do
        it(case.name, function()
            local native <close> = create_machine(case)
            local initial_hash = native:get_root_hash()
            expect.equal(native:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            expect_result(native, case)
            local expected_hash = native:get_root_hash()

            local logged <close> = create_machine(case)
            local _ <close>, filename = tests_util.scope_temp_pathname()
            expect.equal(logged:log_step(1, filename), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            expect.equal(logged:verify_step(initial_hash, filename, 1), expected_hash)

            local uarch <close> = create_machine(case)
            expect.equal(uarch:run_uarch(math.maxinteger), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
            local before_reset = uarch:get_root_hash()
            local log = uarch:log_reset_uarch()
            expect.equal(uarch:verify_reset_uarch(before_reset, log), expected_hash)
            expect_result(uarch, case)
        end)
    end
end)

lester.report()
lester.exit()
