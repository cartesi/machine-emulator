-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")

local RAM_START = cartesi.AR_RAM_START
local MTVEC = RAM_START + 0x100
local STVEC = RAM_START + 0x200
local MSTATUS_SIE = 1 << 1
local MSTATUS_MIE = 1 << 3
local INTERRUPT_FLAG = 1 << 63

-- Each context increments a different register, then loops without changing interrupt state.
local function increment_loop(instruction)
    return string.pack("<I4I4", instruction, 0xffdff06f) -- jal x0,-4
end

local function create_machine(case, prv, hash_function, mcycle)
    local machine = cartesi.machine({
        ram = { length = 4096 },
        hash_tree = { hash_function = hash_function },
        processor = {
            registers = {
                pc = RAM_START,
                iprv = prv,
                mcycle = mcycle or 0,
                mtvec = MTVEC,
                stvec = STVEC,
                x10 = 0,
                x11 = 0,
                x12 = 0,
                mstatus = MSTATUS_SIE | MSTATUS_MIE,
                mideleg = case.deleg,
                mip = case.pending,
                mie = case.enabled or case.pending,
            },
        },
    })
    machine:write_memory(RAM_START, increment_loop(0x00160613)) -- addi x12,x12,1
    machine:write_memory(MTVEC, increment_loop(0x00150513)) -- addi x10,x10,1
    machine:write_memory(STVEC, increment_loop(0x00158593)) -- addi x11,x11,1
    return machine
end

local priority_cases = {
    { name = "SEI delegated, SSI retained", deleg = 0x200, pending = 0x202, irq = 1, dest = 3 },
    { name = "SEI delegated, STI retained", deleg = 0x200, pending = 0x220, irq = 5, dest = 3 },
    { name = "SSI delegated, STI retained", deleg = 0x002, pending = 0x022, irq = 5, dest = 3 },
    { name = "SEI and SSI delegated, STI retained", deleg = 0x202, pending = 0x222, irq = 5, dest = 3 },
    { name = "SEI and STI delegated, SSI retained", deleg = 0x220, pending = 0x222, irq = 1, dest = 3 },
    { name = "SSI and STI delegated, SEI retained", deleg = 0x022, pending = 0x222, irq = 9, dest = 3 },
    { name = "all delegated", deleg = 0x222, pending = 0x222, irq = 9, dest = 1 },
    { name = "none delegated", deleg = 0, pending = 0x222, irq = 9, dest = 3 },
    { name = "machine external first", deleg = 0x222, pending = 0xaaa, irq = 11, dest = 3 },
    { name = "machine software before timer", deleg = 0x222, pending = 0x2aa, irq = 3, dest = 3 },
    { name = "machine timer before supervisor external", deleg = 0x222, pending = 0x2a2, irq = 7, dest = 3 },
    { name = "disabled M destination", deleg = 0x200, pending = 0x202, enabled = 0x200, irq = 9, dest = 1 },
}

describe("interrupt priority", function()
    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        describe(hash_function, function()
            for _, prv in ipairs({ 0, 1 }) do
                describe(prv == 0 and "U-mode" or "S-mode", function()
                    for _, case in ipairs(priority_cases) do
                        it(case.name, function()
                            local machine <close> = create_machine(case, prv, hash_function)
                            expect.equal(machine:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                            expect.equal(machine:read_reg("iprv"), case.dest)
                            expect.equal(
                                machine:read_reg(case.dest == 3 and "mcause" or "scause"),
                                INTERRUPT_FLAG | case.irq
                            )
                            expect.equal(machine:read_reg(case.dest == 3 and "mepc" or "sepc"), RAM_START)
                            expect.equal(machine:read_reg("x10"), case.dest == 3 and 1 or 0)
                            expect.equal(machine:read_reg("x11"), case.dest == 1 and 1 or 0)
                            expect.equal(machine:read_reg("x12"), 0)
                        end)
                    end

                    for i = 1, 5 do
                        local case = priority_cases[i]
                        it(case.name .. " agrees across execution paths", function()
                            local mcycle_start = 8190 -- Cross an RTC tick, as well as arbitrary run boundaries.
                            local mcycle_end = mcycle_start + 32
                            local reference <close> = create_machine(case, prv, hash_function, mcycle_start)
                            local hashes = {}
                            for mcycle = mcycle_start + 1, mcycle_end do
                                expect.equal(reference:run(mcycle), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                                hashes[#hashes + 1] = reference:get_root_hash()
                            end
                            for _, chunk_size in ipairs({ 7, 32 }) do
                                local machine <close> = create_machine(case, prv, hash_function, mcycle_start)
                                while machine:read_reg("mcycle") < mcycle_end do
                                    local target = math.min(machine:read_reg("mcycle") + chunk_size, mcycle_end)
                                    expect.equal(machine:run(target), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                                    expect.equal(machine:get_root_hash(), hashes[target - mcycle_start])
                                end
                            end

                            for log2_period = 0, 5 do
                                local machine <close> = create_machine(case, prv, hash_function, mcycle_start)
                                local collected = machine:collect_mcycle_root_hashes(mcycle_end, log2_period)
                                expect.equal(collected.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                                local expected = {}
                                for offset = 1 << log2_period, 32, 1 << log2_period do
                                    expected[#expected + 1] = hashes[offset]
                                end
                                expect.equal(collected.hashes, expected)
                                expect.equal(machine:get_root_hash(), hashes[32])
                            end

                            if hash_function == "keccak256" then
                                local machine <close> = create_machine(case, prv, hash_function, mcycle_start)
                                for offset = 1, 32 do
                                    expect.equal(
                                        machine:run_uarch(math.maxinteger),
                                        cartesi.UARCH_BREAK_REASON_UARCH_HALTED
                                    )
                                    machine:reset_uarch()
                                    expect.equal(machine:get_root_hash(), hashes[offset])
                                end
                            end

                            local logged <close> = create_machine(case, prv, hash_function, mcycle_start)
                            local initial_hash = logged:get_root_hash()
                            local log, break_reason = logged:log_step(32)
                            expect.equal(break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                            expect.equal(logged:get_root_hash(), hashes[32])
                            expect.equal(logged:verify_step(initial_hash, log, 32), hashes[32])
                            expect.equal(reference:read_reg("x10"), 16)
                            expect.equal(reference:read_reg("x11"), 0)
                        end)
                    end
                end)
            end

            it("M-mode ignores delegated interrupts", function()
                local machine <close> = create_machine(priority_cases[1], 3, hash_function)
                machine:run(1)
                expect.equal(machine:read_reg("mcause"), INTERRUPT_FLAG | 1)
                expect.equal(machine:read_reg("x10"), 1)
                expect.equal(machine:read_reg("x11"), 0)
            end)

            it("SIE does not mask M-destined interrupts", function()
                local machine <close> = create_machine(priority_cases[1], 1, hash_function)
                machine:write_reg("mstatus", 0)
                machine:run(1)
                expect.equal(machine:read_reg("mcause"), INTERRUPT_FLAG | 1)
                expect.equal(machine:read_reg("x10"), 1)
            end)

            it("SIE masks S-destined interrupts in S-mode", function()
                local machine <close> = create_machine(priority_cases[7], 1, hash_function)
                machine:write_reg("mstatus", 0)
                machine:run(1)
                expect.equal(machine:read_reg("iprv"), 1)
                expect.equal(machine:read_reg("x12"), 1)
            end)

            it("U-mode enables higher-privilege interrupts regardless of SIE and MIE", function()
                local machine <close> = create_machine(priority_cases[1], 0, hash_function)
                machine:write_reg("mstatus", 0)
                machine:run(1)
                expect.equal(machine:read_reg("iprv"), 3)
                expect.equal(machine:read_reg("mcause"), INTERRUPT_FLAG | 1)
                expect.equal(machine:read_reg("x10"), 1)
            end)

            it("MIE masks M-destined interrupts in M-mode", function()
                local machine <close> = create_machine(priority_cases[1], 3, hash_function)
                machine:write_reg("mstatus", 0)
                machine:run(1)
                expect.equal(machine:read_reg("iprv"), 3)
                expect.equal(machine:read_reg("x12"), 1)
            end)
        end)
    end
end)

os.exit(lester.report())
