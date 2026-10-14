-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local tests_util = require("cartesi.tests.util")

local RAM_START = cartesi.AR_RAM_START
local DRIVE_START = 0x90000000
local MTVEC = RAM_START + 0x100
local TLB_CODE, TLB_READ, TLB_WRITE = 0, 1, 2
local TLB_SET_SIZE, TLB_SLOT_BYTES = 256, 32
local VALUE = 0x0102030405060708
local STORE_VALUE = 0x123456789abcdef

local cases = {
    { name = "WRITE slot for PMAs", set = TLB_WRITE, target = cartesi.AR_PMAS_START, insn = 0x00b53023, fault = 7 },
    {
        name = "WRITE slot for read-only flash",
        set = TLB_WRITE,
        target = DRIVE_START,
        insn = 0x00b53023,
        fault = 7,
        read_only = true,
    },
    { name = "CODE slot for flash", set = TLB_CODE, target = DRIVE_START, insn = 0x02a00613, fault = 1 },
    {
        name = "READ slot for read-only flash",
        set = TLB_READ,
        target = DRIVE_START,
        insn = 0x00053603,
        read_only = true,
    },
    { name = "WRITE slot for writable flash", set = TLB_WRITE, target = DRIVE_START, insn = 0x00b53023 },
    { name = "CODE slot for RAM", set = TLB_CODE, target = RAM_START, insn = 0x02a00613 },
}

local function install_shadow_tlb_slot(machine, set_index, paddr)
    local pmas = machine:read_memory(cartesi.AR_PMAS_START, cartesi.AR_PMAS_LENGTH)
    local pma_index
    for index = 0, #pmas // 16 - 1 do
        local istart = string.unpack("<I8", pmas, 1 + index * 16)
        if (istart & 1) ~= 0 and (istart & ~0xfff) == paddr then
            pma_index = index
            break
        end
    end
    assert(pma_index, "target PMA not found")
    local slot_index = (paddr >> 12) & (TLB_SET_SIZE - 1)
    local offset = cartesi.AR_SHADOW_TLB_START
        - cartesi.AR_SHADOW_STATE_START
        + (set_index * TLB_SET_SIZE + slot_index) * TLB_SLOT_BYTES
    local shadow = machine:read_memory(cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_STATE_LENGTH)
    local slot = string.pack("<I8I8I8I8", paddr, 0, pma_index, 0)
    machine:write_memory(cartesi.AR_SHADOW_STATE_START, shadow:sub(1, offset) .. slot .. shadow:sub(offset + #slot + 1))
end

local function create_machine(case, hash_function, data_filename, cached)
    local machine = cartesi.machine({
        ram = { length = 4096 },
        flash_drive = {
            {
                start = DRIVE_START,
                length = 4096,
                read_only = case.read_only or false,
                backing_store = { data_filename = data_filename },
            },
        },
        hash_tree = { hash_function = hash_function },
        processor = {
            registers = {
                pc = case.set == TLB_CODE and case.target or RAM_START,
                mtvec = MTVEC,
                x10 = case.target,
                x11 = STORE_VALUE,
                x12 = 0x99,
            },
        },
    })
    machine:write_memory(RAM_START, string.pack("<I4", case.insn))
    machine:write_memory(MTVEC, string.pack("<I4", 0x0000006f)) -- jal x0,0
    if cached then
        install_shadow_tlb_slot(machine, case.set, case.target)
    end
    return machine
end

local function expect_access_result(machine, case, before)
    expect.equal(machine:read_reg("mcycle"), 1)
    if case.fault then
        expect.equal(machine:read_reg("mcause"), case.fault)
        expect.equal(machine:read_reg("mtval"), case.target)
        expect.equal(machine:read_reg("mepc"), case.set == TLB_CODE and case.target or RAM_START)
        expect.equal(machine:read_reg("pc"), MTVEC)
        expect.equal(machine:read_reg("x12"), 0x99)
        expect.equal(machine:read_memory(case.target, 8), before)
    elseif case.set == TLB_WRITE then
        expect.equal(machine:read_memory(case.target, 8), string.pack("<I8", STORE_VALUE))
    else
        expect.equal(machine:read_reg("x12"), case.set == TLB_CODE and 42 or VALUE)
    end
end

describe("shadow TLB permissions", function()
    for _, hash_function in ipairs({ "keccak256", "sha256" }) do
        describe(hash_function, function()
            for _, stored in ipairs({ false, true }) do
                describe(stored and "stored" or "created", function()
                    for _, case in ipairs(cases) do
                        it(case.name, function()
                            local data = case.set == TLB_CODE and string.pack("<I4", case.insn)
                                or string.pack("<I8", VALUE)
                            local _ <close>, data_filename =
                                filesystem.write_scope_temp_file(data .. string.rep("\0", 4096 - #data))
                            local reference <close> = create_machine(case, hash_function, data_filename, false)
                            local before = reference:read_memory(case.target, 8)
                            expect.equal(reference:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                            expect_access_result(reference, case, before)

                            local source <close> = create_machine(case, hash_function, data_filename, true)
                            local directory = filesystem.temp_pathname()
                            local _ <close> = tests_util.scope_exit(function()
                                if stored then
                                    cartesi.machine:remove_stored(directory)
                                end
                            end)
                            if stored then
                                source:store(directory)
                            end
                            local run <close> = stored and cartesi.machine(directory, {}, cartesi.SHARING_NONE)
                                or create_machine(case, hash_function, data_filename, true)
                            local initial_hash = run:get_root_hash()
                            expect.equal(initial_hash, source:get_root_hash())
                            if hash_function == "keccak256" then
                                expect.equal(
                                    run:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE),
                                    cartesi.UARCH_PRISTINE_STATE_HASH
                                )
                            end
                            expect.equal(run:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                            expect_access_result(run, case, before)
                            local expected_hash = run:get_root_hash()
                            expect.equal(expected_hash, tests_util.calculate_emulator_hash(run))

                            local logged <close> = stored and cartesi.machine(directory, {}, cartesi.SHARING_NONE)
                                or create_machine(case, hash_function, data_filename, true)
                            expect.equal(logged:get_root_hash(), initial_hash)
                            local filename = filesystem.temp_pathname()
                            local _ <close> = tests_util.scope_exit(function()
                                os.remove(filename)
                            end)
                            expect.equal(logged:log_step(1, filename), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                            expect.equal(logged:get_root_hash(), expected_hash)
                            expect.equal(logged:verify_step(initial_hash, filename, 1), expected_hash)

                            local collected <close> = stored and cartesi.machine(directory, {}, cartesi.SHARING_NONE)
                                or create_machine(case, hash_function, data_filename, true)
                            local result = collected:collect_mcycle_root_hashes(1, 0)
                            expect.equal(result.break_reason, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                            expect.equal(result.hashes, { expected_hash })

                            if hash_function == "keccak256" then
                                local uarch <close> = stored and cartesi.machine(directory, {}, cartesi.SHARING_NONE)
                                    or create_machine(case, hash_function, data_filename, true)
                                expect.equal(uarch:run_uarch(math.maxinteger), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
                                local before_reset = uarch:get_root_hash()
                                local log = uarch:log_reset_uarch()
                                expect.equal(uarch:verify_reset_uarch(before_reset, log), expected_hash)
                                expect.equal(uarch:get_root_hash(), expected_hash)
                            end
                        end)
                    end
                end)
            end
        end)
    end
end)

os.exit(lester.report())
