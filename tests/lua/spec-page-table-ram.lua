-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Page tables live only in RAM, the only range whose PMAs support page-table walks. A page-table walk
-- that reaches a page-table entry outside RAM raises the access fault of the original access type,
-- and leaves the entry unchanged.

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")
local tests_util = require("cartesi.tests.util")

local RAM_START = cartesi.AR_RAM_START
local RAM_LENGTH = 0x10000
local DRIVE_START = 0x90000000
local MTVEC = RAM_START + 0x100
local HOLE = 0x200000000 -- No address range covers it

-- A gigapage at this virtual address maps the start of RAM
local VA = 0x40000000
local DATA_OFFSET = 0x1000
local ROOT_IN_RAM = RAM_START + 0x2000
local VALUE = 0x0102030405060708
local STORE_VALUE = 0x123456789abcdef

local PTE_V, PTE_R, PTE_W, PTE_X, PTE_A, PTE_D = 1, 2, 4, 8, 64, 128
local MSTATUS_MPRV = 1 << 17
local MSTATUS_MPP_S = 1 << 11
local SATP_SV39 = 8 << 60

-- The leaf PTE, with A and D clear, and its index in the root table
local LEAF = ((RAM_START >> 12) << 10) | PTE_V | PTE_R | PTE_W | PTE_X
local LEAF_OFFSET = ((VA >> 30) & 0x1ff) * 8

local accesses = {
    -- Fetches run in S-mode, so the fetch itself is translated
    fetch = { insn = 0x02a00613, fault = 1, tval = VA, ad = PTE_A }, -- addi x12,x0,42
    -- Loads and stores run in M-mode with MPRV, so only the data access is translated
    load = { insn = 0x00053603, fault = 5, tval = VA + DATA_OFFSET, ad = PTE_A }, -- ld x12,0(x10)
    store = { insn = 0x00b53023, fault = 7, tval = VA + DATA_OFFSET, ad = PTE_A | PTE_D }, -- sd x11,0(x10)
}

local tables = {
    { name = "RAM", root = ROOT_IN_RAM },
    { name = "a writable flash drive", root = DRIVE_START, drive = true, read_only = false },
    { name = "a read-only flash drive", root = DRIVE_START, drive = true, read_only = true },
    { name = "the CLINT", root = cartesi.AR_CLINT_START },
    { name = "a hole", root = HOLE },
}

local function create_machine(access, table_case, data_filename)
    local registers = {
        mtvec = MTVEC,
        satp = SATP_SV39 | (table_case.root >> 12),
        x10 = VA + DATA_OFFSET,
        x11 = STORE_VALUE,
        x12 = 0x99,
    }
    if access == "fetch" then
        registers.iprv = 1
        registers.pc = VA
    else
        registers.pc = RAM_START
        registers.mstatus = MSTATUS_MPRV | MSTATUS_MPP_S
    end
    local config = { ram = { length = RAM_LENGTH }, processor = { registers = registers } }
    if table_case.drive then
        config.flash_drive = {
            {
                start = DRIVE_START,
                length = 4096,
                read_only = table_case.read_only,
                backing_store = { data_filename = data_filename },
            },
        }
    end
    local machine = cartesi.machine(config)
    machine:write_memory(RAM_START, string.pack("<I4", accesses[access].insn))
    machine:write_memory(MTVEC, string.pack("<I4", 0x0000006f)) -- jal x0,0
    machine:write_memory(RAM_START + DATA_OFFSET, string.pack("<I8", VALUE))
    if table_case.root == ROOT_IN_RAM then
        machine:write_memory(ROOT_IN_RAM + LEAF_OFFSET, string.pack("<I8", LEAF))
    end
    return machine
end

local function expect_result(machine, access, table_case)
    local case = accesses[access]
    expect.equal(machine:read_reg("mcycle"), 1)
    if table_case.root == ROOT_IN_RAM then
        -- The walk succeeds and sets the A bit, and the D bit for a store
        expect.equal(string.unpack("<I8", machine:read_memory(ROOT_IN_RAM + LEAF_OFFSET, 8)), LEAF | case.ad)
        if access == "fetch" then
            expect.equal(machine:read_reg("x12"), 42)
        elseif access == "load" then
            expect.equal(machine:read_reg("x12"), VALUE)
        else
            expect.equal(machine:read_memory(RAM_START + DATA_OFFSET, 8), string.pack("<I8", STORE_VALUE))
        end
        return
    end
    -- The walk stops at the root entry, outside RAM, with the access fault
    expect.equal(machine:read_reg("mcause"), case.fault)
    expect.equal(machine:read_reg("mtval"), case.tval)
    expect.equal(machine:read_reg("pc"), MTVEC)
    expect.equal(machine:read_reg("x12"), 0x99)
    expect.equal(machine:read_memory(RAM_START + DATA_OFFSET, 8), string.pack("<I8", VALUE))
    if table_case.drive then
        expect.equal(string.unpack("<I8", machine:read_memory(DRIVE_START + LEAF_OFFSET, 8)), LEAF)
    end
end

describe("page tables outside RAM", function()
    for _, table_case in ipairs(tables) do
        for _, access in ipairs({ "fetch", "load", "store" }) do
            it(access .. " through page tables in " .. table_case.name, function()
                local root = string.rep("\0", LEAF_OFFSET) .. string.pack("<I8", LEAF)
                local _ <close>, data_filename =
                    filesystem.write_scope_temp_file(root .. string.rep("\0", 4096 - #root))

                local native <close> = create_machine(access, table_case, data_filename)
                local initial_hash = native:get_root_hash()
                expect.equal(native:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect_result(native, access, table_case)
                local expected_hash = native:get_root_hash()

                local logged <close> = create_machine(access, table_case, data_filename)
                local _ <close>, filename = tests_util.scope_temp_pathname()
                expect.equal(logged:log_step(1, filename), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect.equal(logged:verify_step(initial_hash, filename, 1), expected_hash)

                local uarch <close> = create_machine(access, table_case, data_filename)
                expect.equal(uarch:run_uarch(math.maxinteger), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
                local before_reset = uarch:get_root_hash()
                local log = uarch:log_reset_uarch()
                expect.equal(uarch:verify_reset_uarch(before_reset, log), expected_hash)
                expect_result(uarch, access, table_case)
            end)
        end
    end
end)

lester.report()
lester.exit()
