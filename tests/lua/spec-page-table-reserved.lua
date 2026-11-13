-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- For non-leaf page-table entries, the D, A, and U bits are reserved. A page-table walk that reaches a non-leaf entry
-- with any of them set raises the page fault of the original access type, and leaves the entries unchanged.

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local cartesi = require("cartesi")
local tests_util = require("cartesi.tests.util")

local RAM_START = cartesi.AR_RAM_START
local RAM_LENGTH = 0x10000
local MTVEC = RAM_START + 0x100

-- A non-leaf entry in the root table points to a second table, whose leaf maps a megapage at the start of RAM
local VA = 0x40000000
local DATA_OFFSET = 0x1000
local ROOT = RAM_START + 0x2000
local TABLE = RAM_START + 0x3000
local VALUE = 0x0102030405060708
local STORE_VALUE = 0x123456789abcdef

local PTE_V, PTE_R, PTE_W, PTE_X, PTE_U, PTE_A, PTE_D = 1, 2, 4, 8, 16, 64, 128
local MSTATUS_MPRV = 1 << 17
local MSTATUS_MPP_S = 1 << 11
local SATP_SV39 = 8 << 60

-- The entries, with A and D clear, and their offsets in their tables
local NON_LEAF = ((TABLE >> 12) << 10) | PTE_V
local NON_LEAF_ADDR = ROOT + ((VA >> 30) & 0x1ff) * 8
local LEAF = ((RAM_START >> 12) << 10) | PTE_V | PTE_R | PTE_W | PTE_X
local LEAF_ADDR = TABLE + ((VA >> 21) & 0x1ff) * 8

local accesses = {
    -- Fetches run in S-mode, so the fetch itself is translated
    fetch = { insn = 0x02a00613, fault = 12, tval = VA, ad = PTE_A }, -- addi x12,x0,42
    -- Loads and stores run in M-mode with MPRV, so only the data access is translated
    load = { insn = 0x00053603, fault = 13, tval = VA + DATA_OFFSET, ad = PTE_A }, -- ld x12,0(x10)
    store = { insn = 0x00b53023, fault = 15, tval = VA + DATA_OFFSET, ad = PTE_A | PTE_D }, -- sd x11,0(x10)
}

local reserved = {
    { name = "no reserved bit", bit = 0 },
    { name = "A", bit = PTE_A },
    { name = "D", bit = PTE_D },
    { name = "U", bit = PTE_U },
}

local function read_pte(machine, addr)
    return (string.unpack("<I8", machine:read_memory(addr, 8)))
end

local function create_machine(access, bit)
    local registers = {
        mtvec = MTVEC,
        satp = SATP_SV39 | (ROOT >> 12),
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
    local machine = cartesi.machine({ ram = { length = RAM_LENGTH }, processor = { registers = registers } })
    machine:write_memory(RAM_START, string.pack("<I4", accesses[access].insn))
    machine:write_memory(MTVEC, string.pack("<I4", 0x0000006f)) -- jal x0,0
    machine:write_memory(RAM_START + DATA_OFFSET, string.pack("<I8", VALUE))
    machine:write_memory(NON_LEAF_ADDR, string.pack("<I8", NON_LEAF | bit))
    machine:write_memory(LEAF_ADDR, string.pack("<I8", LEAF))
    return machine
end

local function expect_result(machine, access, bit)
    local case = accesses[access]
    expect.equal(machine:read_reg("mcycle"), 1)
    expect.equal(read_pte(machine, NON_LEAF_ADDR), NON_LEAF | bit)
    if bit == 0 then
        -- The walk succeeds and sets the A bit of the leaf, and the D bit for a store
        expect.equal(read_pte(machine, LEAF_ADDR), LEAF | case.ad)
        if access == "fetch" then
            expect.equal(machine:read_reg("x12"), 42)
        elseif access == "load" then
            expect.equal(machine:read_reg("x12"), VALUE)
        else
            expect.equal(machine:read_memory(RAM_START + DATA_OFFSET, 8), string.pack("<I8", STORE_VALUE))
        end
        return
    end
    -- The walk stops at the non-leaf entry with the page fault
    expect.equal(machine:read_reg("mcause"), case.fault)
    expect.equal(machine:read_reg("mtval"), case.tval)
    expect.equal(machine:read_reg("pc"), MTVEC)
    expect.equal(machine:read_reg("x12"), 0x99)
    expect.equal(machine:read_memory(RAM_START + DATA_OFFSET, 8), string.pack("<I8", VALUE))
    expect.equal(read_pte(machine, LEAF_ADDR), LEAF)
end

describe("reserved bits in non-leaf page-table entries", function()
    for _, r in ipairs(reserved) do
        for _, access in ipairs({ "fetch", "load", "store" }) do
            it(access .. " through a non-leaf entry with " .. r.name, function()
                local native <close> = create_machine(access, r.bit)
                local initial_hash = native:get_root_hash()
                expect.equal(native:run(1), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect_result(native, access, r.bit)
                local expected_hash = native:get_root_hash()

                local logged <close> = create_machine(access, r.bit)
                local _ <close>, filename = tests_util.scope_temp_pathname()
                expect.equal(logged:log_step(1, filename), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
                expect.equal(logged:verify_step(initial_hash, filename, 1), expected_hash)

                local uarch <close> = create_machine(access, r.bit)
                expect.equal(uarch:run_uarch(math.maxinteger), cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
                local before_reset = uarch:get_root_hash()
                local log = uarch:log_reset_uarch()
                expect.equal(uarch:verify_reset_uarch(before_reset, log), expected_hash)
                expect_result(uarch, access, r.bit)
            end)
        end
    end
end)

lester.report()
lester.exit()
