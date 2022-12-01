#!/usr/bin/env lua5.3

-- Copyright 2019 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local cartesi = require"cartesi"
local test_util = require "tests.util"

-- There is no UINT64_MAX in Lua, so we have to use the signed representation
local MAX_MCYCLE = -1

local function build_machine()
    local config =  {
        processor = {
            -- Request automatic default values for versioning CSRs
            mimpid = -1,
            marchid = -1,
            mvendorid = -1
        },
        rom = {
            image_filename = test_util.tests_path .. "bootstrap.bin"
        },
        ram = {
            image_filename = test_util.tests_path .. "mcycle_overflow.bin",
            length = 32 << 20,
        },
    }
    local machine = cartesi.machine(config)

    -- Stop the machine before the first RAM instruction
    local wfi_cycle = 7
    assert(machine:run(wfi_cycle) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)

    return machine
end

local function do_test(description, f)
    io.write("  " .. description .. "...")
    local machine = build_machine()
    f(machine)
    machine:destroy()
    print(" passed")
end

print("testing mcycle overflow")

do_test("machine should run up to mcycle limit", function(machine)
    machine:write_mcycle(MAX_MCYCLE - 5)
    -- Run once to trigger an interrupt, which might cause an overflow on the
    -- next call to machine:run
    assert(machine:run(MAX_MCYCLE - 4) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:read_mcycle() == MAX_MCYCLE)
end)

do_test("machine run shouldn't change state in max mcycle", function(machine)
    machine:write_mcycle(MAX_MCYCLE)
    local hash_before = machine:get_root_hash()
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    local hash_after = machine:get_root_hash()
    assert(hash_before == hash_after)
end)

for _, proofs in ipairs{true, false} do
    test_util.disabled_test("machine step should do nothing on max mcycle [proofs=" ..
            tostring(proofs) .. "]", function(machine)
        machine:write_mcycle(MAX_MCYCLE)
        local log = machine:step{proofs=proofs}
        assert(machine:read_mcycle() == MAX_MCYCLE)
        assert(#log.accesses == 1)
        assert(log.accesses[1].type == "read")
        assert(log.accesses[1].address == 0x228)
        assert(log.accesses[1].read == string.pack('J', MAX_MCYCLE))
        assert((log.accesses[1].proof ~= nil) == proofs)
    end)
end

print("passed all")
