#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")

local MAX_MCYCLE = cartesi.MCYCLE_MAX
local MAX_UARCH_CYCLE = cartesi.UARCH_CYCLE_MAX

local function build_machine()
    local config = {
        ram = {
            length = 32 << 20,
            backing_store = {
                data_filename = test_util.tests_path .. "mcycle_overflow.bin",
            },
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
    local machine <close> = build_machine()
    f(machine)
    print(" passed")
end

print("testing mcycle overflow")

do_test("machine should run up to mcycle limit", function(machine)
    machine:write_reg("mcycle", MAX_MCYCLE - 5)
    -- Run once to trigger an interrupt, which might cause an overflow on the
    -- next call to machine:run
    assert(machine:run(MAX_MCYCLE - 4) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:read_reg("mcycle") == MAX_MCYCLE)
end)

do_test("machine run shouldn't change state in max mcycle", function(machine)
    machine:write_reg("mcycle", MAX_MCYCLE)
    local hash_before = machine:get_root_hash()
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    local hash_after = machine:get_root_hash()
    assert(hash_before == hash_after)
end)

do_test("run_uarch shouldn't change state at max uarch_cycle", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local hash_before = machine:get_root_hash()
    assert(machine:run_uarch(MAX_UARCH_CYCLE) == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_CYCLE)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local hash_after = machine:get_root_hash()
    assert(hash_before == hash_after)
end)

do_test("machine step should do nothing on max mcycle", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    local hash_before = machine:get_root_hash()
    local filename = os.tmpname()
    os.remove(filename)
    machine:log_step_uarch(1, filename)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local hash_after = machine:get_root_hash()
    assert(hash_before == hash_after)
    machine:verify_step_uarch(hash_before, filename, 1, hash_after)
    os.remove(filename)
end)

print("passed all")
