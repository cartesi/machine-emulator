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
local filesystem = require("cartesi.filesystem")
local tests_util = require("cartesi.tests.util")

local MAX_MCYCLE = cartesi.MCYCLE_MAX
local MAX_UARCH_CYCLE = cartesi.UARCH_CYCLE_MAX

local function build_machine()
    local config = {
        ram = {
            length = 32 << 20,
            backing_store = {
                data_filename = tests_util.tests_path .. "mcycle_overflow.bin",
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
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("mcycle") == MAX_MCYCLE)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
end)

do_test("machine run at the overflow cycle should report overflow without changing state", function(machine)
    machine:write_reg("mcycle", MAX_MCYCLE)
    local hash_before = machine:get_root_hash()
    assert(machine:run(MAX_MCYCLE) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:get_root_hash() == hash_before)
end)

do_test("machine should stop exactly at a nearby mcycle limit", function(machine)
    local mcycle_limit = machine:read_reg("mcycle") + 5
    machine:write_reg("imcyclemax", mcycle_limit)
    assert(machine:run(mcycle_limit - 1) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:read_reg("mcycle") == mcycle_limit - 1)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:run(mcycle_limit) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("mcycle") == mcycle_limit)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:run(mcycle_limit + 1) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
end)

do_test("mcycle past the limit should overflow without advancing", function(machine)
    local mcycle = machine:read_reg("mcycle")
    machine:write_reg("imcyclemax", mcycle - 1)
    local hash_before = machine:get_root_hash()
    assert(machine:run(mcycle) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:get_root_hash() == hash_before)
    assert(machine:run(mcycle + 1) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("mcycle") == mcycle)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:run(mcycle + 1) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
end)

do_test("mcycle overflow should take precedence over halt and yield", function(machine)
    local mcycle = machine:read_reg("mcycle")
    machine:write_reg("imcyclemax", mcycle)
    machine:write_reg("iflags_H", 1)
    machine:write_reg("iflags_Y", 1)
    local hash_before = machine:get_root_hash()
    assert(machine:run(mcycle) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:get_root_hash() == hash_before)
    assert(machine:read_reg("iflags_H") == 1)
    assert(machine:read_reg("iflags_Y") == 1)
end)

do_test("same-target run should report existing halt or manual yield", function(machine)
    local mcycle = machine:read_reg("mcycle")
    machine:write_reg("iflags_H", 1)
    local halted_hash = machine:get_root_hash()
    assert(machine:run(mcycle) == cartesi.BREAK_REASON_HALTED)
    assert(machine:get_root_hash() == halted_hash)

    machine:write_reg("iflags_H", 0)
    machine:write_reg("iflags_Y", 1)
    local yielded_hash = machine:get_root_hash()
    assert(machine:run(mcycle) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    assert(machine:get_root_hash() == yielded_hash)
end)

do_test("logged mcycle steps should preserve target and overflow semantics", function(machine)
    local mcycle = machine:read_reg("mcycle")
    machine:write_reg("imcyclemax", mcycle)

    local zero_step_filename = filesystem.temp_pathname()
    local overflow_step_filename = filesystem.temp_pathname()
    local _ <close> = tests_util.scope_exit(function()
        os.remove(zero_step_filename)
        os.remove(overflow_step_filename)
    end)

    local root_hash_before = machine:get_root_hash()
    assert(machine:log_step(0, zero_step_filename) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:get_root_hash() == root_hash_before)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:verify_step(root_hash_before, zero_step_filename, 0) == root_hash_before)

    assert(machine:log_step(1, overflow_step_filename) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    local root_hash_after = machine:get_root_hash()
    assert(machine:read_reg("mcycle") == mcycle)
    assert(machine:read_reg("iflags_H") == 0)
    assert(root_hash_after == root_hash_before)
    assert(machine:verify_step(root_hash_before, overflow_step_filename, 1) == root_hash_after)
end)

do_test("logged mcycle step should do nothing at max mcycle", function(machine)
    machine:write_reg("mcycle", MAX_MCYCLE)
    local step_filename = filesystem.temp_pathname()
    local _ <close> = tests_util.scope_exit(function()
        os.remove(step_filename)
    end)

    local root_hash = machine:get_root_hash()
    assert(machine:log_step(1, step_filename) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("mcycle") == MAX_MCYCLE)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:get_root_hash() == root_hash)
    assert(machine:verify_step(root_hash, step_filename, 1) == root_hash)
end)

do_test("logged mcycle step should overflow from one cycle before max mcycle", function(machine)
    machine:write_reg("mcycle", MAX_MCYCLE - 1)
    local step_filename = filesystem.temp_pathname()
    local _ <close> = tests_util.scope_exit(function()
        os.remove(step_filename)
    end)

    local root_hash_before = machine:get_root_hash()
    assert(machine:log_step(1, step_filename) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    local root_hash_after = machine:get_root_hash()
    assert(machine:read_reg("mcycle") == MAX_MCYCLE)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:verify_step(root_hash_before, step_filename, 1) == root_hash_after)
end)

do_test("run_uarch should report overflow without changing halt at max uarch_cycle", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    assert(machine:run_uarch(MAX_UARCH_CYCLE) == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW)
    assert(machine:read_reg("uarch_halt") == 0)
    assert(machine:run_uarch(MAX_UARCH_CYCLE + 1) == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_halt") == 0)
    assert(machine:run_uarch(MAX_UARCH_CYCLE + 1) == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW)
end)

do_test("uarch overflow should take precedence over halt", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    machine:write_reg("uarch_halt", 1)
    local hash_before = machine:get_root_hash()
    assert(machine:run_uarch(MAX_UARCH_CYCLE) == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW)
    assert(machine:get_root_hash() == hash_before)
    assert(machine:read_reg("uarch_halt") == 1)
end)

do_test("logged uarch step should preserve state at max uarch cycle", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    local hash_before = machine:get_root_hash()
    local filename = os.tmpname()
    os.remove(filename)
    machine:log_step_uarch(1, filename)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_halt") == 0)
    local hash_after = machine:get_root_hash()
    assert(hash_before == hash_after)
    assert(machine:verify_step_uarch(hash_before, filename, 1) == hash_after)
    os.remove(filename)
end)

print("passed all")
