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

local function build_machine()
    local machine_config = {
        ram = {
            image_filename = test_util.tests_path .. "mtime_interrupt.bin",
            length = 32 << 20,
        },
    }
    return cartesi.machine(machine_config)
end

local function do_test(description, f)
    io.write("  " .. description .. "...")
    local machine <close> = build_machine()
    f(machine)
    print(" passed")
end

local RTC_FREQ_DIV = 8192
local EXPECTED_MCYCLE = RTC_FREQ_DIV * 2 + 20

local function check_state(machine)
    assert(machine:read_iflags_H(), "machine did not halt")
    assert(machine:read_htif_tohost_data() >> 1 == 0, "invalid return code")
    assert(machine:read_mcycle() == EXPECTED_MCYCLE, "invalid mcycle")
end

print("testing mtime interrupt")

do_test("machine:run should interrupt for mtime", function(machine)
    for _ = 1, EXPECTED_MCYCLE do
        machine:run(-1)
        if machine:read_iflags_H() then
            break
        end
    end
    check_state(machine)
end)

test_util.disabled_test("machine:log_step_uarch should interrupt for mtime", function(machine)
    for _ = 1, EXPECTED_MCYCLE do
        machine:log_step_uarch({})
        if machine:read_iflags_H() then
            break
        end
    end
    check_state(machine)
end)

print("passed")
