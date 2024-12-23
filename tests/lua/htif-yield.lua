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

local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s [options]

where options are:

  --test-path=<dir>
    path to test binaries
    (default: environment $CARTESI_TESTS_PATH)

  --uarch-test
    use microarchitecture to run tests

  --uarch-ram-image=<filename>
    name of file containing microarchitecture RAM image.

]=],
        arg[0]
    ))
    os.exit()
end

local uarch
local run_with_uarch = false
local test_path = test_util.tests_path

-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    {
        "^%-%-help$",
        function(all)
            if not all then
                return false
            end
            help()
        end,
    },
    {
        "^%-%-uarch$",
        function(all)
            if not all then
                return false
            end
            run_with_uarch = true
            return true
        end,
    },
    {
        "^%-%-uarch%-ram%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            uarch = uarch or {}
            uarch.ram = uarch.ram or {}
            uarch.ram.image_filename = o
            return true
        end,
    },
    {
        "^%-%-test%-path%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            test_path = o
            return true
        end,
    },
    {
        ".*",
        function(all)
            error("unrecognized option " .. all .. ". Use --help to obtain a list of supported options.")
        end,
    },
}

-- Process command line options
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    end
end

-- Config yields 5 times with progress
local config = {
    ram = {
        image_filename = test_path .. "/htif_yield.bin",
        length = 0x4000000,
    },
}

if uarch then
    config.uarch = uarch
end

local YIELD_MANUAL = cartesi.CMIO_YIELD_COMMAND_MANUAL
local YIELD_AUTOMATIC = cartesi.CMIO_YIELD_COMMAND_AUTOMATIC

local REASON_PROGRESS = cartesi.CMIO_YIELD_AUTOMATIC_REASON_PROGRESS
local REASON_TX_OUTPUT = cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_OUTPUT
local REASON_TX_REPORT = cartesi.CMIO_YIELD_AUTOMATIC_REASON_TX_REPORT
local REASON_RX_ACCEPTED = cartesi.CMIO_YIELD_MANUAL_REASON_RX_ACCEPTED
local REASON_RX_REJECTED = cartesi.CMIO_YIELD_MANUAL_REASON_RX_REJECTED
local REASON_TX_EXCEPTION = cartesi.CMIO_YIELD_MANUAL_REASON_TX_EXCEPTION

local yields = {
    { mcycle = 10, data = 10, cmd = YIELD_MANUAL, reason = REASON_PROGRESS },
    { mcycle = 42, data = 11, cmd = YIELD_MANUAL, reason = REASON_PROGRESS },
    { mcycle = 74, data = 12, cmd = YIELD_MANUAL, reason = REASON_PROGRESS },
    { mcycle = 106, data = 13, cmd = YIELD_MANUAL, reason = REASON_RX_ACCEPTED },
    { mcycle = 138, data = 14, cmd = YIELD_MANUAL, reason = REASON_RX_REJECTED },
    { mcycle = 170, data = 15, cmd = YIELD_MANUAL, reason = REASON_TX_OUTPUT },
    { mcycle = 202, data = 16, cmd = YIELD_MANUAL, reason = REASON_TX_REPORT },
    { mcycle = 234, data = 17, cmd = YIELD_MANUAL, reason = REASON_TX_EXCEPTION },

    { mcycle = 266, data = 20, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS },
    { mcycle = 298, data = 21, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS },
    { mcycle = 330, data = 22, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS },
    { mcycle = 362, data = 23, cmd = YIELD_AUTOMATIC, reason = REASON_RX_ACCEPTED },
    { mcycle = 394, data = 24, cmd = YIELD_AUTOMATIC, reason = REASON_RX_REJECTED },
    { mcycle = 426, data = 25, cmd = YIELD_AUTOMATIC, reason = REASON_TX_OUTPUT },
    { mcycle = 458, data = 26, cmd = YIELD_AUTOMATIC, reason = REASON_TX_REPORT },
}

local function run_machine_with_uarch(machine)
    -- mimics "machine:run()" using the microarchitecture
    while true do
        local ubr = machine:run_uarch()
        if ubr == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
            machine:reset_uarch()
            if machine:read_reg("iflags_H") ~= 0 then
                -- iflags.H was set during the last mcycle
                return cartesi.BREAK_REASON_HALTED
            end
            if machine:read_reg("iflags_Y") ~= 0 then
                -- iflags.Y was set during the last mcycle
                return cartesi.BREAK_REASON_YIELDED_MANUALLY
            end
            if machine:read_reg("iflags_X") ~= 0 then
                -- machine was yielded with automatic reset. iflags.X will be cleared on the next mcycle
                return cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            end
        end
    end
end

local function run_machine(machine)
    if run_with_uarch then
        return run_machine_with_uarch(machine)
    end
    return machine:run()
end

local function stderr(...)
    io.stderr:write(string.format(...))
end

local final_mcycle = 500
local exit_payload = 42
local progress_enable = false

local function test(machine_config, yield_automatic_enable, yield_manual_enable)
    stderr(
        "  testing yield_automatic:%s yield_manual:%s\n",
        yield_automatic_enable and "on" or "off",
        yield_manual_enable and "on" or "off"
    )
    machine_config.htif = {
        yield_automatic = yield_automatic_enable,
        yield_manual = yield_manual_enable,
    }
    local machine <close> = cartesi.machine(machine_config)
    for _, v in ipairs(yields) do
        if
            (v.reason == REASON_PROGRESS and progress_enable)
            or (v.cmd == YIELD_MANUAL and yield_manual_enable)
            or (v.cmd == YIELD_AUTOMATIC and yield_automatic_enable)
        then
            local break_reason = run_machine(machine)

            -- mcycle should be as expected
            local mcycle = machine:read_reg("mcycle")
            assert(mcycle == v.mcycle, string.format("mcycle: expected %d, got %d", v.mcycle, mcycle))

            if yield_automatic_enable and v.cmd == YIELD_AUTOMATIC then
                assert(
                    break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY,
                    "expected break reason yielded automatically"
                )
                assert(machine:read_reg("iflags_X") ~= 0, "expected iflags_X set")
                assert(machine:read_reg("iflags_Y") == 0, "expected iflags_Y not set")
            elseif yield_manual_enable and v.cmd == YIELD_MANUAL then
                assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "expected break reason yielded manually")
                assert(machine:read_reg("iflags_Y") ~= 0, "expected iflags_Y set")
                assert(machine:read_reg("iflags_X") == 0, "expected iflags_X not set")
            else
                assert(false)
            end

            -- data should be as expected
            local data = machine:read_reg("htif_tohost_data")
            local reason = machine:read_reg("htif_tohost_reason")
            assert(data == v.data, string.format("data: expected %d, got %d", v.data, data))
            assert(reason == v.reason, string.format("reason: expected %d, got %d", v.reason, reason))
            -- cmd should be as expected
            assert(machine:read_reg("htif_tohost_cmd") == v.cmd)
            -- trying to run it without resetting iflags.Y should not advance
            if machine:read_reg("iflags_Y") ~= 0 then
                run_machine(machine)
                assert(mcycle == machine:read_reg("mcycle"))
                assert(machine:read_reg("iflags_Y") ~= 0)
            end
            -- now reset it so the machine can be advanced
            machine:write_reg("iflags_Y", 0)
        end
    end
    -- finally run to completion
    local break_reason = run_machine(machine)
    -- should be halted
    assert(break_reason == cartesi.BREAK_REASON_HALTED)
    assert(machine:read_reg("iflags_H") ~= 0, "expected iflags_H set")
    -- at the expected mcycle
    assert(
        machine:read_reg("mcycle") == final_mcycle,
        string.format("mcycle: expected, %u got %u", final_mcycle, machine:read_reg("mcycle"))
    )
    -- with the expected payload
    assert(
        (machine:read_reg("htif_tohost_data") >> 1) == exit_payload,
        string.format("exit payload: expected %u, got %u\n", exit_payload, machine:read_reg("htif_tohost_data") >> 1)
    )
    stderr("    passed\n")
end

stderr("testing yield sink\n")

for _, auto in ipairs({ true, false }) do
    for _, manual in ipairs({ true, false }) do
        test(config, auto, manual)
    end
end
