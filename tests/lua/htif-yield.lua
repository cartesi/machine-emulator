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
            if not all then return false end
            help()
        end,
    },
    {
        "^%-%-uarch$",
        function(all)
            if not all then return false end
            run_with_uarch = true
            return true
        end,
    },
    {
        "^%-%-uarch%-ram%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            uarch = uarch or {}
            uarch.ram = uarch.ram or {}
            uarch.ram.image_filename = o
            return true
        end,
    },
    {
        "^%-%-test%-path%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            test_path = o
            return true
        end,
    },
    {
        ".*",
        function(all) error("unrecognized option " .. all .. ". Use --help to obtain a list of supported options.") end,
    },
}

-- Process command line options
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then break end
        end
    end
end

-- Config yields 5 times with progress
local config = {
    processor = {
        mvendorid = -1,
        mimpid = -1,
        marchid = -1,
    },
    ram = {
        image_filename = test_path .. "/htif_yield.bin",
        length = 0x4000000,
    },
}

if uarch then config.uarch = uarch end

local YIELD_MANUAL = cartesi.machine.HTIF_YIELD_MANUAL
local YIELD_AUTOMATIC = cartesi.machine.HTIF_YIELD_AUTOMATIC

local REASON_PROGRESS = cartesi.machine.HTIF_YIELD_REASON_PROGRESS
local REASON_RX_ACCEPTED = cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED
local REASON_RX_REJECTED = cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED
local REASON_TX_VOUCHER = cartesi.machine.HTIF_YIELD_REASON_TX_VOUCHER
local REASON_TX_NOTICE = cartesi.machine.HTIF_YIELD_REASON_TX_NOTICE
local REASON_TX_REPORT = cartesi.machine.HTIF_YIELD_REASON_TX_REPORT
local REASON_TX_EXCEPTION = cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION

local yields = {
    { mcycle = 9,   data = 10, cmd = YIELD_MANUAL,    reason = REASON_PROGRESS },
    { mcycle = 40,  data = 11, cmd = YIELD_MANUAL,    reason = REASON_PROGRESS },
    { mcycle = 71,  data = 12, cmd = YIELD_MANUAL,    reason = REASON_PROGRESS },
    { mcycle = 103, data = 13, cmd = YIELD_MANUAL,    reason = REASON_RX_ACCEPTED },
    { mcycle = 135, data = 14, cmd = YIELD_MANUAL,    reason = REASON_RX_REJECTED },
    { mcycle = 167, data = 15, cmd = YIELD_MANUAL,    reason = REASON_TX_VOUCHER },
    { mcycle = 199, data = 16, cmd = YIELD_MANUAL,    reason = REASON_TX_NOTICE },
    { mcycle = 231, data = 17, cmd = YIELD_MANUAL,    reason = REASON_TX_REPORT },
    { mcycle = 263, data = 18, cmd = YIELD_MANUAL,    reason = REASON_TX_EXCEPTION },

    { mcycle = 294, data = 20, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS },
    { mcycle = 325, data = 21, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS },
    { mcycle = 356, data = 22, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS },
    { mcycle = 388, data = 23, cmd = YIELD_AUTOMATIC, reason = REASON_RX_ACCEPTED },
    { mcycle = 420, data = 24, cmd = YIELD_AUTOMATIC, reason = REASON_RX_REJECTED },
    { mcycle = 452, data = 25, cmd = YIELD_AUTOMATIC, reason = REASON_TX_VOUCHER },
    { mcycle = 484, data = 26, cmd = YIELD_AUTOMATIC, reason = REASON_TX_NOTICE },
    { mcycle = 516, data = 27, cmd = YIELD_AUTOMATIC, reason = REASON_TX_REPORT },
}

local function run_machine_with_uarch(machine)
    -- mimics "machine:run()" using the microarchitecture
    while true do
        local ubr = machine:run_uarch()
        if ubr == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
            machine:reset_uarch()
            if machine:read_iflags_H() then
                -- iflags.H was set during the last mcycle
                return cartesi.BREAK_REASON_HALTED
            end
            if machine:read_iflags_Y() then
                -- iflags.Y was set during the last mcycle
                return cartesi.BREAK_REASON_YIELDED_MANUALLY
            end
            if machine:read_iflags_X() then
                -- machine was yielded with automatic reset. iflags.X will be cleared on the next mcycle
                return cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            end
        end
    end
end

local function run_machine(machine)
    if run_with_uarch then return run_machine_with_uarch(machine) end
    return machine:run()
end

local function stderr(...) io.stderr:write(string.format(...)) end

local final_mcycle = 557
local exit_payload = 42
local progress_enable = false

local function test(config, yield_automatic_enable, yield_manual_enable)
    stderr(
        "  testing yield_automatic:%s yield_manual:%s\n",
        yield_automatic_enable and "on" or "off",
        yield_manual_enable and "on" or "off"
    )
    config.htif = {
        yield_automatic = yield_automatic_enable,
        yield_manual = yield_manual_enable,
    }
    local machine <close> = cartesi.machine(config)
    local break_reason
    for _, v in ipairs(yields) do
        if
            (v.reason == REASON_PROGRESS and progress_enable)
            or (v.cmd == YIELD_MANUAL and yield_manual_enable)
            or (v.cmd == YIELD_AUTOMATIC and yield_automatic_enable)
        then
            while not machine:read_iflags_Y() and not machine:read_iflags_X() and not machine:read_iflags_H() do
                break_reason = run_machine(machine)
            end

            -- mcycle should be as expected
            local mcycle = machine:read_mcycle()
            assert(mcycle == v.mcycle, string.format("mcycle: expected %d, got %d", v.mcycle, mcycle))

            if yield_automatic_enable and v.cmd == YIELD_AUTOMATIC then
                assert(
                    break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY,
                    "expected break reason yielded automatically"
                )
                assert(machine:read_iflags_X(), "expected iflags_X set")
                assert(not machine:read_iflags_Y(), "expected iflags_Y not set")
            elseif yield_manual_enable and v.cmd == YIELD_MANUAL then
                assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "expected break reason yielded manually")
                assert(machine:read_iflags_Y(), "expected iflags_Y set")
                assert(not machine:read_iflags_X(), "expected iflags_X not set")
            else
                assert(false)
            end

            -- data should be as expected
            local data = machine:read_htif_tohost_data()
            local reason = data >> 32
            data = data << 32 >> 32
            assert(data == v.data, string.format("data: expected %d, got %d", v.data, data))
            assert(reason == v.reason)
            -- cmd should be as expected
            assert(machine:read_htif_tohost_cmd() == v.cmd)
            -- trying to run it without resetting iflags.Y should not advance
            if machine:read_iflags_Y() then
                run_machine(machine)
                assert(mcycle == machine:read_mcycle())
                assert(machine:read_iflags_Y())
            end
            -- now reset it so the machine can be advanced
            machine:reset_iflags_Y()
            machine:reset_iflags_X()
        end
    end
    -- finally run to completion
    while not machine:read_iflags_Y() and not machine:read_iflags_H() do
        break_reason = run_machine(machine)
    end
    -- should be halted
    assert(break_reason == cartesi.BREAK_REASON_HALTED)
    assert(machine:read_iflags_H(), "expected iflags_H set")
    -- at the expected mcycle
    assert(
        machine:read_mcycle() == final_mcycle,
        string.format("mcycle: expected, %u got %u", final_mcycle, machine:read_mcycle())
    )
    -- with the expected payload
    assert(
        (machine:read_htif_tohost_data() >> 1) == exit_payload,
        string.format("exit payload: expected %u, got %u\n", exit_payload, machine:read_htif_tohost_data() >> 1)
    )
    stderr("    passed\n")
end

stderr("testing yield sink\n")

for _, auto in ipairs({ true, false }) do
    for _, manual in ipairs({ true, false }) do
        test(config, auto, manual)
    end
end
