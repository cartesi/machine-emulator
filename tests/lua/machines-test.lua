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
local test_data = require("cartesi.tests.data")

-- Note: for this test to work, jsonrpc-remote-cartesi-machine must
-- run on the same computer and jsonrpc-remote-cartesi-machine execution path
-- must be provided

-- There is no UINT64_MAX in Lua, so we have to use the signed representation
local MAX_MCYCLE = -1
local OUTPUTS_ROOT_HASH_SIZE = 32

local cleanup = {}
local remote_address
local MACHINES_DIR = test_util.machines_path

-- Print help and exit
local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s <machine_type> [options]

where options are:

  --remote-address=<address>
    address of the jsonrpc-remote-cartesi-machine.

  --help
    print this help message with usage and available options

<address> is one of the following formats:
  <host>:<port>
   unix:<path>

<host> can be a host name, IPv4 or IPv6 address.
]=],
        arg[0]
    ))
    os.exit()
end

local options = {
    {
        "^%-%-help$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        "^%-%-remote%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            remote_address = o
            return true
        end,
    },
    { ".*", function(all) error("unrecognized option " .. all) end },
}

-- Process command line options
local arguments = {}
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then break end
        end
    else
        arguments[#arguments + 1] = argument
    end
end

assert(not arguments[1])
assert(remote_address ~= nil, "remote cartesi machine address is missing")

local function connect()
    local remote = require("cartesi.jsonrpc").stub(remote_address)
    local version = assert(remote.get_version(), "could not connect to remote cartesi machine at " .. remote_address)
    local shutdown = function() remote.shutdown() end
    local mt = { __gc = function() pcall(shutdown) end }
    setmetatable(cleanup, mt)
    return remote, version
end
local remote = connect()

local function load_machine(name)
    local runtime = {
        concurrency = {
            update_merkle_tree = 0,
        },
    }
    return assert(remote).machine(MACHINES_DIR .. name, runtime)
end

local function set_yield_data(machine, reason, data)
    local m16 = (1 << 16) - 1
    local m32 = (1 << 32) - 1
    machine:write_htif_fromhost_data(((reason & m16) << 32) | (data & m32))
end

local function get_yield(machine)
    local m16 = (1 << 16) - 1
    local m32 = (1 << 32) - 1
    local cmd = machine:read_htif_tohost_cmd()
    local data = machine:read_htif_tohost_data()
    local reason = data >> 32
    return cmd, reason & m16, data & m32
end

local function next_input(machine, config, reason, data, override_length)
    assert(machine:read_iflags_Y())
    machine:replace_memory_range(config.cmio.rx_buffer) -- clear
    machine:write_memory(config.cmio.rx_buffer.start, data)
    local length = override_length or #data
    set_yield_data(machine, reason, length)
    machine:reset_iflags_Y()
end

local function setup_advance(machine, config, data, override_length)
    assert(data)
    local reason = cartesi.machine.HTIF_YIELD_REASON_ADVANCE_STATE
    next_input(machine, config, reason, data, override_length)
end

local function setup_inspect(machine, config, data, override_length)
    local reason = cartesi.machine.HTIF_YIELD_REASON_INSPECT_STATE
    next_input(machine, config, reason, data, override_length)
end

local function get_exit_code(machine)
    assert(machine:read_iflags_H())
    return machine:read_htif_tohost_data() >> 1
end

local function check_output(machine, config, expected)
    assert(machine:read_iflags_X())
    local cmd, reason, length = get_yield(machine)
    assert(cmd == cartesi.machine.HTIF_YIELD_CMD_AUTOMATIC)
    assert(reason == cartesi.machine.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT)
    local output = machine:read_memory(config.cmio.tx_buffer.start, length)
    assert(expected == output)

    return cartesi.keccak(output)
end

local function check_report(machine, config, expected)
    assert(machine:read_iflags_X())
    local cmd, reason, length = get_yield(machine)
    assert(cmd == cartesi.machine.HTIF_YIELD_CMD_AUTOMATIC)
    assert(reason == cartesi.machine.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT)
    local output = machine:read_memory(config.cmio.tx_buffer.start, length)
    assert(expected == output)
end

local function check_exception(machine, config, expected)
    assert(machine:read_iflags_Y())
    local cmd, reason, length = get_yield(machine)
    assert(cmd == cartesi.machine.HTIF_YIELD_CMD_MANUAL)
    assert(reason == cartesi.machine.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION)
    local output = machine:read_memory(config.cmio.tx_buffer.start, length)
    assert(expected == output, string.format("expected: %q, got: %q", expected, output))
end

local function check_outputs_root_hash(root_hash, output_hashes)
    local z = string.rep("\0", 32)
    if #output_hashes == 0 then output_hashes = { z } end
    for _ = 1, 16 do
        local parent_output_hashes = {}
        local child = 1
        local parent = 1
        while true do
            local c1 = output_hashes[child]
            if not c1 then break end
            local c2 = output_hashes[child + 1]
            if c2 then
                parent_output_hashes[parent] = cartesi.keccak(c1, c2)
            else
                parent_output_hashes[parent] = cartesi.keccak(c1, z)
            end
            parent = parent + 1
            child = child + 2
        end
        z = cartesi.keccak(z, z)
        output_hashes = parent_output_hashes
    end
    assert(root_hash == output_hashes[1], "output root hash mismatch")
end

local function check_finish(machine, config, output_hashes)
    local cmd, reason, length = get_yield(machine)
    assert(machine:read_iflags_Y())
    assert(cmd == cartesi.machine.HTIF_YIELD_CMD_MANUAL)
    assert(reason == cartesi.machine.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(length == OUTPUTS_ROOT_HASH_SIZE)
    local output = machine:read_memory(config.cmio.tx_buffer.start, length)
    check_outputs_root_hash(output, output_hashes)
end

local function do_test(description, machine_name, fn, expected_exit_code)
    io.write("  " .. description .. "...\n")

    local machine <close> = load_machine(machine_name)
    local config = machine:get_initial_config()

    -- accommodate tests to machines that don't halt
    local exit_code = fn(machine, config) or get_exit_code(machine)
    assert(
        expected_exit_code == exit_code,
        string.format("expected exit code: %d, got: %d", expected_exit_code, exit_code)
    )

    print("<<<<<<<<<<<<<<<< passed >>>>>>>>>>>>>>>")
end

do_test("catch exit when http-server shuts down", "http-server-error-machine", function(machine, config)
    setup_advance(machine, config, test_data.valid_advance)
    machine:run(MAX_MCYCLE)
end, 1)

do_test("catch exception when dapp exits with failure", "fatal-error-machine", function(machine, config)
    setup_advance(machine, config, test_data.valid_advance)

    -- exception
    machine:run(MAX_MCYCLE)
    check_exception(machine, config, "dapp exited with exit status: 2")

    return 0
end, 0)

do_test("halt with exit code", "exception-machine", function(machine, config)
    setup_advance(machine, config, test_data.valid_advance)
    machine:run(MAX_MCYCLE)
end, 1)

do_test("inspect reply is the same as request", "inspect-state-machine", function(machine, config)
    local message = "hello world"
    setup_inspect(machine, config, message)
    machine:run(MAX_MCYCLE)

    check_report(machine, config, message)
    return 0
end, 0)

do_test("merkle tree state must match and reset for each input", "advance-state-machine", function(machine, config)
    for _ = 1, 2 do
        local hashes = {}
        setup_advance(machine, config, test_data.valid_advance)

        -- 2 vouchers
        machine:run(MAX_MCYCLE)
        hashes[#hashes + 1] = check_output(machine, config, test_data.valid_advance_voucher_reply)

        machine:run(MAX_MCYCLE)
        hashes[#hashes + 1] = check_output(machine, config, test_data.valid_advance_voucher_reply)

        -- 2 notices
        machine:run(MAX_MCYCLE)
        hashes[#hashes + 1] = check_output(machine, config, test_data.valid_advance_notice_reply)

        machine:run(MAX_MCYCLE)
        hashes[#hashes + 1] = check_output(machine, config, test_data.valid_advance_notice_reply)

        -- 2 reports
        machine:run(MAX_MCYCLE)
        check_report(machine, config, test_data.valid_advance_report_reply)

        machine:run(MAX_MCYCLE)
        check_report(machine, config, test_data.valid_advance_report_reply)

        -- finish
        machine:run(MAX_MCYCLE)
        check_finish(machine, config, hashes)
    end

    return 0
end, 0)
