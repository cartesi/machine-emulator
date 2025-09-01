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
--local jsonrpc = require("cartesi.jsonrpc")
local calldata = require("cartesi.calldata")
local socket = require("socket")

local function stderr(...) io.stderr:write((string.format(...))) end

local tinsert = table.insert

local function tappend(t, elems)
    local n = #t
    for i, v in ipairs(elems) do
        t[n + i] = v
    end
end

local function errorf(fmt, ...) error(string.format(fmt, ...)) end

local config = {
    dtb = {
        entrypoint = "while true; do rollup accept; done",
        init = 'echo "\
         .\
        / \\\\\
      /    \\\\\
\\\\---/---\\\\  /----\\\\\
 \\\\       X       \\\\\
  \\\\----/  \\\\---/---\\\\\
       \\\\    / CARTESI\
        \\\\ /   MACHINE\
         \'\
"\
busybox mkdir -p /run/drive-label && echo "root" > /run/drive-label/pmem0\
',
    },
    flash_drive = {
        {
            backing_store = {
                data_filename = "rootfs.ext2",
            },
            start = 0x80000000000000,
        },
    },
    ram = {
        backing_store = {
            data_filename = "linux.bin",
        },
        length = 0x8000000,
    },
    virtio = {},
}

local INPUT_COUNT = 10
local LOG2_MCYCLE_PERIOD = 15
local MCYCLE_PERIOD = 1 << LOG2_MCYCLE_PERIOD

local function encode_input(index)
    local chain_id = "0x0000000000000000000000000000000000000001"
    local app_contract = "0x0000000000000000000000000000000000000002"
    local msg_sender = "0x0000000000000000000000000000000000000003"
    local block_number = 4
    local block_timestamp = 5
    local prev_randao = 6
    local payload = string.rep("Hello world!", index + 1)
    local advance_sig = [[
        EvmAdvance(
            uint256 chainId,
            address appContract,
            address msgSender,
            uint256 blockNumber,
            uint256 blockTimestamp,
            uint256 prevRandao,
            uint256 index,
            bytes payload
        )
    ]]
    local args = {
        chainId = chain_id,
        appContract = app_contract,
        msgSender = msg_sender,
        blockNumber = block_number,
        blockTimestamp = block_timestamp,
        prevRandao = prev_randao,
        index = index,
        payload = calldata.raw(payload),
    }
    return assert(calldata.encode_calldata(advance_sig, args))
end

local failed = cartesi.BREAK_REASON_FAILED
local halted = cartesi.BREAK_REASON_HALTED
local yielded_manually = cartesi.BREAK_REASON_YIELDED_MANUALLY
--local yielded_softly = cartesi.BREAK_REASON_YIELDED_SOFTLY
--local yielded_automatically = cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
--local reached_target_mcycle = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE

local function create_machine()
    --local machine = arg[1] and assert(jsonrpc.connect_server(arg[1])) or assert(jsonrpc.spawn_server("127.0.0.1:0"))
    local machine = cartesi.machine
    -- create from template
    local m = machine(config)
    -- run until first yield
    local break_reason = m:run(math.maxinteger)
    assert(break_reason == yielded_manually, "machine did not yield manually")
    return m, break_reason
end

local function get_root_hashes_directly(input_count)
    local inputs = {}
    local hashes
    local m, break_reason = create_machine()
    local mcycle = m:read_reg("mcycle")
    local target_mcycle
    local index = 0
    while index < input_count and break_reason ~= halted and break_reason ~= failed do
        if break_reason == yielded_manually then
            if hashes then tinsert(inputs, hashes) end
            hashes = {}
            local input = encode_input(index)
            m:send_cmio_response(cartesi.CMIO_YIELD_REASON_ADVANCE_STATE, input)
            index = index + 1
            target_mcycle = mcycle + MCYCLE_PERIOD
        end
        break_reason = m:run(target_mcycle)
        mcycle = m:read_reg("mcycle")
        if mcycle == target_mcycle then
            target_mcycle = mcycle + MCYCLE_PERIOD
            tinsert(hashes, m:get_root_hash())
        end
    end
    print("Halted")
    return inputs
end

--[[
local break_reason_name = {
    [halted] = "halted",
    [failed] = "failed",
    [yielded_manually] = "yielded_manually",
    [yielded_automatically] = "yielded_automatically",
    [yielded_softly] = "yielded_softly",
    [reached_target_mcycle] = "reached_target_mcycle",
}
]]

local function get_root_hashes_with_collect(input_count)
    local inputs = {}
    local hashes
    local m, break_reason = create_machine()
    local mcycle_phase
    local index = 0
    local period_count = 7
    while index < input_count and break_reason ~= halted and break_reason ~= failed do
        if break_reason == yielded_manually then
            if hashes then tinsert(inputs, hashes) end
            hashes = {}
            mcycle_phase = 0
            local input = encode_input(index)
            m:send_cmio_response(cartesi.CMIO_YIELD_REASON_ADVANCE_STATE, input)
            index = index + 1
        end
        local collected = m:collect_mcycle_root_hashes(
            m:read_reg("mcycle") + period_count * MCYCLE_PERIOD,
            MCYCLE_PERIOD,
            mcycle_phase
        )
        break_reason, mcycle_phase = collected.break_reason, collected.mcycle_phase
        tappend(hashes, collected.hashes)
    end
    print("Halted")
    return inputs
end

collectgarbage()
collectgarbage()

local t = socket.gettime()
local inputs_collected = get_root_hashes_with_collect(INPUT_COUNT)
local collect_time = socket.gettime() - t

collectgarbage()
collectgarbage()

t = socket.gettime()
local inputs_directly = get_root_hashes_directly(INPUT_COUNT)
local directly_time = socket.gettime() - t

stderr("collect in %.2gs, direct in %.2g", collect_time, directly_time)

if #inputs_collected ~= #inputs_directly then
    errorf("number of inputs do not match (%u vs %u)", #inputs_collected, #inputs_directly)
end
for i, c in ipairs(inputs_collected) do
    local d = inputs_directly[i]
    if #c ~= #d then errorf("number of hashes in input %u do not match (%u vs %u)", i - 1, #c, #d) end
    for j, hc in ipairs(c) do
        local hd = d[j]
        if hc ~= hd then
            local hex_hc = calldata.encode_hex(hc:sub(1, 8))
            local hex_hd = calldata.encode_hex(hd:sub(1, 8))
            errorf("hashes %u of input %u do not match (%s vs %s)", i - 1, j - 1, hex_hc, hex_hd)
        end
    end
end
