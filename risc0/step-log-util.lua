#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

local HEADER_SIZE = 72 -- root_hash_before(32) + mcycle_count(8) + root_hash_after(32)

local function hexhash(bin)
    local hex = {}
    for i = 1, #bin do hex[i] = string.format("%02x", string.byte(bin, i)) end
    return table.concat(hex)
end

local function read_header(path)
    local f <close> = assert(io.open(path, "rb"))
    local data = f:read(HEADER_SIZE)
    assert(data and #data >= HEADER_SIZE,
        string.format("step log too small (got %d bytes, need %d)", data and #data or 0, HEADER_SIZE))
    local root_hash_before = hexhash(data:sub(1, 32))
    local mcycle_count = string.unpack("<I8", data, 33)
    local root_hash_after = hexhash(data:sub(41, 72))
    return root_hash_before, mcycle_count, root_hash_after
end

local commands = {}

function commands.info(args)
    local path = assert(args[1], "usage: step-log-util.lua info <step-log>")
    local hash_before, mcycle, hash_after = read_header(path)
    print("Step log: " .. path)
    print("  root_hash_before: " .. hash_before)
    print("  mcycle_count:     " .. mcycle)
    print("  root_hash_after:  " .. hash_after)
end

commands["root-hash-before"] = function(args)
    local path = assert(args[1], "usage: step-log-util.lua root-hash-before <step-log>")
    local hash_before = read_header(path)
    io.write(hash_before)
end

commands["mcycle-count"] = function(args)
    local path = assert(args[1], "usage: step-log-util.lua mcycle-count <step-log>")
    local _, mcycle = read_header(path)
    io.write(tostring(mcycle))
end

commands["root-hash-after"] = function(args)
    local path = assert(args[1], "usage: step-log-util.lua root-hash-after <step-log>")
    local _, _, hash_after = read_header(path)
    io.write(hash_after)
end

-- Print help and exit
local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s <command> [args...]

Commands:

  info <step-log>              Print step log header fields
  root-hash-before <step-log>  Print root hash before (hex)
  mcycle-count <step-log>       Print mcycle count (decimal)
  root-hash-after <step-log>   Print root hash after (hex)

]=],
        arg[0]
    ))
    os.exit()
end

-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    {
        "^%-h$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        ".*",
        function(all)
            error("unrecognized option " .. all)
        end,
    },
}

-- Process command line options
local values = {}
for _, argument in ipairs(arg) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        values[#values + 1] = argument
    end
end

if not values[1] then help() end
local cmd_name = values[1]
assert(commands[cmd_name], "unknown command '" .. cmd_name .. "', use --help for usage")

local cmd_args = {}
for i = 2, #values do
    cmd_args[i - 1] = values[i]
end

commands[cmd_name](cmd_args)
