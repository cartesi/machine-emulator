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

-- Step log header utility for Cartesi Machine RISC0 workflows.
--
-- Replaces complex xxd/sed/python3 pipelines in Makefiles with a single
-- Lua script that reads the 72-byte step log header directly.
--
-- Usage:
--   step-log-util.lua info <step-log>              Human-readable header
--   step-log-util.lua root-hash-before <step-log>  Hex hash (no newline)
--   step-log-util.lua mcycle-count <step-log>       Decimal (no newline)
--   step-log-util.lua root-hash-after <step-log>   Hex hash (no newline)
--   step-log-util.lua hex-encode <string>           Hex-encode (no newline)

local HEADER_SIZE = 72 -- root_hash_before(32) + mcycle_count(8) + root_hash_after(32)

local function hexstring(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function read_header(path)
    local f, err = io.open(path, "rb")
    if not f then
        io.stderr:write("error: " .. err .. "\n")
        os.exit(1)
    end
    local data = f:read(HEADER_SIZE)
    f:close()
    if not data or #data < HEADER_SIZE then
        io.stderr:write(string.format("error: step log too small (got %d bytes, need %d)\n",
            data and #data or 0, HEADER_SIZE))
        os.exit(1)
    end
    local root_hash_before = hexstring(data:sub(1, 32))
    local mcycle_count = string.unpack("<I8", data, 33)
    local root_hash_after = hexstring(data:sub(41, 72))
    return root_hash_before, mcycle_count, root_hash_after
end

local commands = {}

function commands.info(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua info <step-log>\n")
        os.exit(1)
    end
    local hash_before, mcycle, hash_after = read_header(path)
    print("Step log: " .. path)
    print("  root_hash_before: " .. hash_before)
    print("  mcycle_count:     " .. mcycle)
    print("  root_hash_after:  " .. hash_after)
end

commands["root-hash-before"] = function(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua root-hash-before <step-log>\n")
        os.exit(1)
    end
    local hash_before = read_header(path)
    io.write(hash_before)
end

commands["mcycle-count"] = function(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua mcycle-count <step-log>\n")
        os.exit(1)
    end
    local _, mcycle = read_header(path)
    io.write(tostring(mcycle))
end

commands["root-hash-after"] = function(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua root-hash-after <step-log>\n")
        os.exit(1)
    end
    local _, _, hash_after = read_header(path)
    io.write(hash_after)
end

commands["hex-encode"] = function(args)
    local s = args[1]
    if not s then
        io.stderr:write("usage: step-log-util.lua hex-encode <string>\n")
        os.exit(1)
    end
    io.write(hexstring(s))
end

local cmd_name = arg[1]
if not cmd_name or not commands[cmd_name] then
    io.stderr:write("usage: step-log-util.lua <command> [args...]\n")
    io.stderr:write("\nCommands:\n")
    io.stderr:write("  info <step-log>              Print step log header fields\n")
    io.stderr:write("  root-hash-before <step-log>  Print root hash before (hex)\n")
    io.stderr:write("  mcycle-count <step-log>       Print mcycle count (decimal)\n")
    io.stderr:write("  root-hash-after <step-log>   Print root hash after (hex)\n")
    io.stderr:write("  hex-encode <string>           Hex-encode a string\n")
    os.exit(1)
end

local cmd_args = {}
for i = 2, #arg do
    cmd_args[i - 1] = arg[i]
end

commands[cmd_name](cmd_args)
