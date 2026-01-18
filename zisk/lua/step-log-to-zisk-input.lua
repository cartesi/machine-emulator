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

local function stderr(fmt, ...) io.stderr:write(string.format(fmt, ...)) end

local function help()
    io.stdout:write([=[
Usage: step-log-to-zisk-input.lua [options] <step-log-file>...

Converts step log(s) to ZisK prover input file(s). The ZisK prover reads all
arguments (hashes, mcycle count, step log) from a single serialized input file.

Options:
  --help                   Display this help
  --output=<template>      Output filename template
                           Placeholders: %initial-hash%, %mcycle%, %final-hash%, %suffix%
                           Default: zisk-input-%initial-hash%-%mcycle%-%final-hash%%suffix%.bin
  --output-dir=<dir>       Output directory (used with default filename template)
  --initial-hash=<hex>     Initial root hash (64 hex chars) - only for single file
  --final-hash=<hex>       Final root hash (64 hex chars) - only for single file
  --mcycle=<number>        Machine cycle count - only for single file

Arguments are inferred from step log filename if it matches the pattern:
  step-<initial-hash>-<mcycle>-<final-hash>[-suffix].log

The %suffix% placeholder includes the test name (e.g., "-rv64ui-p-xori") if present.

Multiple files:
  ./step-log-to-zisk-input.lua step-*.log
  ./step-log-to-zisk-input.lua --output-dir=zisk-inputs step-*.log

Output format (binary):
  [0..32):  initial_hash
  [32..40): mcycle (u64 LE)
  [40..72): final_hash
  [72..):   step_log
]=])
    os.exit(0)
end

local function fromhex(str)
    return (str:gsub("..", function(cc)
        return string.char(tonumber(cc, 16))
    end))
end

local function pack_u64_le(n)
    return string.pack("<I8", n)
end

local function read_file(filename)
    local f <close> = assert(io.open(filename, "rb"), "failed to open " .. filename)
    return assert(f:read("a"))
end

local function write_file(filename, data)
    local f <close> = assert(io.open(filename, "wb"), "failed to create " .. filename)
    assert(f:write(data))
end

local function file_exists(path)
    local f <close> = io.open(path, "r")
    return f ~= nil
end

local function ensure_directory(path)
    if path and not file_exists(path) then
        os.execute("mkdir -p " .. path)
    end
end

local function dirname(path)
    return path:match("^(.+)/[^/]+$")
end

-- Parse step log filename: step-<initial_hash>-<mcycle>-<final_hash>[-suffix].log
local function parse_step_log_filename(filepath)
    local filename = filepath:match("([^/]+)$") or filepath
    local basename = filename:match("^(.+)%.log$")
    if not basename then return nil end

    local rest = basename:match("^step%-(.+)$")
    if not rest then return nil end

    local initial_hash = rest:sub(1, 64)
    if #initial_hash ~= 64 or not initial_hash:match("^%x+$") then return nil end

    rest = rest:sub(66)
    local mcycle_str, after = rest:match("^(%d+)%-(.+)$")
    if not mcycle_str then return nil end

    local final_hash = after:sub(1, 64)
    if #final_hash ~= 64 or not final_hash:match("^%x+$") then return nil end

    -- Extract optional suffix after final hash
    local suffix = nil
    if #after > 64 then
        suffix = after:sub(66)  -- skip the '-' after final hash
    end

    return {
        initial_hash = initial_hash,
        mcycle = tonumber(mcycle_str),
        final_hash = final_hash,
        suffix = suffix,
    }
end

-- Expand output template with values
local function expand_output_template(template, initial_hash, final_hash, mcycle, suffix)
    local result = template
    result = result:gsub("%%initial%-hash%%", initial_hash)
    result = result:gsub("%%final%-hash%%", final_hash)
    result = result:gsub("%%mcycle%%", tostring(mcycle))
    -- Handle suffix: if suffix exists, include with leading dash; otherwise remove placeholder
    if suffix then
        result = result:gsub("%%suffix%%", "-" .. suffix)
    else
        result = result:gsub("%%suffix%%", "")
    end
    return result
end

-- Process a single step log file
local function process_file(step_log_file, output_template, output_dir, opt_initial_hash, opt_final_hash, opt_mcycle)
    local inferred = parse_step_log_filename(step_log_file)

    local initial_hash = opt_initial_hash
    local final_hash = opt_final_hash
    local mcycle = opt_mcycle
    local suffix = nil

    if inferred then
        -- Check for conflicts with explicit options
        if initial_hash and initial_hash ~= inferred.initial_hash then
            return nil, string.format("%s: --initial-hash conflicts with filename", step_log_file)
        end
        if final_hash and final_hash ~= inferred.final_hash then
            return nil, string.format("%s: --final-hash conflicts with filename", step_log_file)
        end
        if mcycle and mcycle ~= inferred.mcycle then
            return nil, string.format("%s: --mcycle conflicts with filename", step_log_file)
        end
        initial_hash = initial_hash or inferred.initial_hash
        final_hash = final_hash or inferred.final_hash
        mcycle = mcycle or inferred.mcycle
        suffix = inferred.suffix
    end

    -- Validate required values
    if not initial_hash or #initial_hash ~= 64 or not initial_hash:match("^%x+$") then
        return nil, string.format("%s: cannot determine initial-hash", step_log_file)
    end
    if not final_hash or #final_hash ~= 64 or not final_hash:match("^%x+$") then
        return nil, string.format("%s: cannot determine final-hash", step_log_file)
    end
    if not mcycle then
        return nil, string.format("%s: cannot determine mcycle", step_log_file)
    end

    -- Build output filename
    local output_file = expand_output_template(output_template, initial_hash, final_hash, mcycle, suffix)
    if output_dir then
        local basename = output_file:match("([^/]+)$") or output_file
        output_file = output_dir .. "/" .. basename
    end

    -- Ensure output directory exists
    local dir = dirname(output_file)
    if dir then
        ensure_directory(dir)
    end

    -- Read step log
    local ok, step_log_data = pcall(read_file, step_log_file)
    if not ok then
        return nil, string.format("%s: %s", step_log_file, step_log_data)
    end

    -- Build ZisK input: initial_hash(32) + mcycle(8 LE) + final_hash(32) + step_log
    local zisk_input = fromhex(initial_hash) .. pack_u64_le(mcycle) .. fromhex(final_hash) .. step_log_data

    -- Write output
    local ok2, err = pcall(write_file, output_file, zisk_input)
    if not ok2 then
        return nil, string.format("%s: %s", output_file, err)
    end

    return output_file, #zisk_input
end

-- Main
local input_files = {}
local output_template = "zisk-input-%initial-hash%-%mcycle%-%final-hash%%suffix%.bin"
local output_dir = nil
local opt_initial_hash = nil
local opt_final_hash = nil
local opt_mcycle = nil

local options = {
    { "^%-%-help$", help },
    { "^%-h$", help },
    {
        "^%-%-output=(.+)$",
        function(v)
            output_template = v
            return true
        end,
    },
    {
        "^%-%-output%-dir=(.+)$",
        function(v)
            output_dir = v:gsub("/*$", "")
            return true
        end,
    },
    {
        "^%-%-initial%-hash=(%x+)$",
        function(v)
            opt_initial_hash = v
            return true
        end,
    },
    {
        "^%-%-final%-hash=(%x+)$",
        function(v)
            opt_final_hash = v
            return true
        end,
    },
    {
        "^%-%-mcycle=(%d+)$",
        function(v)
            opt_mcycle = tonumber(v)
            return true
        end,
    },
}

-- Process arguments
for _, a in ipairs(arg) do
    local matched = false
    for _, opt in ipairs(options) do
        local v1, v2 = a:match(opt[1])
        if v1 ~= nil then
            opt[2](v1, v2)
            matched = true
            break
        end
    end
    if not matched then
        if a:match("^%-") then
            stderr("Error: unknown option: %s\n", a)
            os.exit(1)
        else
            table.insert(input_files, a)
        end
    end
end

if #input_files == 0 then
    stderr("Error: no input files specified\n")
    stderr("Try --help for usage\n")
    os.exit(1)
end

-- Explicit hash/mcycle options only allowed for single file
if #input_files > 1 and (opt_initial_hash or opt_final_hash or opt_mcycle) then
    stderr("Error: --initial-hash, --final-hash, --mcycle only allowed with single input file\n")
    os.exit(1)
end

-- Process files
local success_count = 0
local error_count = 0

for _, input_file in ipairs(input_files) do
    local output_file, result = process_file(
        input_file, output_template, output_dir,
        opt_initial_hash, opt_final_hash, opt_mcycle
    )
    if output_file then
        stderr("Created: %s (%d bytes)\n", output_file, result)
        success_count = success_count + 1
    else
        stderr("Error: %s\n", result)
        error_count = error_count + 1
    end
end

if #input_files > 1 then
    stderr("\nSummary: %d created, %d errors\n", success_count, error_count)
end

if error_count > 0 then
    os.exit(1)
end
