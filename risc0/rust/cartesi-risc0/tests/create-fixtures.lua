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

-- This file creates a set of step log files to be used as test fixtures.
-- Each step log file name has the following format:
--    step-<start-mcycle>-<root_hash_before>-<mcycle_count>--<root_hash_after>.log
-- These files are stored in the directory specified by the command line argument.
-- This directory is created if it does not exist.

local cartesi = require("cartesi")

local function stderr_unsilenceable(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local stderr = stderr_unsilenceable

local function create_directory(path)
    local success = io.open(path, "r")
    if success == nil then
        os.execute("mkdir -p " .. path)
        stderr("Created directory:" .. path .. "\n")
    else
        success:close()
        stderr("Directory already exists:" .. path .. "\n")
    end
end

local function create_default_config(images_dir, command)
    return {
        ram = {
            length = 0x4000000,
            image_filename = images_dir .. "linux.bin",
        },
        dtb = {
            entrypoint = command,
        },
        cmio = {
            rx_buffer = { shared = false },
            tx_buffer = { shared = false },
        },
        flash_drive = {
            {
                image_filename = images_dir .. "rootfs.ext2",
            },
        },
    }
end

local function adjust_path(path)
    return string.gsub(path or ".", "/*$", "") .. "/"
end

local IMAGES_DIR = adjust_path(assert(os.getenv("CARTESI_IMAGES_PATH")))

local function create_machine(command)
    local config = create_default_config(IMAGES_DIR, command)
    local machine = cartesi.machine(config)
    return machine
end

-- Print help and exit
local function help()
    stderr(
        [=[
Usage:

  %s [options] [<fixtures-dir>]

where <fixtures-dir> is the directory where fixtures will be created.
The default value is "./fixtures".

where options are:

    --fixtures-dir=<dir>
    directory where fixtures will be created

   -h or --help
    print this help message and exit

]=],
        arg[0]
    )
    os.exit()
end

local cmdline_opts_finished = false
-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    {
        "^%-h$",
        function(all)
            if not all then
                return false
            end
            help()
            return true
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then
                return false
            end
            help()
            return true
        end,
    },
    {
        ".*",
        function(all)
            if not all then
                return false
            end
            local not_option = all:sub(1, 1) ~= "-"
            if not_option or all == "--" then
                cmdline_opts_finished = true
                return true
            end
            error("unrecognized option " .. all)
        end,
    },
}

local values = {}

-- Process command line options
for _, argument in ipairs({ ... }) do
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

local fixtures_dir = (values[1] or "./fixtures")
fixtures_dir  = adjust_path(fixtures_dir)

local function hexstring(hash)
    return (string.gsub(hash, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

local function create_step_log(mcycle_count, command, start_mcycle)
    local temp_filename = fixtures_dir .. "temp.log"
    local deleter = {}
    local function remove_temp_file()
        os.remove(temp_filename)
    end
    setmetatable(deleter, {
        __gc = remove_temp_file
    })

    start_mcycle = start_mcycle or 0
    local machine <close> = create_machine(command)
    machine:run(start_mcycle)
    assert(machine:read_reg("mcycle") == start_mcycle)
    local root_hash_before = machine:get_root_hash()
     machine:log_step(mcycle_count, temp_filename)
    local root_hash_after = machine:get_root_hash()
    local final_filename = fixtures_dir .. "step-" .. start_mcycle .. "-"  .. hexstring(root_hash_before) .. "-" .. mcycle_count .. "-" .. hexstring(root_hash_after) .. ".log"
    os.execute("cp " .. temp_filename .. " " .. final_filename)
    print("Created step log:" .. final_filename)
    remove_temp_file()
end

local command = 'lua -e "print(os.clock(), (10.5 * 2.3 + 5.7 / 3.1 - math.sqrt(42)) ^ 1.5)" | sha256sum'
local machine <close> = create_machine(command)
machine:run()
local max_mcycle = machine:read_reg("mcycle")
local fixture_count = 10
local mcycle_stride = max_mcycle // fixture_count
local max_step_count = 1000
local mcycle_count = mcycle_stride > max_step_count and max_step_count or mcycle_stride

create_directory(fixtures_dir)
for start_mcycle = 0, max_mcycle, mcycle_stride do
    create_step_log(mcycle_count, command, start_mcycle)
end
