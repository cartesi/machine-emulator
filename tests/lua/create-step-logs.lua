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

-- This script creates a set of step log files to be used as test fixtures.
-- Each step log file name has the following format:
--    step-<start-mcycle>-<root_hash_before>-<mcycle_count>--<root_hash_after>.log
-- These files are stored in the directory specified by the command line argument.
-- This directory is created if it does not exist.

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")

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
        hash_tree = {
            hash_function = "sha256",
        },

        ram = {
            length = 0x4000000,
            backing_store = {
                data_filename = images_dir .. "linux.bin",
            },
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
                backing_store = {
                    data_filename = images_dir .. "rootfs.ext2",
                },
            },
        },
    }
end

local function adjust_images_path(path)
    return string.gsub(path or ".", "/*$", "") .. "/"
end

local IMAGES_DIR = adjust_images_path(test_util.images_path)
local STEP_LOGS_PATH = adjust_images_path(test_util.step_logs_path)

local function create_machine(command)
    local config = create_default_config(IMAGES_DIR, command)
    local machine = cartesi.machine(config)
    return machine
end

local function create_step_log(mcycle_count, command, start_mcycle)
    local temp_filename = STEP_LOGS_PATH .. "temp.log"
    local deleter = {}
    local function remove_temp_file()
        os.remove(temp_filename)
    end
    setmetatable(deleter, {
        __gc = remove_temp_file,
    })

    start_mcycle = start_mcycle or 0
    local machine <close> = create_machine(command)
    machine:run(start_mcycle)
    assert(machine:read_reg("mcycle") == start_mcycle)
    local root_hash_before = machine:get_root_hash()
    machine:log_step(mcycle_count, temp_filename)
    local root_hash_after = machine:get_root_hash()
    local final_filename = STEP_LOGS_PATH
        .. test_util.step_log_filename(root_hash_before, mcycle_count, root_hash_after)
    os.execute("cp " .. temp_filename .. " " .. final_filename)
    print("Created step log:" .. final_filename)
    remove_temp_file()
end

local command = 'lua -e "print(os.clock(), (10.5 * 2.3 + 5.7 / 3.1 - math.sqrt(42)) ^ 1.5)" | sha256sum'
local machine <close> = create_machine(command)
machine:run()
local max_mcycle = machine:read_reg("mcycle")
local files_count = 10
local mcycle_stride = max_mcycle // files_count
local max_step_count = 1000
local mcycle_count = mcycle_stride > max_step_count and max_step_count or mcycle_stride

create_directory(STEP_LOGS_PATH)
for start_mcycle = 0, max_mcycle, mcycle_stride do
    create_step_log(mcycle_count, command, start_mcycle)
end
