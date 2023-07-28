#!/usr/bin/env lua5.3

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

local cartesi = require"cartesi"
local util = require"cartesi.util"

local function stderr_unsilenceable(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local stderr = stderr_unsilenceable

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

local IMAGES_DIR = adjust_images_path(os.getenv('CARTESI_IMAGES_PATH') or "/opt/cartesi/share/images")
local ROOT_DIR = "/tmp/server-manager-root"
local MACHINES_DIR = ROOT_DIR .. "/tests"

-- Print help and exit
local function help()
    stderr([=[
Usage:

  %s [options]

where options are:

   -h or --help
    print this help message and exit

   --rollup-init
    uses rollup-init echo-dapp instead of the ioctl-echo-loop on machines

]=], arg[0])
    os.exit()
end

local rollup_init = false
-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    { "^%-h$", function(all)
        if not all then return false end
        help()
        return true
    end },
    { "^%-%-help$", function(all)
        if not all then return false end
        help()
        return true
    end },
    { "^%-%-rollup%-init$", function(all)
        if not all then return false end
        rollup_init = true
        return true
    end },
    { ".*", function(all)
        if not all then return false end
        local not_option = all:sub(1,1) ~= "-"
        if not_option or all == "--" then
          cmdline_opts_finished = true
          return true
        end
        error("unrecognized option " .. all)
    end }
}

-- Process command line options
for i, a in ipairs(arg) do
    if not cmdline_opts_finished then
      for j, option in ipairs(options) do
          if option[2](a:match(option[1])) then
              break
          end
      end
    end
end

local function create_directory(path)
    local success, message = io.open(path, "r")
    if success == nil then
        os.execute("mkdir " .. path)
        stderr("Created directory:" .. path .. "\n")
    else
        success:close()
        stderr("Directory already exists:" .. path .. "\n")
    end
end

local function get_file_length(file_path)
  local file = io.open(file_path, "rb")
  local size = file:seek("end")
  file:close()
  return size
end

function create_default_config(images_dir, command)
    return {
      ram = {
        length = 0x4000000,
        image_filename = images_dir .. "linux.bin",
      },
      rom = {
        image_filename = images_dir .. "rom.bin",
        bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet swiotlb=noforce splash=no mtdparts=flash.0:-(root) " .. command,
      },
      htif = {
        console_getchar = false, -- default
        yield_automatic = true,
        yield_manual = true,
      },
      flash_drive = {
        {
          start = 1<<55,
          length = get_file_length(images_dir .. "rootfs.ext2"),
          image_filename = images_dir .. "rootfs.ext2",
          shared = false, -- default
        },
      },
      rollup = {
        rx_buffer = {
          start = 0x60000000,
          length = 0x200000,
          shared = false, -- default
        },
        tx_buffer = {
          start = 0x60200000,
          length = 0x200000,
          shared = false, -- default
        },
        input_metadata = {
          start = 0x60400000,
          length = 0x1000,
          shared = false, -- default
        },
        voucher_hashes = {
          start = 0x60600000,
          length = 0x200000,
          shared = false, -- default
        },
        notice_hashes = {
          start = 0x60800000,
          length = 0x200000,
          shared = false, -- default
        },
      },
    }
end

local function instantiate_filename(pattern, values)
    -- replace escaped % with something safe
    pattern = string.gsub(pattern, "%\\%%", "\0")
    pattern = string.gsub(pattern, "%%(%a)", function(s)
        return values[s] or s
    end)
    -- restore escaped %
    return (string.gsub(pattern, "\0", "%"))
end

local function store_machine(machine, config, store_dir)
    local h = util.hexhash(machine:get_root_hash())
    local name = instantiate_filename(store_dir, { h = h })
    machine:store(name)
end

local function create_machine(machine_name, command, config_func)
  stderr("Creating machine: " .. machine_name .. " ...\n")
  local config = create_default_config(IMAGES_DIR, command)
  if config_func then config_func(config) end
  local machine = cartesi.machine(config)
  machine:run(math.maxinteger)
  store_machine(machine, config, MACHINES_DIR .. "/" .. machine_name )
end


create_directory(ROOT_DIR)
create_directory(MACHINES_DIR)

-- Basic cases
if rollup_init then
  create_machine("advance-state-machine", "-- rollup-init echo-dapp --vouchers=2 --notices=2 --reports=2 --verbose");
  create_machine("inspect-state-machine", "-- rollup-init echo-dapp --reports=2 --verbose");
  create_machine("one-notice-machine", "-- rollup-init echo-dapp --vouchers=0 --notices=1 --reports=0 --verbose");
  create_machine("one-report-machine", "-- rollup-init echo-dapp --vouchers=0 --notices=0 --reports=1 --verbose");
  create_machine("one-voucher-machine", "-- rollup-init echo-dapp --vouchers=1 --notices=0 --reports=0 --verbose");
  create_machine("advance-rejecting-machine", "-- rollup-init echo-dapp --reject=0 --verbose");
  create_machine("inspect-rejecting-machine", "-- rollup-init echo-dapp --reports=0 --reject-inspects --verbose");
else
  create_machine("advance-state-machine", "-- ioctl-echo-loop --vouchers=2 --notices=2 --reports=2 --verbose=1");
  create_machine("inspect-state-machine", "-- ioctl-echo-loop --reports=2 --verbose=1");
  create_machine("one-notice-machine", "-- ioctl-echo-loop --vouchers=0 --notices=1 --reports=0 --verbose=1");
  create_machine("one-report-machine", "-- ioctl-echo-loop --vouchers=0 --notices=0 --reports=1 --verbose=1");
  create_machine("one-voucher-machine", "-- ioctl-echo-loop --vouchers=1 --notices=0 --reports=0 --verbose=1");
  create_machine("advance-rejecting-machine", "-- ioctl-echo-loop --reject=0 --verbose=1");
  create_machine("inspect-rejecting-machine", "-- ioctl-echo-loop --reports=0 --reject-inspects --verbose=1");
end

-- Some edge cases
create_machine("no-output-machine", "-- while true; do rollup accept; done");
create_machine("infinite-loop-machine", "-- rollup accept; while true; do :; done");
create_machine("halting-machine", "-- rollup accept");
create_machine("init-exception-machine", "-- echo '{\"payload\":\"test payload\"}' | rollup exception");
create_machine("exception-machine", "-- rollup accept; echo '{\"payload\":\"test payload\"}' | rollup exception");

create_machine("fatal-error-machine",
  "-- echo 'import requests; requests.post(\"http://127.0.0.1:5004/finish\", json={\"status\":\"accept\"}); exit(2);' > s.py; rollup-init python3 s.py");
create_machine("http-server-error-machine",
  "-- echo 'import requests; import os; requests.post(\"http://127.0.0.1:5004/finish\", json={\"status\":\"accept\"}); os.system(\"killall rollup-http-server\");' > s.py; rollup-init python3 s.py");
create_machine("voucher-on-inspect-machine",
  "-- rollup accept; echo '{\"address\":\"fafafafafafafafafafafafafafafafafafafafa\",\"payload\":\"test payload\"}' | rollup voucher; rollup accept");
create_machine("notice-on-inspect-machine",
  "-- rollup accept; echo '{\"payload\":\"test payload\"}' | rollup notice; rollup accept");

-- Should not work with no rollup or misconfigured htif
create_machine("no-manual-yield-machine", "-- yield automatic rx-accepted 0",
  function(config) config.htif.yield_manual = false end );
create_machine("no-automatic-yield-machine", "-- rollup accept",
  function(config) config.htif.yield_automatic= false end );
create_machine("console-getchar-machine", "-- rollup accept",
  function(config) config.htif.console_getchar = true end );
create_machine("no-rollup-machine", "-- yield manual rx-accepted 0",
  function(config) config.rollup = nil end );

-- Should not work with shared buffers
create_machine("shared-rx-buffer-machine", "-- rollup accept",
  function(config) config.rollup.rx_buffer.shared = true end );
create_machine("shared-tx-buffer-machine", "-- rollup accept",
  function(config) config.rollup.tx_buffer.shared = true end );
create_machine("shared-input-metadata-machine", "-- rollup accept",
  function(config) config.rollup.input_metadata.shared = true end );
create_machine("shared-voucher-hashes-machine", "-- rollup accept",
  function(config) config.rollup.voucher_hashes.shared = true end );
create_machine("shared-notice-hashes-machine", "-- rollup accept",
  function(config) config.rollup.notice_hashes.shared = true end );
