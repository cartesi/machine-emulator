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

local cartesi = require("cartesi")
local util = require("cartesi.util")
local test_util = require("cartesi.tests.util")

local function stderr_unsilenceable(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end
local stderr = stderr_unsilenceable

local function adjust_images_path(path)
    return string.gsub(path or ".", "/*$", "") .. "/"
end
local function basedir(s)
    s = string.gsub(s, "/$", "")
    return string.match(s, "/.+[^/]+/") or "."
end
local IMAGES_DIR = adjust_images_path(test_util.images_path)
local MACHINES_DIR = adjust_images_path(test_util.cmio_path)

-- Print help and exit
local function help()
    stderr(
        [=[
Usage:

  %s [options]

where options are:

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

-- Process command line options
for _, a in ipairs(arg) do
    if not cmdline_opts_finished then
        for _, option in ipairs(options) do
            if option[2](a:match(option[1])) then
                break
            end
        end
    end
end

local function create_directory(path)
    local success = io.open(path, "r")
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
    if file == nil then
        error("File not found: " .. file_path)
    end
    local size = file:seek("end")
    file:close()
    return size
end

local function create_default_config(images_dir, command)
    return {
        ram = {
            length = 0x4000000,
            image_filename = images_dir .. "linux.bin",
        },
        dtb = {
            bootargs = "quiet earlycon=sbi console=hvc0 rootfstype=ext2 root=/dev/pmem0 rw init=/usr/sbin/cartesi-init",
            init = "USER=dapp\n",
            entrypoint = command,
        },
        htif = {
            console_getchar = false, -- default
            yield_automatic = true,
            yield_manual = true,
        },
        cmio = {
            rx_buffer = { shared = false },
            tx_buffer = { shared = false },
        },
        flash_drive = {
            {
                start = 1 << 55,
                length = get_file_length(images_dir .. "rootfs.ext2"),
                image_filename = images_dir .. "rootfs.ext2",
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

local function store_machine(machine, store_dir)
    local h = util.hexhash(machine:get_root_hash())
    local name = instantiate_filename(store_dir, { h = h })
    machine:store(name)
end

local function create_machine(machine_name, command, config_func)
    stderr("Creating machine: " .. machine_name .. " ...\n")
    local config = create_default_config(IMAGES_DIR, command)
    if config_func then
        config_func(config)
    end
    local machine = cartesi.machine(config)
    machine:run(math.maxinteger)
    store_machine(machine, MACHINES_DIR .. machine_name)
end

create_directory(basedir(MACHINES_DIR))
create_directory(MACHINES_DIR)

-- Basic cases
create_machine("advance-rejecting-machine-http", "rollup-init echo-dapp --reject=0 --verbose")
create_machine("advance-rejecting-machine-ioctl", "ioctl-echo-loop --reject=0 --verbose=1")
create_machine("advance-state-machine-http", "rollup-init echo-dapp --vouchers=2 --notices=2 --reports=2 --verbose")
create_machine("advance-state-machine-ioctl", "ioctl-echo-loop --vouchers=2 --notices=2 --reports=2 --verbose=1")
create_machine("inspect-rejecting-machine-http", "rollup-init echo-dapp --reports=0 --reject-inspects --verbose")
create_machine("inspect-rejecting-machine-ioctl", "ioctl-echo-loop --reports=0 --reject-inspects --verbose=1")
create_machine("inspect-state-machine-http", "rollup-init echo-dapp --reports=2 --verbose")
create_machine("inspect-state-machine-ioctl", "ioctl-echo-loop --reports=2 --verbose=1")
create_machine("one-notice-machine-http", "rollup-init echo-dapp --vouchers=0 --notices=1 --reports=0 --verbose")
create_machine("one-notice-machine-ioctl", "ioctl-echo-loop --vouchers=0 --notices=1 --reports=0 --verbose=1")
create_machine("one-report-machine-http", "rollup-init echo-dapp --vouchers=0 --notices=0 --reports=1 --verbose")
create_machine("one-report-machine-ioctl", "ioctl-echo-loop --vouchers=0 --notices=0 --reports=1 --verbose=1")
create_machine("one-voucher-machine-http", "rollup-init echo-dapp --vouchers=1 --notices=0 --reports=0 --verbose")
create_machine("one-voucher-machine-ioctl", "ioctl-echo-loop --vouchers=1 --notices=0 --reports=0 --verbose=1")

create_machine("exception-machine", 'rollup accept; echo \'{"payload":"test payload"}\' | rollup exception')

create_machine(
    "fatal-error-machine",
    [[
echo '
curl -vv -H "Content-Type: application/json" -d "{\"status\":\"accept\"}" http://127.0.0.1:5004/finish;
exit 2' > /home/dapp/s.sh;
chmod +x /home/dapp/s.sh;
rollup-init bash /home/dapp/s.sh
]]
)

create_machine(
    "http-server-error-machine",
    [[
echo 'curl -vv -H "Content-Type: application/json" -d "{\"status\":\"accept\"}" http://127.0.0.1:5004/finish;
killall rollup-http-server;
sleep 86400' > /home/dapp/s.sh;
chmod +x /home/dapp/s.sh;
rollup-init bash /home/dapp/s.sh
]]
)

-- Should not work with shared buffers
create_machine("shared-rx-buffer-machine", "rollup accept", function(config)
    config.cmio.rx_buffer.shared = true
end)
create_machine("shared-tx-buffer-machine", "rollup accept", function(config)
    config.cmio.tx_buffer.shared = true
end)
