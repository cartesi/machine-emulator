#!/usr/bin/env lua5.4

-- Copyright 2019 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local cartesi = require"cartesi"
local test_util = require "tests.util"

local config =  {
    processor = {
        mvendorid = -1,
        mimpid = -1,
        marchid = -1,
    },
    ram = {
        -- This test will fetch the rollup buffers from the PMA entries; check
        -- that `rx_buffer` and `input_metadata` are filled with a byte patern;
        -- then write a byte pattern into `tx_buffer`, `voucher_hashes` and
        -- `notice_hashes`.
        image_filename = test_util.tests_path .. "htif_rollup.bin",
        length = 0x4000000,
    },
    rom = {
        image_filename = test_util.tests_path .. "bootstrap.bin"
    },
    htif = {
        yield_automatic = true,
    },
    rollup = {
        rx_buffer = {
            start = 0x60000000, length = 0x1000, shared = false,
        },
        tx_buffer = {
            start = 0x60001000, length = 0x1000, shared = false,
        },
        input_metadata = {
            start = 0x60002000, length = 0x1000, shared = false,
        },
        voucher_hashes = {
            start = 0x60003000, length = 0x1000, shared = false,
        },
        notice_hashes = {
            start = 0x60004000, length = 0x1000, shared = false,
        },
    }
}

local function stderr(...)
    io.stderr:write(string.format(...))
end

local final_mcycle = 8981
local exit_payload = 0

function check_buffer(machine, pattern, buffer)
    local mem = string.rep(pattern, buffer.length/8)
    assert(mem == machine:read_memory(buffer.start, buffer.length))
end

function test(config)
    local pattern = "\xef\xcd\xab\x89\x67\x45\x23\x01"
    local machine = cartesi.machine(config)

    -- fill input with `pattern`
    local rx = config.rollup.rx_buffer;
    machine:write_memory(rx.start, string.rep(pattern, rx.length/8), rx.length);

    -- fill input_metadata with `pattern`
    local im = config.rollup.input_metadata;
    machine:write_memory(im.start, string.rep(pattern, im.length/8), im.length);
    machine:run(math.maxinteger)

    -- check that buffers got filled in with `pattern`
    check_buffer(machine, pattern, config.rollup.tx_buffer)
    check_buffer(machine, pattern, config.rollup.voucher_hashes)
    check_buffer(machine, pattern, config.rollup.notice_hashes)

    assert(machine:read_iflags_H())

    local mcycle = machine:read_mcycle()
    assert(mcycle == final_mcycle, "[mcycle] expected:" .. final_mcycle .. " got: " .. mcycle)

    local exit = machine:read_htif_tohost_data() >> 1
    assert(exit == exit_payload, "[exit] expected: " .. exit_payload .. " got: " .. exit)

    stderr("    passed\n")
end

stderr("testing rollup\n")
test(config)
