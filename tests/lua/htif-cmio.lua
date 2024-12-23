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

local config_base = {
    ram = {
        -- This test will fetch the cmio buffers from the PMA entries; check
        -- that `rx_buffer` is filled with a byte pattern;
        -- then write a byte pattern into `tx_buffer` to be checked inside.
        image_filename = test_util.tests_path .. "htif_cmio.bin",
        length = 0x4000000,
    },
}

local function stderr(...)
    io.stderr:write(string.format(...))
end

local final_mcycle = 1835101
local exit_payload = 0

local function test(config)
    local pattern = "\xef\xcd\xab\x89\x67\x45\x23\x01"
    local machine <close> = cartesi.machine(config)

    -- fill input with `pattern`
    local rx_length = 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE
    machine:write_memory(cartesi.PMA_CMIO_RX_BUFFER_START, string.rep(pattern, rx_length / 8), rx_length)

    machine:run(math.maxinteger)

    -- check that buffers got filled in with `pattern`
    local tx_length = 1 << cartesi.PMA_CMIO_TX_BUFFER_LOG2_SIZE
    assert(string.rep(pattern, tx_length / 8) == machine:read_memory(cartesi.PMA_CMIO_TX_BUFFER_START, tx_length))

    assert(machine:read_reg("iflags_H") ~= 0)

    local mcycle = machine:read_reg("mcycle")
    assert(mcycle == final_mcycle, "[mcycle] expected:" .. final_mcycle .. " got: " .. mcycle)

    local exit = machine:read_reg("htif_tohost_data") >> 1
    assert(exit == exit_payload, "[exit] expected: " .. exit_payload .. " got: " .. exit)

    stderr("    passed\n")
end

stderr("testing cmio\n")
test(config_base)
