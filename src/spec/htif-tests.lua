#!/usr/bin/env lua5.4

-- Copyright 2023 Cartesi Pte. Ltd.
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

local cartesi = require("cartesi")
local fs = require("spec.util.fs")
local lester = require("spec.util.lester")
local has_luaposix, unistd = pcall(require, "posix.unistd")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("machine htif", function()
    -- This test will fetch the rollup buffers from the PMA entries; check
    -- that `rx_buffer` and `input_metadata` are filled with a byte patern;
    -- then write a byte pattern into `tx_buffer`, `voucher_hashes` and
    -- `notice_hashes`.
    it("should write/read rollup buffers", function()
        local ROLLUP_BUFFER_LENGTH = 4096
        local machine_config = {
            ram = { image_filename = fs.tests_path .. "htif_rollup.bin", length = 0x4000000 },
            rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
            htif = { yield_automatic = true },
            rollup = {
                rx_buffer = { start = 0x60000000, length = ROLLUP_BUFFER_LENGTH, shared = false },
                tx_buffer = { start = 0x60001000, length = ROLLUP_BUFFER_LENGTH, shared = false },
                input_metadata = { start = 0x60002000, length = ROLLUP_BUFFER_LENGTH, shared = false },
                voucher_hashes = { start = 0x60003000, length = ROLLUP_BUFFER_LENGTH, shared = false },
                notice_hashes = { start = 0x60004000, length = ROLLUP_BUFFER_LENGTH, shared = false },
            },
        }
        local machine <close> = cartesi.machine(machine_config)
        -- fill input with `pattern`
        local pattern = string.rep("\xef\xcd\xab\x89\x67\x45\x23\x01", ROLLUP_BUFFER_LENGTH / 8)
        local rollup = machine_config.rollup
        machine:write_memory(rollup.rx_buffer.start, pattern, rollup.rx_buffer.length)
        -- fill input_metadata with `pattern`
        machine:write_memory(rollup.input_metadata.start, pattern, rollup.input_metadata.length)
        machine:run(math.maxinteger)
        -- check that buffers got filled in with `pattern`
        expect.equal(pattern, machine:read_memory(rollup.tx_buffer.start, rollup.tx_buffer.length))
        expect.equal(pattern, machine:read_memory(rollup.voucher_hashes.start, rollup.voucher_hashes.length))
        expect.equal(pattern, machine:read_memory(rollup.notice_hashes.start, rollup.notice_hashes.length))
        expect.truthy(machine:read_iflags_H())
        expect.equal(machine:read_mcycle(), 8981)
        expect.equal(machine:read_htif_tohost_data() >> 1, 0)
    end)

    local YIELD_MANUAL = cartesi.machine.HTIF_YIELD_MANUAL
    local YIELD_AUTOMATIC = cartesi.machine.HTIF_YIELD_AUTOMATIC
    local yields = {
        { mcycle = 13, data = 10, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_PROGRESS },
        { mcycle = 44, data = 11, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_PROGRESS },
        { mcycle = 75, data = 12, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_PROGRESS },
        { mcycle = 107, data = 13, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED },
        { mcycle = 139, data = 14, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED },
        { mcycle = 171, data = 15, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_TX_VOUCHER },
        { mcycle = 203, data = 16, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_TX_NOTICE },
        { mcycle = 235, data = 17, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_TX_REPORT },
        { mcycle = 267, data = 18, cmd = YIELD_MANUAL, reason = cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION },
        { mcycle = 298, data = 20, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_PROGRESS },
        { mcycle = 329, data = 21, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_PROGRESS },
        { mcycle = 360, data = 22, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_PROGRESS },
        { mcycle = 392, data = 23, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED },
        { mcycle = 424, data = 24, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED },
        { mcycle = 456, data = 25, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_TX_VOUCHER },
        { mcycle = 488, data = 26, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_TX_NOTICE },
        { mcycle = 520, data = 27, cmd = YIELD_AUTOMATIC, reason = cartesi.machine.HTIF_YIELD_REASON_TX_REPORT },
    }
    local function make_yield_test(yield_automatic_enable, yield_manual_enable)
        local test_name =
            string.format("should sink for yield (automatic=%s manual=%s)", yield_automatic_enable, yield_manual_enable)
        it(test_name, function()
            local machine_config = {
                ram = { image_filename = fs.tests_path .. "htif_yield.bin", length = 0x4000000 },
                rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
                htif = { yield_automatic = yield_automatic_enable, yield_manual = yield_manual_enable },
            }
            local machine <close> = cartesi.machine(machine_config)
            local break_reason
            for _, v in ipairs(yields) do
                if
                    (v.cmd == YIELD_MANUAL and yield_manual_enable)
                    or (v.cmd == YIELD_AUTOMATIC and yield_automatic_enable)
                then
                    while not machine:read_iflags_Y() and not machine:read_iflags_X() and not machine:read_iflags_H() do
                        break_reason = machine:run()
                    end
                    -- mcycle should be as expected
                    local mcycle = machine:read_mcycle()
                    expect.equal(mcycle, v.mcycle)

                    if yield_automatic_enable and v.cmd == YIELD_AUTOMATIC then
                        expect.equal(break_reason, cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY)
                        expect.truthy(machine:read_iflags_X())
                        expect.falsy(machine:read_iflags_Y())
                    elseif yield_manual_enable and v.cmd == YIELD_MANUAL then
                        expect.equal(break_reason, cartesi.BREAK_REASON_YIELDED_MANUALLY)
                        expect.truthy(machine:read_iflags_Y())
                        expect.falsy(machine:read_iflags_X())
                    else
                        expect.truthy(false)
                    end
                    -- data should be as expected
                    local data = machine:read_htif_tohost_data()
                    local reason = data >> 32
                    data = data << 32 >> 32
                    expect.equal(data, v.data)
                    expect.equal(reason, v.reason)
                    expect.equal(machine:read_htif_tohost_cmd(), v.cmd)
                    -- trying to run it without resetting iflags.Y should not advance
                    if machine:read_iflags_Y() then
                        machine:run()
                        expect.equal(machine:read_mcycle(), mcycle)
                        expect.truthy(machine:read_iflags_Y())
                    end
                    -- now reset it so the machine can be advanced
                    machine:reset_iflags_Y()
                    machine:reset_iflags_X()
                end
            end
            -- finally run to completion
            while not machine:read_iflags_Y() and not machine:read_iflags_H() do
                break_reason = machine:run()
            end
            -- should be halted
            expect.equal(break_reason, cartesi.BREAK_REASON_HALTED)
            expect.truthy(machine:read_iflags_H())
            -- at the expected mcycle
            expect.equal(machine:read_mcycle(), 561)
            -- with the expected payload
            expect.equal((machine:read_htif_tohost_data() >> 1), 42)
        end)
    end

    make_yield_test(false, false)
    make_yield_test(false, true)
    make_yield_test(true, false)
    make_yield_test(true, true)

    it("should write to console when getchar is disabled", function()
        local machine <close> = cartesi.machine({
            ram = { image_filename = fs.tests_path .. "htif_console.bin", length = 0x4000000 },
            rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
            htif = { console_getchar = false },
        })
        machine:run(math.maxinteger)
        -- should be halted
        expect.truthy(machine:read_iflags_H())
        -- with the expected payload
        expect.equal((machine:read_htif_tohost_data() >> 1), 42)
        -- at the expected mcycle
        expect.equal(machine:read_mcycle(), 2141)
        io.write("\n")
    end)

    -- This test is only enabled if luaposix is installed in the system
    it("should read/write to console when getchar is enabled", function()
        -- create new FD for stdin and write in it,
        -- later the cartesi machine console will consume this value
        local read_fd, write_fd = unistd.pipe()
        unistd.dup2(read_fd, unistd.STDIN_FILENO)
        unistd.write(write_fd, "CTSI")
        local machine <close> = cartesi.machine({
            ram = { image_filename = fs.tests_path .. "htif_console.bin", length = 0x4000000 },
            rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
            htif = { console_getchar = true },
        })
        machine:run(math.maxinteger)
        -- should be halted
        expect.truthy(machine:read_iflags_H())
        -- with the expected payload
        expect.equal((machine:read_htif_tohost_data() >> 1), 42)
        -- at the expected mcycle
        expect.equal(machine:read_mcycle(), 2141)
        io.write("\n")

        -- we cannot initialize TTY twice
        expect.fail(
            function()
                cartesi.machine({
                    ram = { image_filename = fs.tests_path .. "htif_console.bin", length = 0x4000000 },
                    rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
                    htif = { console_getchar = true },
                })
            end,
            "TTY already initialized"
        )
    end, has_luaposix)
end)
