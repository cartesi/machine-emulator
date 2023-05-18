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

local lester = require("spec.util.lester")
local fs = require("spec.util.fs")
local util = require("cartesi.util")
local cartesi = require("cartesi")
local keccak = require("cartesi").keccak
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("machine run", function()
    it("should not break due to mtime interrupts", function()
        local machine <close> = cartesi.machine({
            rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
            ram = { image_filename = fs.tests_path .. "mtime_interrupt.bin", length = 1 << 20 },
        })
        machine:run()
        expect.truthy(machine:read_iflags_H())
        expect.equal(machine:read_htif_tohost_data() >> 1, 0)
        expect.equal(machine:read_mcycle(), cartesi.RTC_FREQ_DIV * 2 + 20)
    end)

    it("should run up to mcycle limit", function()
        local machine <close> = cartesi.machine({
            rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
            ram = { image_filename = fs.tests_path .. "mcycle_overflow.bin", length = 1 << 20 },
        })
        -- Stop the machine before the first RAM instruction
        local WFI_CYCLE = 7
        expect.equal(machine:run(WFI_CYCLE), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        machine:write_mcycle(cartesi.MAX_MCYCLE - 5)
        -- Run once to trigger an interrupt, which might cause an overflow on the
        -- next call to machine:run
        expect.equal(machine:run(cartesi.MAX_MCYCLE - 4), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        expect.equal(machine:run(cartesi.MAX_MCYCLE), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        expect.equal(machine:read_mcycle(), cartesi.MAX_MCYCLE)
    end)

    it("shouldn't change state in max mcycle", function()
        local machine <close> = cartesi.machine({
            rom = { image_filename = fs.tests_path .. "bootstrap.bin" },
            ram = { length = 1 << 20 },
        })
        machine:write_mcycle(cartesi.MAX_MCYCLE)
        local hash_before = machine:get_root_hash()
        expect.equal(machine:run(cartesi.MAX_MCYCLE), cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        local hash_after = machine:get_root_hash()
        expect.equal(hash_before, hash_after)
    end)
end)

describe("machine dump", function()
    local pmas_file_names = {
        "0000000000000000--0000000000001000.bin", -- shadow state
        "0000000000001000--000000000000f000.bin", -- rom
        "0000000000010000--0000000000001000.bin", -- shadow pmas
        "0000000000020000--0000000000006000.bin", -- shadow tlb
        "0000000002000000--00000000000c0000.bin", -- clint
        "0000000040008000--0000000000001000.bin", -- htif
        "0000000080000000--0000000000100000.bin", -- ram
    }
    local config = {
        rom = { image_filename = fs.rom_image },
        ram = { length = 1 << 20 },
    }

    -- Auto remove PMA bin files after each test
    lester.after(function() fs.remove_files(pmas_file_names) end)

    it("should match pmas dumps", function()
        local machine <close> = cartesi.machine(config)
        machine:dump_pmas()
        for _, file_name in ipairs(pmas_file_names) do
            local mem_start, mem_size = file_name:match("^(%x+)%-%-(%x+)%.bin$")
            mem_start, mem_size = tonumber(mem_start, 16), tonumber(mem_size, 16)
            local file_mem = fs.read_file(file_name)
            local machine_mem = machine:read_memory(mem_start, mem_size)
            expect.equal(util.hexhash(keccak(file_mem)), util.hexhash(keccak(machine_mem)))
        end
    end)
end)
