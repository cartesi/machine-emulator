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
local cartesi = require("cartesi")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("machine step_uarch", function()
    local only_rom_config = {
        ram = { length = 0x4000000 },
        rom = { image_filename = fs.rom_image },
        uarch = {
            ram = { image_filename = fs.uarch_ram_image, length = 0x20000 },
        },
    }
    it("should verify state transition and access log", function()
        local machine <close> = cartesi.machine(only_rom_config)
        local old_hash = machine:get_root_hash()
        local access_log = machine:step_uarch({ proofs = true, annotations = true })
        expect.truthy(access_log.brackets)
        expect.truthy(access_log.accesses)
        expect.truthy(access_log.notes)
        local new_hash = machine:get_root_hash()
        local res = cartesi.machine.verify_state_transition(old_hash, access_log, new_hash, {})
        expect.equal(res, 1)
        res = cartesi.machine.verify_access_log(access_log, {})
        expect.equal(res, 1)
    end)

    for _, proofs in ipairs({ true, false }) do
        it(string.format("should do nothing on max mcycle (proofs=%s)", proofs), function()
            local machine <close> = cartesi.machine(only_rom_config)
            machine:write_mcycle(cartesi.MAX_MCYCLE)
            local log = machine:step_uarch({ proofs = proofs })
            expect.equal(#log.accesses, 7)
            local old_hash = machine:get_root_hash()
            expect.equal(machine:read_mcycle(), cartesi.MAX_MCYCLE)
            local new_hash = machine:get_root_hash()
            expect.equal(old_hash, new_hash)
        end)
    end
end)
