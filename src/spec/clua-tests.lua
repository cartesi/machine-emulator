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

describe("machine clua", function()
    local dummy_machine <close> = cartesi.machine({
        ram = { length = 0x4000 },
        rom = { image_filename = fs.rom_image },
    })

    it("should fail when trying to pass non machine to a a machine API", function()
        local read_mcycle = dummy_machine.read_mcycle
        expect.fail(function() read_mcycle(1) end, "expected cartesi machine object")
        expect.fail(function() read_mcycle(nil) end, "expected cartesi machine object")
        expect.fail(function() read_mcycle() end, "expected cartesi machine object")
        expect.fail(function() read_mcycle({}) end, "expected cartesi machine object")
        expect.fail(function() read_mcycle(setmetatable({}, {})) end, "expected cartesi machine object")
    end)

    it("should be able to convert a machine to a string", function()
        local s = tostring(dummy_machine)
        expect.truthy(s)
        expect.equal(s:match("[a-z ]+"), "cartesi machine object")
    end)
end)
