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
local util = require("cartesi.util")
local describe, it, expect = lester.describe, lester.it, lester.expect
local keccak = require("cartesi").keccak

local function hexkeccak(...) return util.hexhash(keccak(...)) end

describe("keccak", function()
    it("should fail when passing invalid arguments", function()
        expect.fail(function() keccak("a", "b", "c") end, "too many arguments")
        expect.fail(function() keccak(1, 2) end, "too many arguments")
        expect.fail(function() keccak() end, "too few arguments")
    end)

    it("should match hashes for uint64 integers", function()
        expect.equal(hexkeccak(0), "011b4d03dd8c01f1049143cf9c4c817e4b167f1d1b83e5c6f0f10d89ba1e7bce")
        expect.equal(hexkeccak(1), "30f692b256e24009bcb34d0ee84da73c298afacc0924e01105e2eb0f01a87fe2")
        expect.equal(hexkeccak(-1), "ad0bfb4b0a66700aeb759d88c315168cc0a11ee99e2a680e548ecf0a464e7daf")
        expect.equal(hexkeccak(0x8000000000000000), "f9b31243137c51434c88c419b2a3d7d2103a13948255efab17ca486946dfbf49")
        expect.equal(hexkeccak(0xf0f10d89ba1e7bce), "86433232ac2024ad7962ccc2fbb7c0219499b98ec24049a81ca6484d206eb288")
    end)

    it("should match hashes for one string", function()
        expect.equal(hexkeccak(""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        expect.equal(hexkeccak("0"), "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d")
        expect.equal(hexkeccak("test"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
        expect.equal(hexkeccak(hexkeccak("")), "79482f93ea0d714e293366322922962af38ecdd95cff648355c1af4b40a78b32")
    end)

    it("should match hashes for two strings", function()
        expect.equal(hexkeccak("", ""), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        expect.equal(hexkeccak("0", ""), "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d")
        expect.equal(hexkeccak("", "0"), "044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d")
        expect.equal(hexkeccak("test", ""), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
        expect.equal(hexkeccak("tes", "t"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
        expect.equal(hexkeccak("te", "st"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
        expect.equal(hexkeccak("t", "est"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
        expect.equal(hexkeccak("", "test"), "9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658")
    end)

    it("should match hashes for large ranges", function()
        expect.equal(
            hexkeccak(string.rep("a", 8191)),
            "b52a6c73f463177a28d89360fb470808ba6572ec75de6db05a3bb044ca4d1009"
        )
        expect.equal(
            hexkeccak(string.rep("a", 4096), string.rep("a", 4095)),
            "b52a6c73f463177a28d89360fb470808ba6572ec75de6db05a3bb044ca4d1009"
        )
    end)
end)
