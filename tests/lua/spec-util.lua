-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local util = require("cartesi.util")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("cartesi.util", function()
    it("protects calls while preserving their results", function()
        local protected = util.protect(function(a, b)
            return a + b, nil, a * b
        end)
        local sum, middle, product = protected(2, 3)
        expect.equal(sum, 5)
        expect.equal(middle, nil)
        expect.equal(product, 6)
    end)

    it("returns errors", function()
        local protected = util.protect(function()
            error("failed", 0)
        end)
        local result, err = protected()
        expect.equal(result, nil)
        expect.equal(err, "failed")
    end)

    it("allows coroutine yields", function()
        local protected = util.protect(function(value)
            return coroutine.yield(value)
        end)
        local cortn = coroutine.create(protected)
        local ok, value = coroutine.resume(cortn, "before")
        expect.equal(ok, true)
        expect.equal(value, "before")
        ok, value = coroutine.resume(cortn, "after")
        expect.equal(ok, true)
        expect.equal(value, "after")
    end)
end)

lester.report()
