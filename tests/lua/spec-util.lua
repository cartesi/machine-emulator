-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local util = require("cartesi.util")
local describe, it, expect = lester.describe, lester.it, lester.expect

describe("cartesi.util", function()
    it("finds the machine at the end of a runner chain", function()
        local machine = require("cartesi").machine
        local GDBStub = require("cartesi.gdbstub")
        local gdb = GDBStub.new(machine)
        local runner = { runner = gdb }
        expect.equal(util.get_runner_machine(machine), machine)
        expect.equal(util.get_runner_machine(gdb), machine)
        expect.equal(util.get_runner_machine({ runner = runner }), machine)
        expect.equal(rawget(gdb, "runner"), machine)
        expect.equal(rawget(gdb, "machine"), nil)
    end)

    it("rejects runner chains that do not end at a machine", function()
        local file <close> = assert(io.tmpfile())
        for _, terminal in ipairs({ false, 1, "machine", {}, file }) do
            local ok, err = pcall(util.get_runner_machine, { runner = terminal })
            expect.equal(ok, false)
            expect.truthy(err:find("runner chain must end at a Cartesi machine", 1, true))
        end
        local ok = pcall(util.get_runner_machine, nil)
        expect.equal(ok, false)
    end)

    it("forwards methods through wrappers with the correct receiver and caches them", function()
        local lookups = 0
        local underlying = setmetatable({ value = 7 }, {
            __index = function(self, name)
                lookups = lookups + 1
                if name == "read" then
                    return function(receiver, ...)
                        expect.equal(receiver, self)
                        return self.value, ...
                    end
                end
            end,
        })
        local function wrap(object)
            return setmetatable({}, {
                __index = function(self, name)
                    return util.forward_method(self, object, name)
                end,
            })
        end
        local inner = wrap(underlying)
        local outer = wrap(inner)
        local results = table.pack(outer:read("argument", nil))
        expect.equal(results.n, 3)
        expect.equal(results[1], 7)
        expect.equal(results[2], "argument")
        expect.equal(results[3], nil)
        expect.equal(lookups, 1)
        expect.equal(rawget(outer, "read"), outer.read)
        underlying.value = 9
        expect.equal(outer:read(), 9)
        expect.equal(lookups, 1)
        expect.equal(outer.value, nil)
        expect.equal(outer.absent, nil)
        inner.read = function(self)
            expect.equal(self, inner)
            return "override"
        end
        expect.equal(wrap(inner):read(), "override")
    end)

    it("forwards machine methods through the GDB runner without exposing machine data", function()
        local GDBStub = require("cartesi.gdbstub")
        local machine = { mcycle = 12 }
        function machine:read_reg(name)
            expect.equal(self, machine)
            expect.equal(name, "mcycle")
            return self.mcycle
        end
        local runner = GDBStub.new(machine)
        expect.equal(runner:read_reg("mcycle"), 12)
        expect.equal(runner.mcycle, nil)
        expect.equal(runner.run, GDBStub.run)
    end)

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
