#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local ram = cartesi.AR_RAM_START
local native <close> = cartesi.machine({ ram = { length = 1 << 20 } })
local uarch <close> = cartesi.machine({ ram = { length = 1 << 20 } })
for _, m in ipairs({ native, uarch }) do
    m:write_reg("mstatus", m:read_reg("mstatus") | (1 << 13))
end

local count = 0
local max_cycles = 0
local function compare(bits, operand, rounding, dynamic)
    local instruction = (bits == 64 and 0x5a000053 or 0x58000053)
        | (1 << 15)
        | ((dynamic and 7 or rounding) << 12)
        | (3 << 7)
    if bits == 32 then
        operand = operand | 0xffffffff00000000
    end
    for _, m in ipairs({ native, uarch }) do
        m:write_reg("pc", ram)
        m:write_memory(ram, string.pack("<I4", instruction))
        m:write_reg("f1", operand)
        m:write_reg("fcsr", (rounding << 5) | (count % 32))
    end
    native:run(native:read_reg("mcycle") + 1)
    uarch:run_uarch(1 << 20)
    assert(uarch:read_reg("uarch_halt") ~= 0)
    max_cycles = math.max(max_cycles, uarch:read_reg("uarch_cycle"))
    uarch:reset_uarch()
    assert(native:read_reg("pc") == ram + 4, "square root trapped")
    assert(native:read_reg("f3") == uarch:read_reg("f3"), "square-root value differs")
    assert(native:read_reg("fcsr") == uarch:read_reg("fcsr"), "square-root flags differ")
    assert(native:get_root_hash() == uarch:get_root_hash(), "square-root roots differ")
    count = count + 1
end

local edges = {
    [32] = {
        0,
        1,
        0x007fffff,
        0x00800000,
        0x3f7fffff,
        0x3f800000,
        0x3f800001,
        0x40000000,
        0x407fffff,
        0x40800000,
        0x40800001,
        0x7f7fffff,
        0x7f800000,
        0x7f800001,
        0x7fc00000,
    },
    [64] = {
        0,
        1,
        0x000fffffffffffff,
        0x0010000000000000,
        0x3fefffffffffffff,
        0x3ff0000000000000,
        0x3ff0000000000001,
        0x4000000000000000,
        0x400fffffffffffff,
        0x4010000000000000,
        0x4010000000000001,
        0x7fefffffffffffff,
        0x7ff0000000000000,
        0x7ff0000000000001,
        0x7ff8000000000000,
    },
}
local state = 0x1cba98609cd53b72
local function random_word()
    state = state ~ (state << 13)
    state = state ~ (state >> 7)
    state = state ~ (state << 17)
    return state
end
for _, bits in ipairs({ 32, 64 }) do
    for rounding = 0, 4 do
        for _, dynamic in ipairs({ false, true }) do
            for _, value in ipairs(edges[bits]) do
                compare(bits, value, rounding, dynamic)
                compare(bits, value | (1 << (bits - 1)), rounding, dynamic)
            end
            for _ = 1, 256 do
                local value = random_word()
                if bits == 32 then
                    value = value & 0xffffffff
                end
                compare(bits, value, rounding, dynamic)
            end
        end
    end
end
print(
    string.format("FP square root: %d native/uarch values, flags, and roots matched; max %d cycles", count, max_cycles)
)
