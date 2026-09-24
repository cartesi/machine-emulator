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
local function compare(bits, a, b, rounding)
    local instruction = (bits == 64 and 0x1a000053 or 0x18000053) | (2 << 20) | (1 << 15) | (rounding << 12) | (3 << 7)
    if bits == 32 then
        a = a | 0xffffffff00000000
        b = b | 0xffffffff00000000
    end
    for _, m in ipairs({ native, uarch }) do
        m:write_reg("pc", ram)
        m:write_memory(ram, string.pack("<I4", instruction))
        m:write_reg("f1", a)
        m:write_reg("f2", b)
        m:write_reg("fcsr", count % 32)
    end
    native:run(native:read_reg("mcycle") + 1)
    uarch:run_uarch(1 << 20)
    assert(uarch:read_reg("uarch_halt") ~= 0)
    max_cycles = math.max(max_cycles, uarch:read_reg("uarch_cycle"))
    uarch:reset_uarch()
    assert(native:read_reg("pc") == ram + 4, "division trapped")
    assert(native:read_reg("f3") == uarch:read_reg("f3"), "division value differs")
    assert(native:read_reg("fcsr") == uarch:read_reg("fcsr"), "division flags differ")
    assert(native:get_root_hash() == uarch:get_root_hash(), "division roots differ")
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
        0x7fefffffffffffff,
        0x7ff0000000000000,
        0x7ff0000000000001,
        0x7ff8000000000000,
    },
}
local random_state = 0x621783cd753cae81
local function random_word()
    random_state = random_state ~ (random_state << 13)
    random_state = random_state ~ (random_state >> 7)
    random_state = random_state ~ (random_state << 17)
    return random_state
end

for _, bits in ipairs({ 32, 64 }) do
    for _, a in ipairs(edges[bits]) do
        for _, b in ipairs(edges[bits]) do
            for signs = 0, 3 do
                for rounding = 0, 4 do
                    compare(bits, a | ((signs & 1) << (bits - 1)), b | ((signs >> 1) << (bits - 1)), rounding)
                end
            end
        end
    end
    for _ = 1, 200 do
        local a, b = random_word(), random_word()
        if bits == 32 then
            a, b = a & 0xffffffff, b & 0xffffffff
        end
        for rounding = 0, 4 do
            compare(bits, a, b, rounding)
        end
    end
end

print(string.format("FP division: %d native/uarch values, flags, and roots matched; max %d cycles", count, max_cycles))
