-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local lester = require("cartesi.third-party.lester")
local util = require("cartesi.tests.util")
local rejections = require("cartesi.tests.step-log-slice-rejections")
lester.parse_args()

local function reject(fn, expected)
    local ok, err = pcall(fn)
    assert(not ok and tostring(err):find(expected, 1, true), tostring(err))
end

local function machine()
    return cartesi.machine({ ram = { length = 1 << 20 } })
end

lester.describe("page-slice witnesses", function()
    lester.it("uses floor 9 and preserves roots for reads and writes", function()
        local m <close> = machine()
        assert(m:get_runtime_config().log2_slice_floor == nil)
        m:write_reg("pc", 0x80000000)
        m:write_reg("x1", 0x80002000)
        -- sd x2,0(x1); ld x3,0(x1)
        m:write_memory(0x80000000, string.pack("<I4I4", 0x0020b023, 0x0000b183))
        m:write_reg("x2", 0x1122334455667788)
        local before = m:get_root_hash()
        local bytes = m:log_step(2)
        assert(cartesi.machine:verify_step(before, bytes, 2) == m:get_root_hash())
        local log = util.parse_step_log(bytes)
        assert(log.signature == "CTSI\4\0\0\0")
        local found_floor = false
        for _, page in ipairs(log.pages) do
            assert(page.log2_size >= 9)
            assert(page.offset & ((1 << page.log2_size) - 1) == 0)
            found_floor = found_floor or page.log2_size == 9
        end
        assert(found_floor)
    end)

    for _, case in ipairs(rejections) do
        lester.it("rejects " .. case.tag, function()
            local m <close> = machine()
            local before = m:get_root_hash()
            local bytes = m:log_step(1)
            local log = util.parse_step_log(bytes)
            if case.mutate then
                case.mutate(log)
            end
            bytes = util.serialize_step_log(log)
            if case.wire then
                bytes = case.wire(bytes)
            end
            reject(function()
                cartesi.machine:verify_step(before, bytes, 1)
            end, case.error)
        end)
    end

    for _, write in ipairs({ false, true }) do
        lester.it("checks slice bounds on a hot TLB " .. (write and "write" or "read"), function()
            local m <close> = machine()
            m:write_reg("pc", 0x80000000)
            m:write_reg("x1", 0x80002000)
            -- Access two adjacent leaves of the same page. The second access hits
            -- the TLB initialized by the first, bypassing address resolution.
            local first, second = 0x0000b103, 0x0200b183 -- ld x2,0(x1); ld x3,32(x1)
            if write then
                first, second = 0x0020b023, 0x0230b023
            end -- sd x2,0(x1); sd x3,32(x1)
            m:write_memory(0x80000000, string.pack("<I4I4", first, second))
            local before = m:get_root_hash()
            local bytes = m:log_step(2)
            assert(cartesi.machine:verify_step(before, bytes, 2) == m:get_root_hash())
            local log = util.parse_step_log(bytes)
            util.restrict_step_log_slice(log, 0x80002, 0, 5)
            assert(util.recompute_step_log_root(log) == before, "tampered proof must still match pre-state")
            bytes = util.serialize_step_log(log)
            -- One instruction succeeds; the second crosses the slice's upper bound.
            cartesi.machine:verify_step(before, bytes, 1)
            reject(function()
                cartesi.machine:verify_step(before, bytes, 2)
            end, "access outside witnessed slice")
        end)
    end

    lester.it("checks an instruction fetch beyond a cached code slice", function()
        local m <close> = machine()
        m:write_reg("pc", 0x8000001c)
        m:write_memory(0x8000001c, string.pack("<I4I4", 0x00000013, 0x00000013))
        local before = m:get_root_hash()
        local bytes = m:log_step(2)
        local log = util.parse_step_log(bytes)
        util.restrict_step_log_slice(log, 0x80000, 0, 5)
        assert(util.recompute_step_log_root(log) == before)
        bytes = util.serialize_step_log(log)
        cartesi.machine:verify_step(before, bytes, 1)
        reject(function()
            cartesi.machine:verify_step(before, bytes, 2)
        end, "access outside witnessed slice")
    end)

    lester.it("checks the entire padded CMIO write", function()
        local m <close> = machine()
        m:write_reg("iflags_Y", 1)
        m:write_reg(
            "htif_tohost",
            (cartesi.HTIF_DEV_YIELD << 56)
                | (cartesi.HTIF_YIELD_CMD_MANUAL << 48)
                | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED << 32)
        )
        local before = m:get_root_hash()
        local data = string.rep("a", 33)
        local bytes = m:log_send_cmio_response(0, data, before)
        local log = util.parse_step_log(bytes)
        util.restrict_step_log_slice(log, cartesi.AR_CMIO_RX_BUFFER_START >> 12, 0, 5)
        assert(util.recompute_step_log_root(log) == before)
        reject(function()
            cartesi.machine:verify_send_cmio_response(0, data, before, util.serialize_step_log(log), before)
        end, "access outside witnessed slice")
    end)
end)
lester.report()
lester.exit()
