#!/usr/bin/env lua5.4

local cartesi = require"cartesi"
local test_util = require "tests.util"

-- Config yields 5 times with progress
local config_base =  {
  processor = {
    mvendorid = -1,
    mimpid = -1,
    marchid = -1,
  },
  ram = {
    image_filename = test_util.tests_path .. "htif_yield.bin",
    length = 0x4000000,
  },
  rom = {
    image_filename = test_util.tests_path .. "bootstrap.bin"
  },
}

local YIELD_MANUAL = cartesi.machine.HTIF_YIELD_MANUAL
local YIELD_AUTOMATIC = cartesi.machine.HTIF_YIELD_AUTOMATIC

local REASON_PROGRESS    = cartesi.machine.HTIF_YIELD_REASON_PROGRESS
local REASON_RX_ACCEPTED = cartesi.machine.HTIF_YIELD_REASON_RX_ACCEPTED
local REASON_RX_REJECTED = cartesi.machine.HTIF_YIELD_REASON_RX_REJECTED
local REASON_TX_VOUCHER   = cartesi.machine.HTIF_YIELD_REASON_TX_VOUCHER
local REASON_TX_NOTICE  = cartesi.machine.HTIF_YIELD_REASON_TX_NOTICE
local REASON_TX_REPORT   = cartesi.machine.HTIF_YIELD_REASON_TX_REPORT
local REASON_TX_EXCEPTION   = cartesi.machine.HTIF_YIELD_REASON_TX_EXCEPTION

local yields = {
    { mcycle =  13, data = 10, cmd = YIELD_MANUAL, reason = REASON_PROGRESS},
    { mcycle =  44, data = 11, cmd = YIELD_MANUAL, reason = REASON_PROGRESS},
    { mcycle =  75, data = 12, cmd = YIELD_MANUAL, reason = REASON_PROGRESS},
    { mcycle =  107, data = 13, cmd = YIELD_MANUAL, reason = REASON_RX_ACCEPTED},
    { mcycle =  139, data = 14, cmd = YIELD_MANUAL, reason = REASON_RX_REJECTED},
    { mcycle =  171, data = 15, cmd = YIELD_MANUAL, reason = REASON_TX_VOUCHER},
    { mcycle =  203, data = 16, cmd = YIELD_MANUAL, reason = REASON_TX_NOTICE},
    { mcycle = 235, data = 17, cmd = YIELD_MANUAL, reason = REASON_TX_REPORT},
    { mcycle = 267, data = 18, cmd = YIELD_MANUAL, reason = REASON_TX_EXCEPTION},

    { mcycle = 298, data = 20, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS},
    { mcycle = 329, data = 21, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS},
    { mcycle = 360, data = 22, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS},
    { mcycle = 392, data = 23, cmd = YIELD_AUTOMATIC, reason = REASON_RX_ACCEPTED},
    { mcycle = 424, data = 24, cmd = YIELD_AUTOMATIC, reason = REASON_RX_REJECTED},
    { mcycle = 456, data = 25, cmd = YIELD_AUTOMATIC, reason = REASON_TX_VOUCHER},
    { mcycle = 488, data = 26, cmd = YIELD_AUTOMATIC, reason = REASON_TX_NOTICE},
    { mcycle = 520, data = 27, cmd = YIELD_AUTOMATIC, reason = REASON_TX_REPORT},
}

local function stderr(...)
    io.stderr:write(string.format(...))
end

local final_mcycle = 561
local exit_payload = 42
local progress_enable = false

local function test(config, yield_automatic_enable, yield_manual_enable)
    stderr("  testing yield_automatic:%s yield_manual:%s\n",
        yield_automatic_enable and "on" or "off",
        yield_manual_enable and "on" or "off"
    )
    config.htif = {
        yield_automatic = yield_automatic_enable,
        yield_manual = yield_manual_enable,
    }
    local machine = cartesi.machine(config)
    local break_reason
    for _, v in ipairs(yields) do
        if (v.reason == REASON_PROGRESS and progress_enable) or
           (v.cmd    == YIELD_MANUAL and yield_manual_enable) or
           (v.cmd    == YIELD_AUTOMATIC and yield_automatic_enable)
        then
            while not machine:read_iflags_Y() and
                  not machine:read_iflags_X() and
                  not machine:read_iflags_H() do
                break_reason = machine:run()
            end

            -- mcycle should be as expected
            local mcycle = machine:read_mcycle()
            assert(mcycle == v.mcycle,
                string.format("mcycle: expected %d, got %d", v.mcycle, mcycle))

            if yield_automatic_enable and v.cmd == YIELD_AUTOMATIC then
                assert(break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY,
                    "expected break reason yielded automatically")
                assert(machine:read_iflags_X(), "expected iflags_X set")
                assert(not machine:read_iflags_Y(), "expected iflags_Y not set")
            elseif yield_manual_enable and v.cmd == YIELD_MANUAL then
                assert(break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY, "expected break reason yielded manually")
                assert(machine:read_iflags_Y(), "expected iflags_Y set")
                assert(not machine:read_iflags_X(), "expected iflags_X not set")
            else
                assert(false)
            end

            -- data should be as expected
            local data = machine:read_htif_tohost_data()
            local reason = data >> 32
            data = data << 32 >> 32
            assert(data == v.data,
                string.format("data: expected %d, got %d", v.data, data))
            assert(reason == v.reason)
            -- cmd should be as expected
            assert(machine:read_htif_tohost_cmd() == v.cmd)
            -- trying to run it without resetting iflags.Y should not advance
            if machine:read_iflags_Y() then
                machine:run()
                assert(mcycle == machine:read_mcycle())
                assert(machine:read_iflags_Y())
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
    assert(break_reason == cartesi.BREAK_REASON_HALTED)
    assert(machine:read_iflags_H(), "expected iflags_H set")
    -- at the expected mcycle
    assert(machine:read_mcycle() == final_mcycle, string.format("mcycle: expected, %u got %u",
        final_mcycle, machine:read_mcycle()))
    -- with the expected payload
    assert((machine:read_htif_tohost_data() >> 1) == exit_payload,
        string.format("exit payload: expected %u, got %u\n", exit_payload,
            machine:read_htif_tohost_data() >> 1))
    stderr("    passed\n")
end

stderr("testing yield sink\n")

for _, auto in ipairs{true, false} do
    for _, manual in ipairs{true, false} do
        test(config_base, auto, manual)
    end
end
