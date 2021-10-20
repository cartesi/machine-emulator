#!/usr/bin/env lua5.3

local cartesi = require"cartesi"
local test_util = require "tests.util"

-- Config yields 5 times with progress
local config =  {
  processor = {
    mvendorid = -1,
    mimpid = -1,
    marchid = -1,
  },
  ram = {
    image_filename = test_util.tests_path .. "htif_devices.bin",
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

local yields = {
    { mcycle =  13, data = 10, cmd = YIELD_MANUAL, reason = REASON_PROGRESS},
    { mcycle =  26, data = 11, cmd = YIELD_MANUAL, reason = REASON_PROGRESS},
    { mcycle =  39, data = 12, cmd = YIELD_MANUAL, reason = REASON_PROGRESS},
    { mcycle =  53, data = 13, cmd = YIELD_MANUAL, reason = REASON_RX_ACCEPTED},
    { mcycle =  67, data = 14, cmd = YIELD_MANUAL, reason = REASON_RX_REJECTED},
    { mcycle =  81, data = 15, cmd = YIELD_MANUAL, reason = REASON_TX_VOUCHER},
    { mcycle =  95, data = 16, cmd = YIELD_MANUAL, reason = REASON_TX_NOTICE},
    { mcycle = 109, data = 17, cmd = YIELD_MANUAL, reason = REASON_TX_REPORT},

    { mcycle = 122, data = 20, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS},
    { mcycle = 135, data = 21, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS},
    { mcycle = 148, data = 22, cmd = YIELD_AUTOMATIC, reason = REASON_PROGRESS},
    { mcycle = 162, data = 23, cmd = YIELD_AUTOMATIC, reason = REASON_RX_ACCEPTED},
    { mcycle = 176, data = 24, cmd = YIELD_AUTOMATIC, reason = REASON_RX_REJECTED},
    { mcycle = 190, data = 25, cmd = YIELD_AUTOMATIC, reason = REASON_TX_VOUCHER},
    { mcycle = 204, data = 26, cmd = YIELD_AUTOMATIC, reason = REASON_TX_NOTICE},
    { mcycle = 218, data = 27, cmd = YIELD_AUTOMATIC, reason = REASON_TX_REPORT},
}

local function stderr(...)
    io.stderr:write(string.format(...))
end

local final_mcycle = 404
local exit_payload = 42

function test(config, automatic_yield_enable, manual_yield_enable, reset_manual_yields_enable)
    stderr("  testing automatic_yield:%s manual_yield:%s reset_manual_yield:%s\n",
        automatic_yield_enable and "on" or "off",
        manual_yield_enable and "on" or "off",
        reset_manual_yields_enable and "on" or "off"
    )
    config.htif = {
        yield_automatic = automatic_yield_enable,
        yield_manual = manual_yield_enable,
        reset_manual_yields = reset_manual_yields_enable,
    }
    local machine = cartesi.machine(config)
    for i, v in ipairs(yields) do
        if (v.reason == REASON_PROGRESS and progress_enable) or
           (v.cmd    == YIELD_MANUAL and manual_yield_enable) or
           (v.cmd    == YIELD_AUTOMATIC and automatic_yield_enable)
        then
            while not machine:read_iflags_Y() and
                  not machine:read_iflags_X() and
                  not machine:read_iflags_H() do
                machine:run(math.maxinteger)
            end

            if automatic_yield_enable and v.cmd == YIELD_AUTOMATIC then
                assert(machine:read_iflags_X())
                assert(not machine:read_iflags_Y())
            elseif manual_yield_enable and v.cmd == YIELD_MANUAL then
                assert(machine:read_iflags_Y())
                assert(not machine:read_iflags_X())
            else
                assert(false)
            end

            -- mcycle should be as expected
            local mcycle = machine:read_mcycle()
            assert(mcycle == v.mcycle)
            -- data should be as expected
            local data = machine:read_htif_tohost_data()
            local reason = data >> 32
            data = data << 32 >> 32
            assert(data == v.data)
            assert(reason == v.reason)
            -- cmd should be as expected
            assert(machine:read_htif_tohost_cmd() == v.cmd)
            -- trying to run it without resetting iflags.Y should not advance
            if machine:read_iflags_Y() then
                machine:run(math.maxinteger)
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
        machine:run(math.maxinteger)
    end
    -- should be halted
    assert(machine:read_iflags_H())
    -- at the expected mcycle
    assert(machine:read_mcycle() == final_mcycle, machine:read_mcycle())
    -- with the expected payload
    assert((machine:read_htif_tohost_data() >> 1) == exit_payload)
    stderr("    passed\n")
end

stderr("testing yield sink\n")

for _, auto in ipairs{true, false} do
    for _, manual in ipairs{true, false} do
        for _, reset in ipairs{true, false} do
            test(config, auto, manual, reset)
        end
    end
end
