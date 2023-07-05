#!/usr/bin/env lua5.4

local cartesi = require("cartesi")
local test_util = require("tests.util")

local config_base = {
    processor = {
        mvendorid = -1,
        mimpid = -1,
        marchid = -1,
    },
    ram = {
        image_filename = test_util.tests_path .. "htif_console.bin",
        length = 0x4000000,
    },
}

local function stderr(...) io.stderr:write(string.format(...)) end

local final_mcycle = 2137
local exit_payload = 42

local function test(config, console_getchar_enable)
    stderr("  testing console_getchar:%s\n", console_getchar_enable and "on" or "off")
    config.htif = {
        console_getchar = console_getchar_enable,
    }
    local machine <close> = cartesi.machine(config)
    machine:run(math.maxinteger)

    -- should be halted
    assert(machine:read_iflags_H(), "expected iflags_H set")

    -- with the expected payload
    assert(
        (machine:read_htif_tohost_data() >> 1) == exit_payload,
        string.format("exit payload: expected %u, got %u\n", exit_payload, machine:read_htif_tohost_data() >> 1)
    )

    -- at the expected mcycle
    assert(
        machine:read_mcycle() == final_mcycle,
        string.format("mcycle: expected, %u got %u", final_mcycle, machine:read_mcycle())
    )

    stderr("    passed\n")
end

for _, getchar in ipairs({ true, false }) do
    test(config_base, getchar)
end
