#!/usr/bin/env lua5.4

local test_util = require("tests.util")
local cartesi = require("cartesi")

local config = {
    processor = {
        marchid = -1,
        mimplid = -1,
        mvendorid = -1,
        mcycle = 99,
    },
    ram = {
        length = 1 << 12,
    },
    dtb = {
        image_filename = "",
    },
    uarch = {
        ram = { length = 1 << 19, image_filename = test_util.create_test_uarch_program() },
    },
}
local machine <close> = cartesi.machine(config)

local old_hash = machine:get_root_hash()
local access_log = machine:step_uarch({ proofs = true })
local new_hash = machine:get_root_hash()
cartesi.machine.verify_state_transition(old_hash, access_log, new_hash, {})
print("ok")
