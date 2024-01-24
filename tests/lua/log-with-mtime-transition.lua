#!/usr/bin/env lua5.4

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
}
local machine <close> = cartesi.machine(config)

local old_hash = machine:get_root_hash()
local access_log = machine:log_uarch_step({ proofs = true })
local new_hash = machine:get_root_hash()
cartesi.machine.verify_uarch_step_state_transition(old_hash, access_log, new_hash, {})
print("ok")
