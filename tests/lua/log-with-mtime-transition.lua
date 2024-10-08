#!/usr/bin/env lua5.4

local cartesi = require("cartesi")

local config = {
    processor = {
        mcycle = 99,
    },
    ram = {
        length = 1 << 12,
    },
}
local machine <close> = cartesi.machine(config)

local old_hash = machine:get_root_hash()
local access_log = machine:log_step_uarch()
local new_hash = machine:get_root_hash()
cartesi.machine.verify_step_uarch(old_hash, access_log, new_hash, {})
print("ok")
