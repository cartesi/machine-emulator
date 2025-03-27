#!/usr/bin/env lua5.4

local cartesi = require("cartesi")

local config = {
    processor = {
        registers = {
            mcycle = 99,
        },
    },
    ram = {
        length = 1 << 12,
    },
}
local machine <close> = cartesi.machine(config)

io.stderr:write("getting root hash\n")
local old_hash = machine:get_root_hash()
io.stderr:write("getting uarch step log\n")
local access_log = machine:log_step_uarch()
io.stderr:write("getting new root hash\n")
local new_hash = machine:get_root_hash()
io.stderr:write("verifying step log\n")
cartesi.machine:verify_step_uarch(old_hash, access_log, new_hash, {})
print("ok")
