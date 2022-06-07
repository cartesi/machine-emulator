#!/usr/bin/env lua5.3

local cartesi = require"cartesi"

local rom_filename = os.tmpname()
io.open(rom_filename, 'w'):close()
local deleter = setmetatable({}, { __gc = function() os.remove(rom_filename) end } )

local config = {
    processor = {
        marchid = -1,
        mimplid = -1,
        mvendorid = -1,
        mcycle = 99
    },
    ram = {
        length = 1<<12
    },
    rom = {
        image_filename = rom_filename
    },
}

local machine = cartesi.machine(config)
local old_hash = machine:get_root_hash()
local access_log = machine:step({ proofs = true })
local new_hash = machine:get_root_hash()
cartesi.machine.verify_state_transition(old_hash, access_log, new_hash, {})
print("ok")
