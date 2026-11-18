local cartesi = require("cartesi")
local fs = require("cartesi.filesystem")
local util = require("cartesi.util")

local stored = assert(arg[1], "missing argument: machine")
local input = assert(arg[2], "missing argument: input")
local cmd = assert(cartesi[assert(arg[3], "missing argument: yield command")], "unknown yield command")
local reason = assert(cartesi[assert(arg[4], "missing argument: yield reason")], "unknown yield reason")

-- The stored machine is the state that receives the input
local machine = cartesi.machine(stored)
machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, fs.read_file(input), machine:get_root_hash())
local input_mcycle_base = machine:read_reg("mcycle")

repeat
    local break_reason = machine:run()
    local _, yield_cmd, yield_reason = util.decode_htif_tohost(machine:read_reg("htif_tohost"))
    if yield_cmd == cmd and yield_reason == reason then
        io.stderr:write(machine:read_reg("mcycle") - 1 - input_mcycle_base)
        return
    end
until break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
error("yield not found in the input")
