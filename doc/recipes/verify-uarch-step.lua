-- Load the Cartesi modules
local cartesi = require("cartesi")

-- Instantiate machine from configuration
local config = require(arg[1])
local machine = cartesi.machine(config)

-- Advance to the requested mcycle and uarch_cycle
local mcycle = assert(tonumber(arg[2]), "missing mcycle")
local ucycle = assert(tonumber(arg[3]), "missing uarch_cycle")
machine:run(mcycle)
machine:run_uarch(ucycle)

-- Obtain state hash before step, access log, and state hash after step
local hash_before = machine:get_root_hash()
local log = machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
local hash_after = machine:get_root_hash()

-- Potentially mess with the access log to provoke a verification failure
if arg[4] then
    local env = { string = string, cartesi = cartesi, log = log }
    local f = assert(load(arg[4], arg[4], "t", env))
    f()
end

-- Verify the uarch step access log
machine:verify_step_uarch(hash_before, log, hash_after)
io.stderr:write("State transition accepted!\n")
