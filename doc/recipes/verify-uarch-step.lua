-- Load the Cartesi module
local cartesi = require("cartesi")

-- Instantiate machine from configuration
local config = require(arg[1])
local machine = cartesi.machine(config)

-- Advance to the requested mcycle and uarch_cycle
local mcycle = assert(tonumber(arg[2]), "missing mcycle")
local ucycle = assert(tonumber(arg[3]), "missing uarch_cycle")
machine:run(mcycle)
machine:run_uarch(ucycle)

-- Obtain state hash before the step and record the step into a binary log file
local hash_before = machine:get_root_hash()
machine:log_step_uarch(1, "uarch-step.log")
local hash_after = machine:get_root_hash()

-- Potentially mess with the log file to provoke a verification failure. The argument
-- is a Lua expression receiving the log bytes in `log` and returning the tampered bytes.
if arg[4] then
    local f = assert(io.open("uarch-step.log", "rb"))
    local log = f:read("a")
    f:close()
    local env = { string = string, log = log }
    local tampered = assert(load("return " .. arg[4], arg[4], "t", env))()
    f = assert(io.open("uarch-step.log", "wb"))
    f:write(tampered)
    f:close()
end

-- Verify the uarch step log and check the hash it advances to
assert(cartesi.machine:verify_step_uarch(hash_before, "uarch-step.log", 1) == hash_after, "state transition rejected")
io.stderr:write("State transition accepted!\n")
