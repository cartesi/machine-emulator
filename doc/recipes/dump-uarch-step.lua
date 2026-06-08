-- Load the Cartesi modules
local cartesi = require("cartesi")
local util = require("cartesi.util")

-- Instantiate machine from configuration
local config = require(arg[1])
local machine = cartesi.machine(config)

-- Advance to the requested mcycle and uarch_cycle
local mcycle = assert(tonumber(arg[2]), "missing mcycle")
local ucycle = assert(tonumber(arg[3]), "missing uarch_cycle")
machine:run(mcycle)
assert(machine:read_reg("mcycle") == mcycle, "machine halted or yielded early")
machine:run_uarch(ucycle)
assert(machine:read_reg("uarch_cycle") == ucycle, "uarch halted before target")

-- Obtain access log and dump it to screen
local log = machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
io.stderr:write(string.format("\nAccess log of uarch step at mcycle=%u uarch_cycle=%u:\n\n", mcycle, ucycle))
util.print_log(log, io.stderr)
