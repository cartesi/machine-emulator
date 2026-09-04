-- Load the Cartesi module
local cartesi = require("cartesi")

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

-- Record the step into a binary log and dump its printout to screen
local log = machine:log_step_uarch(1)
io.stderr:write(string.format("\nStep log of uarch step at mcycle=%u uarch_cycle=%u:\n\n", mcycle, ucycle))
io.stderr:write(cartesi.machine:dump_step_uarch(log, 1))
