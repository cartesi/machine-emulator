-- Load the Cartesi modules
local cartesi = require"cartesi"
local util = require"cartesi.util"

-- Instantiate machine from configuration
local machine = cartesi.machine(require(arg[1]))

-- Run machine until it halts or yields
local max_mcycle = tonumber(arg[2])
while not machine:read_iflags_H() and not machine:read_iflags_Y() and machine:read_mcycle() < max_mcycle do
    machine:run(max_mcycle)
end
assert(machine:read_mcycle() == max_mcycle, "Machine halted or yielded early!")

-- Obtain state hash before step
local step_log = machine:step{ annotations = true, proofs = true }

-- Dump access log to screen
io.stderr:write(string.format("\nContents of step %u access log:\n\n", max_mcycle))
util.dump_log(step_log, io.stderr)
