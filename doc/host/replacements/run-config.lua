-- Load the Cartesi module
local cartesi = require"cartesi"

-- Instantiate machine from configuration
local machine = cartesi.machine(require(arg[1]))

-- Run machine until it halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(math.maxinteger)
end
