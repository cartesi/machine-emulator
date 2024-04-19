-- Load the Cartesi module
local cartesi = require"cartesi"

-- Instantiate machine from template
local machine = cartesi.machine("calculator-template")

-- Get initial config from template
local config = machine:get_initial_config()

-- Replace input flash drive
local input = config.flash_drive[2]
input.image_filename = assert(arg[1], "missing input image filename")
machine:replace_memory_range(input)

-- Replace output flash drive
local output = config.flash_drive[3]
output.image_filename = assert(arg[2], "missing output image filename")
output.shared = true
machine:replace_memory_range(output)

-- Run machine until it halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(math.maxinteger)
end
