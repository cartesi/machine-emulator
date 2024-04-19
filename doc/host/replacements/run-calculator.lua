-- Load the Cartesi module
local cartesi = require"cartesi"

-- Instantiate machine from configuration
local calculator_config = require"config.calculator"
local machine = cartesi.machine(calculator_config)

-- Write expression to input drive
local input_drive = calculator_config.flash_drive[2]
machine:write_memory(input_drive.start, table.concat(arg, " ") .. "\n")

-- Run machine until it halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(math.maxinteger)
end

local output_drive = calculator_config.flash_drive[3]
print((string.unpack("z", machine:read_memory(output_drive.start, output_drive.length))))
