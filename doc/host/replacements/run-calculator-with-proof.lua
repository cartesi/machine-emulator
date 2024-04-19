-- Load the Cartesi module
local cartesi = require"cartesi"

-- Load the proof verifiction module
local proof = require"cartesi.proof"

-- Instantiate machine from configuration
local config = require"config.calculator"
local machine = cartesi.machine(config)

-- Write expression to input drive
local input_drive = config.flash_drive[2]
machine:write_memory(input_drive.start, table.concat(arg, " ") .. "\n")

-- Run machine until it halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(math.maxinteger)
end

-- Obtain value proof for output flash drive
local output_state_hash = machine:get_root_hash()
local output_drive = config.flash_drive[3]
local output_proof = machine:get_proof(output_drive.start, 12)

-- Verify proof
proof.slice_assert(output_state_hash, output_proof)
print("\nOutput drive proof accepted!\n")

print((string.unpack("z", machine:read_memory(output_drive.start, output_drive.length))))
