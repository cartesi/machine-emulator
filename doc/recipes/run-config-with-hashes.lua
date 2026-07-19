-- Load the Cartesi module
local cartesi = require("cartesi")

-- Writes formatted text to stderr
local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Instantiate machine from configuration
local config = require(arg[1])
local machine = cartesi.machine(config)

-- Print the initial cycle count and root hash
stderr("%u: %s\n", machine:read_reg("mcycle"), cartesi.tohex(machine:get_root_hash()))

-- Run machine until it halts or yields manual
local break_reason
repeat
    break_reason = machine:run(math.maxinteger)
until break_reason == cartesi.BREAK_REASON_HALTED or break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY

-- Print machine status
if break_reason == cartesi.BREAK_REASON_HALTED then
    stderr("\nHalted\n")
else
    stderr("\nYielded manual\n")
end
stderr("Cycles: %u\n", machine:read_reg("mcycle"))

-- Print the final cycle count and root hash
stderr("%u: %s\n", machine:read_reg("mcycle"), cartesi.tohex(machine:get_root_hash()))
