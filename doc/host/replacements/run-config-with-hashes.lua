-- Load the Cartesi module
local cartesi = require"cartesi"

-- Writes formatted text to stderr
local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Converts hash from binary to hexadecimal string
local function hexhash(hash)
    return (string.gsub(hash, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

-- Instantiate machine from configuration
local machine = cartesi.machine(require(arg[1]))

-- Print the initial hash
stderr("%u: %s\n", machine:read_mcycle(), hexhash(machine:get_root_hash()))

-- Run machine until it halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(math.maxinteger)
end

-- Print machine status
if machine:read_iflags_H() then
    stderr("\nHalted\n")
else
    stderr("\nYielded manual\n")
end
-- Print cycle count
stderr("Cycles: %u\n", machine:read_mcycle())

-- Print the final hash
stderr("%u: %s\n", machine:read_mcycle(), hexhash(machine:get_root_hash()))
