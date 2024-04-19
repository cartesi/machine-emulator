-- Load the Cartesi module
local cartesi = require"cartesi"

-- Writes formatted text to stderr
local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Instantiate machine from configuration
local machine = cartesi.machine(require(arg[1]))

local CHUNK = 1000000 -- 1 million cycles
local max_mcycle = CHUNK
-- Loop until machine halts or yields
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    -- Execute at most CHUNK cycles
    machine:run(max_mcycle)
    -- Check if machine yielded automatic
    if machine:read_iflags_X() then
        -- Check if yield was due to progress report
        local reason = machine:read_htif_tohost_data() >> 32
        if reason == cartesi.machine.HTIF_YIELD_REASON_PROGRESS then
            local permil = machine:read_htif_tohost_data()
            -- Show progress feedback
            stderr("Progress: %6.2f\r", permil/10)
        end
    end
    if machine:read_mcycle() == max_mcycle then
        max_mcycle = max_mcycle + CHUNK
        -- Potentially perform other tasks
    end
end
-- Machine is now halted or yielded
stderr("\nCycles: %u\n", machine:read_mcycle())
