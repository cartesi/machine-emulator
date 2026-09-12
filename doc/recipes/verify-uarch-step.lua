-- Load the Cartesi module
local cartesi = require("cartesi")

-- Instantiate machine from configuration
local config = require(arg[1])
local machine = cartesi.machine(config)

-- Advance to the requested mcycle and uarch_cycle
local mcycle = assert(tonumber(arg[2]), "missing mcycle")
local ucycle = assert(tonumber(arg[3]), "missing uarch_cycle")
machine:run(mcycle)
machine:run_uarch(ucycle)

-- Obtain state hash before the step and record the step into a binary log
local hash_before = machine:get_root_hash()
local log = machine:log_step_uarch(1)
local hash_after = machine:get_root_hash()

-- Potentially provoke a verification failure. flip:<offset> flips one bit inside the log;
-- truncate chops the log's last bytes; lie gives the verifier a false state hash to start
-- from.
local offset = arg[4] and arg[4]:match("^flip:(%d+)$")
if offset then
    offset = tonumber(offset)
    log = log:sub(1, offset - 1) .. string.char(log:byte(offset) ~ 1) .. log:sub(offset + 1)
elseif arg[4] == "truncate" then
    log = log:sub(1, #log - 32)
elseif arg[4] == "lie" then
    hash_before = string.char(hash_before:byte(1) ~ 1) .. hash_before:sub(2)
end

-- Verify the uarch step log and check the hash it advances to
assert(cartesi.machine:verify_step_uarch(hash_before, log, 1) == hash_after, "state transition rejected")
io.stderr:write("State transition accepted!\n")
