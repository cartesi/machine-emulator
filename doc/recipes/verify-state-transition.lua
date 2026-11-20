-- Load the Cartesi modules
local cartesi = require("cartesi")
local fs = require("cartesi.filesystem")

-- Read the proof, the state hashes before and after the transition, its position, and the posted input (if any)
local proof = assert(loadfile(assert(arg[1], "missing proof"), "t", {}))()
local root_hash_before = fs.read_file(assert(arg[2], "missing state hash before"))
local root_hash_after = fs.read_file(assert(arg[3], "missing state hash after"))
local input_mcycle_offset = assert(tonumber(arg[4]), "missing input_mcycle_offset")
local uarch_cycle = assert(tonumber(arg[5]), "missing uarch_cycle")
local input_data = arg[6] and fs.read_file(arg[6])

-- Verify the logs the transition at this position requires, as the blockchain does
local obtained_root_hash = root_hash_before
if input_mcycle_offset == 0 and uarch_cycle == 0 and input_data then
    obtained_root_hash = cartesi.machine:verify_send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        input_data,
        root_hash_before,
        proof.send_cmio_log,
        root_hash_before
    )
end
obtained_root_hash = cartesi.machine:verify_step_uarch(obtained_root_hash, proof.step_log)
if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
    obtained_root_hash = cartesi.machine:verify_reset_uarch(obtained_root_hash, proof.reset_uarch_log)
end

-- Check the state hash the transition reaches
assert(obtained_root_hash == root_hash_after, "state transition rejected")
io.stderr:write("State transition accepted!\n")
