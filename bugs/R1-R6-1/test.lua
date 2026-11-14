-- R1-R6-1: cartesi-machine --print-uarch-cycle-root-hashes, across a rejection, must print for the mcycles
-- after the rejecting instruction the uarch trajectory that starts from the canonical state (R6), not hashes
-- made up from the revert root hash.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local cli = os.getenv("CARTESI_MACHINE") or harness.setup_error("CARTESI_MACHINE not set (source bugs/env.sh)")

    -- Canonical state after the rejection: the valid template to which the input is delivered.
    local template_dir = harness.config_dir("baremetal-template") .. "/machine"
    local pre <close> = harness.machine(template_dir)
    local h0 = pre:get_root_hash()
    -- Uarch trajectory of one mcycle from the canonical state: uarch-cycle hashes, halt hash, reset hash.
    local tail = pre:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0).hashes
    if #tail < 3 or tail[#tail] ~= h0 then harness.setup_error("unexpected trajectory from the template") end

    -- Deliver payload "R" (the guest rejects it), run a few mcycles, store the machine mid-input.
    local m <close> = harness.machine(template_dir)
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "R", h0)
    m:run(m:read_reg("mcycle") + 30)
    if m:read_reg("iflags_Y") ~= 0 then harness.setup_error("guest yielded too early") end
    local start = m:read_reg("mcycle")
    local ok, tmp = harness.sh("mktemp -d")
    tmp = tmp:gsub("%s+$", "")
    if not ok or tmp == "" then harness.setup_error("mktemp failed") end
    local stored = tmp .. "/midinput"
    m:store(stored)
    -- Find the rejecting mcycle on the in-memory machine.
    m:run(cartesi.MCYCLE_MAX)
    if m:read_reg("iflags_Y") == 0 or m:read_reg("htif_tohost_reason") ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
    then
        harness.sh("rm -rf " .. tmp)
        harness.setup_error("guest did not reject")
    end
    local rej = m:read_reg("mcycle") -- the reset at the end of the rejecting instruction is labelled "<rej>:"
    local count = rej - start + 4

    local cmd = string.format("%s --load=%s --print-uarch-cycle-root-hashes=%d,start:%d 2>&1", cli, stored, count,
        start)
    io.stderr:write("running: ", cmd, "\n")
    local _, out = harness.sh(cmd)
    harness.sh("rm -rf " .. tmp)

    -- Parse the printed hashes after the reset of the rejecting mcycle ("<rej>: <h0>").
    local printed = {}
    local after = false
    local found_rej = false
    for line in out:gmatch("[^\n]+") do
        local label, hex = line:match("^([%d,]+): 0x(%x+)$")
        if label then
            if after then
                printed[#printed + 1] = { label = label, hash = harness.unhex(hex) }
            elseif label == tostring(rej) then
                found_rej = true
                if harness.unhex(hex) ~= h0 then
                    harness.setup_error("the reset of the rejecting mcycle is not the revert root hash")
                end
                after = true
            end
        end
    end
    if not found_rej then
        io.stderr:write(out:sub(-2000), "\n")
        harness.setup_error("CLI output has no hash for the rejecting mcycle " .. rej)
    end
    if #printed == 0 then harness.setup_error("CLI printed nothing after the rejection") end

    io.stderr:write(string.format("rejecting mcycle %d; revert root hash %s\n", rej, harness.hex(h0)))
    io.stderr:write(string.format("required: %d uarch-level hashes for mcycle %d (trajectory from the canonical state),"
        .. " first %s\n", #tail, rej, harness.hex(tail[1])))
    io.stderr:write(string.format("printed:  %d hashes after the rejection:\n", #printed))
    for i = 1, math.min(#printed, 4) do
        io.stderr:write(string.format("  %s: %s\n", printed[i].label, harness.hex(printed[i].hash)))
    end

    -- Required: the printed period following the rejection is the trajectory from the canonical state.
    local n = math.min(#printed, #tail)
    local same = #printed >= #tail
    local first_diff
    for i = 1, n do
        if printed[i].hash ~= tail[i] then
            same = false
            first_diff = first_diff or i
        end
    end
    if first_diff then
        io.stderr:write(string.format("first difference at entry %d (%s): printed %s, required %s\n", first_diff,
            printed[first_diff].label, harness.hex(printed[first_diff].hash), harness.hex(tail[first_diff])))
    end
    return harness.expect(same, "R6: in every later mcycle, the uarch-level hashes printed by "
        .. "--print-uarch-cycle-root-hashes are the uarch trajectory that starts from the canonical state")
end)
