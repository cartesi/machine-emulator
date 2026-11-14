-- R3-VARSPEC-4: cartesi-machine --print-mcycle-root-hashes must print, for the mcycle boundary that ends the
-- rejecting instruction, only the canonical hash (THREAT_MODEL section 2: obtained from the revert root hash),
-- never the content hash of the rejecting machine in the same "<mcycle>: <hash>" series (R4, R6).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local cli = os.getenv("CARTESI_MACHINE") or harness.setup_error("CARTESI_MACHINE not set (source bugs/env.sh)")

    -- Valid bare-metal template (emit-output guest at an accepted manual yield). Payload "R" is rejected.
    local template_dir = harness.config_dir("baremetal-template") .. "/machine"
    local m <close> = harness.machine(template_dir)
    local h0 = m:get_root_hash() -- revert root hash: the state the rejected input was delivered to
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "R", h0)
    m:run(m:read_reg("mcycle") + 30)
    if m:read_reg("iflags_Y") ~= 0 then harness.setup_error("guest yielded too early") end

    local ok, tmp = harness.sh("mktemp -d")
    tmp = (tmp or ""):gsub("%s+$", "")
    if not ok or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() harness.sh("rm -rf '" .. tmp .. "'") end
    local stored_mid = tmp .. "/midinput" -- mid-input, before the rejecting instruction
    local stored_rej = tmp .. "/rejected" -- at the rejected yield
    local okstore, err = pcall(function()
        m:store(stored_mid)
        m:run(cartesi.MCYCLE_MAX)
        m:store(stored_rej)
    end)
    if not okstore then
        cleanup()
        harness.setup_error("store failed: " .. tostring(err))
    end
    if m:read_reg("iflags_Y") == 0 or m:read_reg("htif_tohost_reason") ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
    then
        cleanup()
        harness.setup_error("guest did not reject")
    end
    local rej = m:read_reg("mcycle") -- boundary that ends the rejecting instruction
    local content = m:get_root_hash() -- the rejecting machine's own content hash
    if content == h0 then
        cleanup()
        harness.setup_error("content hash equals revert root hash; the test cannot tell them apart")
    end
    io.stderr:write(string.format("rejecting mcycle %d\n  canonical (revert root hash) %s\n  rejecting machine content  %s\n",
        rej, harness.hex(h0), harness.hex(content)))

    local scenarios = {
        { name = "window ending at the rejection", dir = stored_mid, opt = string.format("0,start:%d", rej - 3) },
        { name = "stored at the rejected yield, start:<rej>", dir = stored_rej,
            opt = string.format("0,start:%d --max-mcycle=%d", rej, rej + 3) },
        { name = "stored at the rejected yield, no start", dir = stored_rej,
            opt = string.format("0 --max-mcycle=%d", rej + 3) },
    }

    local violations = 0
    for _, sc in ipairs(scenarios) do
        local cmd = string.format("%s --load=%s --print-mcycle-root-hashes=%s 2>&1", cli, sc.dir, sc.opt)
        io.stderr:write("\n[", sc.name, "] running: ", cmd, "\n")
        local _, out = harness.sh(cmd)
        out = out or ""
        local at_rej = {}
        for line in out:gmatch("[^\n]+") do
            local mc, hex = line:match("^(%d+): 0x(%x+)$")
            if mc and tonumber(mc) == rej then at_rej[#at_rej + 1] = harness.unhex(hex) end
        end
        if #at_rej == 0 then
            io.stderr:write(out:sub(-2000), "\n")
            cleanup()
            harness.setup_error("no '" .. rej .. ": <hash>' line printed in scenario: " .. sc.name)
        end
        for i, h in ipairs(at_rej) do
            local tag = (h == h0) and "canonical" or ((h == content) and "REJECTING MACHINE CONTENT HASH" or "OTHER")
            io.stderr:write(string.format("  line %d  %d: %s  (%s)\n", i, rej, harness.hex(h), tag))
            if h ~= h0 then violations = violations + 1 end
        end
    end
    cleanup()

    io.stderr:write(string.format("\nnon-canonical '%d: <hash>' lines printed: %d\n", rej, violations))
    return harness.expect(violations == 0,
        "section 2 / R4 / R6: every hash --print-mcycle-root-hashes prints for the mcycle ending the rejecting "
            .. "instruction must be the canonical hash (the revert root hash)")
end)
