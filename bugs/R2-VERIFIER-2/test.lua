#!/usr/bin/env lua5.4
-- R2-VERIFIER-2: the send-cmio-response (input delivery) verifier accepts read accesses that carry
-- arbitrary, unchecked `written` / `written_hash` fields (trailing log data).
--
-- THREAT_MODEL.md R3: conditions on the log are validity conditions, and a log with trailing data must be
-- rejected. Section 4: relayed logs are adversarial. src/replay-send-cmio-state-access.hpp check_read()
-- checks type, address, size, read data/hash and the proof, but never that a read access has no written
-- data and no written hash. The uarch step/reset verifiers (src/uarch-replay-state-access.hpp
-- check_access_type) reject the same defect, so the two verifier families also disagree on log validity.
-- The after-hash is unaffected, so section 8 rates this Medium ("a verifier that accepts trailing data that
-- does not affect its result (R3)").
--
-- The test:
--   1. puts a small machine at a manual yield with the accepted reason, logs an advance-state delivery;
--   2. checks the honest log verifies (harness sanity);
--   3. control: junk written/written_hash on a read access of a uarch step log is rejected;
--   4. asserts the CORRECT behavior: the same junk on each read access of the delivery log must be rejected.
-- It exits nonzero on feature/prt-audit (the delivery verifier accepts it) and 0 once fixed.
local cartesi = require("cartesi")

local ADVANCE = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
local JUNK_HASH = string.rep("\xAB", 32)
local JUNK_DATA = string.rep("\xCD", 32)

local function deep_copy(t)
    if type(t) ~= "table" then return t end
    local c = {}
    for k, v in pairs(t) do c[k] = deep_copy(v) end
    return c
end

-- 1. Machine waiting at a manual yield with the accepted reason.
local m = cartesi.machine({ ram = { length = 1 << 20 } }, {})
m:write_reg("iflags_Y", 1)
m:write_reg("htif_tohost", (cartesi.HTIF_DEV_YIELD << 56) | (cartesi.HTIF_YIELD_CMD_MANUAL << 48)
    | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED << 32))
local before = m:get_root_hash()
local input = "hello"
local log = m:log_send_cmio_response(ADVANCE, input, before)
local after = m:get_root_hash()
assert(after ~= before, "harness: delivery did not change the state")

-- 2. Honest log verifies.
local ok, res = pcall(cartesi.machine.verify_send_cmio_response, cartesi.machine, ADVANCE, input, before, log, before)
assert(ok and res == after, "harness: honest delivery log does not verify: " .. tostring(res))

-- 3. Control: the uarch step verifier rejects the same defect.
local m2 = cartesi.machine({ ram = { length = 1 << 20 } }, {})
local b2 = m2:get_root_hash()
local slog = m2:log_step_uarch()
assert(slog.accesses[1].type == "read", "harness: first uarch access is not a read")
local bad_slog = deep_copy(slog)
bad_slog.accesses[1].written_hash = JUNK_HASH
bad_slog.accesses[1].written = JUNK_DATA
assert(pcall(cartesi.machine.verify_step_uarch, cartesi.machine, b2, slog), "harness: honest uarch log rejected")
local cok, cerr = pcall(cartesi.machine.verify_step_uarch, cartesi.machine, b2, bad_slog)
assert(not cok, "harness: control failed, uarch verifier accepted junk written data on a read access")
print("control: verify_step_uarch rejects junk on a read access: " .. tostring(cerr))

-- 4. The delivery verifier must reject junk written fields on every read access.
local accepted = {}
local nreads = 0
for i, a in ipairs(log.accesses) do
    if a.type == "read" then
        nreads = nreads + 1
        for _, variant in ipairs({ "both", "written_hash", "written" }) do
            local bad = deep_copy(log)
            if variant ~= "written" then bad.accesses[i].written_hash = JUNK_HASH end
            if variant ~= "written_hash" then bad.accesses[i].written = JUNK_DATA end
            local vok, vres = pcall(cartesi.machine.verify_send_cmio_response, cartesi.machine, ADVANCE, input,
                before, bad, before)
            if vok then
                accepted[#accepted + 1] = string.format("access %d (addr 0x%x, %s)%s", i, a.address, variant,
                    vres == after and " -> honest after-hash" or " -> DIFFERENT after-hash")
            end
        end
    end
end
assert(nreads > 0, "harness: delivery log has no read accesses")

if #accepted > 0 then
    for _, s in ipairs(accepted) do print("accepted: " .. s) end
    print(string.format("FAIL: verify_send_cmio_response accepted %d logs whose read accesses carry junk " ..
        "written/written_hash (trailing log data, R3); verify_step_uarch rejects the same defect", #accepted))
    os.exit(1)
end
print("OK: verify_send_cmio_response rejects junk written data on read accesses")
os.exit(0)
