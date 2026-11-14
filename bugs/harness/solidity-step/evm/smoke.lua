-- Smoke test of the EVM harness: emulator logs verified by the regenerated step contracts on anvil agree with the
-- emulator's own root hashes and verifiers, and a tampered log is rejected.
-- Run after solidity-step/evm/start.sh: lua5.4 bugs/harness/solidity-step/evm/smoke.lua
local cartesi = require("cartesi")
local harness = require("harness")
local evm = require("evm_step")

local e = evm.connect()
local marchid, pristine = e:constants()
assert(marchid == cartesi.MARCHID, "marchid " .. marchid .. " vs emulator " .. cartesi.MARCHID)
assert(pristine == cartesi.UARCH_PRISTINE_STATE_HASH, "pristine hash constant differs from the emulator")
io.stderr:write("  ok constants: marchid ", marchid, ", pristine ", cartesi.tohex(pristine), "\n")

local function check(name, ok, got, want)
    assert(ok, name .. ": EVM reverted: " .. tostring(got))
    assert(got == want, name .. ": EVM root " .. cartesi.tohex(got) .. " ~= emulator " .. cartesi.tohex(want))
    io.stderr:write("  ok ", name, "\n")
end

-- 1. uarch steps of a Linux boot (first mcycles), and the closing step + reset of an mcycle
do
    local m <close> = cartesi.machine(harness.config_dir("linux-rootfs") .. "/machine", {})
    for i = 1, 20 do
        local before = m:get_root_hash()
        local log = m:log_step_uarch()
        local ok, root, status = e:step(before, log)
        check("uarch step " .. i, ok, root, m:get_root_hash())
        assert(status == 0, "status")
    end
    -- run to the end of the mcycle, then log the last step and the reset
    m:run_uarch(cartesi.UARCH_CYCLE_MAX - 1)
    local before = m:get_root_hash()
    local step_log = m:log_step_uarch()
    local reset_log = m:log_reset_uarch()
    local ok, root = e:step_then_reset(before, step_log, reset_log)
    check("step then reset at the end of the mcycle", ok, root, m:get_root_hash())
end

-- 2. input delivery + first step on the valid template (bare-metal), and a rejected tampered log
do
    local m <close> = cartesi.machine(harness.config_dir("baremetal-template") .. "/machine", {})
    local before = m:get_root_hash()
    local data = harness.encode_advance({ payload = "evm harness" })
    local send_log = m:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, before)
    local step_log = m:log_step_uarch()
    local ok, root = e:send_cmio_response_then_step(before, data, send_log, step_log)
    check("send_cmio_response then step (valid template)", ok, root, m:get_root_hash())
    -- tamper: flip a byte of the first sibling of the step log
    local acc = step_log.accesses[#step_log.accesses]
    local s = acc.sibling_hashes[1]
    acc.sibling_hashes[1] = string.char(s:byte(1) ~ 1) .. s:sub(2)
    local ok2, why = e:send_cmio_response_then_step(before, data, send_log, step_log)
    assert(not ok2, "tampered log accepted")
    io.stderr:write("  ok tampered log rejected (", why:sub(1, 60), ")\n")
end

-- 3. metaStep with counter multiple of the uarch span = step + reset
do
    local m <close> = cartesi.machine(harness.config_dir("baremetal-minimal") .. "/machine", {})
    m:run_uarch(cartesi.UARCH_CYCLE_MAX - 1)
    local before = m:get_root_hash()
    local step_log, reset_log = m:log_step_uarch(), m:log_reset_uarch()
    local ok, root = e:meta_step(before, 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE, step_log, reset_log)
    check("metaStep at a span boundary", ok, root, m:get_root_hash())
end
io.stderr:write("evm step harness smoke ok\n")
