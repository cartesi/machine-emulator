-- Smoke test of a deployed Dave build (chain/deploy.sh <variant>): its CartesiStateTransition, compiled with the
-- regenerated step, verifies real emulator transitions through transitionState(machineState, counter, proofs,
-- provider), with the encoding of doc/recipes/prt-ethereum.lua:
--   counter 1          (not an input opening, not a span end): one uarch step
--   counter 2^20 - 1   (span end): the closing uarch step + uarch reset
-- and rejects a tampered proof. Usage: lua5.4 smoke-stf.lua <deployment.json>
local cartesi = require("cartesi")
local json = require("dkjson")
local harness = require("harness")
local evm = require("evm_step")

local d = assert(json.decode(harness.read_file(assert(arg[1], "usage: smoke-stf.lua deployment.json"))))
local e = evm.connect(d.rpc_url, d.stf)
local SIG = "transitionState(bytes32,uint256,bytes,address)"
local function transition(root, counter, proofs)
    local ok, r = e:call(evm.abi_encode(SIG, {
        { "bytes32", root },
        { "uint", counter },
        { "bytes", proofs },
        { "uint", 0 }, -- provider: unused away from input openings
    }))
    if not ok then return false, r end
    return true, r:sub(1, 32)
end

local m <close> = cartesi.machine(harness.config_dir("linux-rootfs") .. "/machine", {})
m:run(1000)
local before = m:get_root_hash()
local log = m:log_step_uarch()
local ok, root = transition(before, 1, evm.concat_logs(log))
assert(ok, "transitionState reverted: " .. tostring(root))
assert(root == m:get_root_hash(), "STF root differs from the emulator")
io.stderr:write("  ok ", d.variant, ": transitionState counter 1 (uarch step)\n")

m:run_uarch(cartesi.UARCH_CYCLE_MAX - 1)
before = m:get_root_hash()
local step_log, reset_log = m:log_step_uarch(), m:log_reset_uarch()
ok, root = transition(before, (1 << 20) - 1, evm.concat_logs(step_log, reset_log))
assert(ok, "transitionState reverted: " .. tostring(root))
assert(root == m:get_root_hash(), "STF root differs from the emulator after step+reset")
io.stderr:write("  ok ", d.variant, ": transitionState counter 2^20-1 (step + reset)\n")

local proofs = evm.concat_logs(step_log, reset_log)
local bad = proofs:sub(1, 40) .. string.char(proofs:byte(41) ~ 0xff) .. proofs:sub(42)
ok = transition(before, (1 << 20) - 1, bad)
assert(not ok, "tampered proof accepted")
io.stderr:write("  ok ", d.variant, ": tampered proof rejected\n")
io.stderr:write("stf smoke ok (", d.variant, ")\n")
