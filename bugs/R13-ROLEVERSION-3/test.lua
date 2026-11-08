#!/usr/bin/env lua5.4
-- R13-ROLEVERSION-3: the honest player detects a deployment/build version mismatch only through the
-- uarch pristine hash.
--
-- R13 makes the interpreter, the uarch, the map from position to transition form and the dispute
-- constants all part of the protocol version, and requires that "the honest operator must be able
-- to detect and refuse a mismatch between its build and a deployment" (A6). The deployed
-- CartesiStateTransition publishes CM_MARCHID precisely "so a claimer can compare it with its own
-- emulator before joining", and its code (UArchStep, UArchReset, SendCmioResponse, AccessLogs,
-- INPUT_MASK/UARCH_CYCLE_MASK) is a pinned artifact the operator can compare by code hash.
--
-- This test runs the real doc/recipes/prt-player.lua (--kind=honest) startup against a mock chain
-- (run-player.lua) in three scenarios:
--   1. control: the state-transition contract has a different UARCH_PRISTINE_STATE_HASH. The player
--      must refuse (it does: this shows the harness reaches the player's version check).
--   2. CM_MARCHID differs from the emulator's cartesi.MARCHID. The player must refuse.
--   3. same pristine hash and CM_MARCHID, but the contract code is a different build: one compiled
--      with the dispute-constant split M=47 / E=25 (still E+M=72, so the factory heights 62/30
--      pass read_geometry's sum-only check). The player must refuse.
-- It also shows the consequence of scenario 3 with the player's real proof encoder: at counter
-- 2^67 the M=47 contract's INPUT_MASK makes the transition an input-window opening (8-byte input
-- prefix + optional CMIO proof), while prt-ethereum.transition_proof encodes a plain uarch step, so
-- every honest proof at that position reverts on-chain.
--
-- Correct behavior (exit 0): the player refuses scenarios 2 and 3 before joining.
-- On feature/prt-audit it accepts both (exit 1).
package.path = "./vendor/?.lua;" .. package.path -- dkjson
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")

local function run(scenario)
    local pipe = assert(io.popen("lua5.4 ./run-player.lua " .. scenario .. " 2>&1"))
    local output = pipe:read("a")
    pipe:close()
    local result = output:match("RESULT ([^\n]*)")
    if not result then
        io.stderr:write(output)
        io.stderr:write("HARNESS ERROR: run-player.lua ", scenario, " printed no RESULT\n")
        os.exit(2)
    end
    print(string.format("  %-18s -> %s", scenario, result))
    return result
end

print("prt-player.lua startup against a mismatching CartesiStateTransition:")
local control = run("pristine-mismatch")
if not control:find("pristine uarch hashes differ", 1, true) then
    io.stderr:write("HARNESS ERROR: the control scenario did not reach the player's pristine-hash check\n")
    os.exit(2)
end
local marchid = run("marchid-mismatch")
local split = run("split-mismatch")
for _, r in ipairs({ marchid, split }) do
    if r:match("^harness") then
        io.stderr:write("HARNESS ERROR: ", r, "\n")
        os.exit(2)
    end
end

-- Consequence of scenario 3, with the player's real encoder and the deployed contract's form map.
local function contract_form(counter, log2_mcycles_per_input)
    -- CartesiStateTransition.transitionState, with LOG2_INPUT_WINDOW_SPAN = M + 20.
    local input_mask = (evmu.bint(1) << (log2_mcycles_per_input + 20)) - 1
    local uarch_mask = (evmu.bint(1) << 20) - 1
    if counter & input_mask == evmu.bint(0) then
        return "input-window opening (8-byte input prefix, CMIO, step)"
    elseif counter & uarch_mask == uarch_mask then
        return "step + reset"
    end
    return "plain uarch step"
end
local counter = evmu.bint(1) << 67
local proof = eth.transition_proof({ step_log = { accesses = {} } }, counter, nil)
local player_form = (#proof == 2) and "plain uarch step (no input prefix)"
    or "input-window opening (" .. ((#proof - 2) // 2) .. "-byte prefix)"
local prefix_at_2_68 = eth.transition_proof({ step_log = { accesses = {} } }, evmu.bint(1) << 68, nil)
print("Counter 2^67 under the split-mismatch deployment:")
print("  player proof encoding    : " .. player_form)
print("  contract (M=47) form     : " .. contract_form(counter, 47))
print("  contract (M=48) form     : " .. contract_form(counter, 48))
print("  player input slot        : " .. eth.coordinates(counter, require("prt").new_geometry(10))
    .. ", contract input slot: " .. tostring(counter >> 67))
print("  player proof at 2^68     : " .. ((#prefix_at_2_68 - 2) // 2) .. "-byte input prefix")
print("  input's mcycle deadline  : player mcycle+2^48-1, contract mcycle+2^47-1")
local consequence = contract_form(counter, 47) ~= contract_form(counter, 48) and #proof == 2

local failures = {}
if marchid == "accepted" then
    failures[#failures + 1] = "CM_MARCHID differs from cartesi.MARCHID"
end
if split == "accepted" then
    failures[#failures + 1] = "the verifier code is a different build (dispute-constant split M=47/E=25)"
end
if #failures > 0 then
    print(
        "FAIL: the honest player joins a deployment whose CartesiStateTransition does not implement its"
            .. " transition function ("
            .. table.concat(failures, "; ")
            .. "): it checks only UARCH_PRISTINE_STATE_HASH and the sum E+M of the factory heights,"
            .. " so it cannot detect and refuse the version mismatch (R13, A6)"
            .. (consequence and "; under the M=47 build its honest proof at counter 2^67 reverts" or "")
    )
    os.exit(1)
end
print("PASS: the player refuses deployments whose verifier is not its build")
os.exit(0)
