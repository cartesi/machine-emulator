#!/usr/bin/env lua5.4
-- Support script for R13-ROLEVERSION-3. Runs the real doc/recipes/prt-player.lua (--kind=honest)
-- against a mock chain and reports whether its startup checks accept the deployment.
--
-- Usage: lua5.4 run-player.lua SCENARIO
--
-- SCENARIO selects the deployed CartesiStateTransition the factory points at:
--   pristine-mismatch : UARCH_PRISTINE_STATE_HASH differs (control: the player must refuse);
--   marchid-mismatch  : same pristine hash, CM_MARCHID = MARCHID + 1, other bytecode;
--   split-mismatch    : same pristine hash and CM_MARCHID, but bytecode compiled from a
--                       machine-solidity-step with ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = 47 and
--                       ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = 25 (factory heights still 62/30).
--
-- Only the network boundary is mocked: prt-cast's JSON-RPC transport, its `cast wallet address`
-- subprocess, and the Dave artifacts (a minimal ABI with the view functions the player calls).
-- The player's own code runs unmodified: its pristine-hash assertion and bridge.read_geometry.
-- The first thing the player does after all its deployment checks is ask `cast` for the signer's
-- address; the mock raises a sentinel there. The script prints one line:
--   RESULT accepted              -- the player passed every startup check (sentinel reached)
--   RESULT refused <message>     -- the player raised before the sentinel
-- and the list of eth_call/RPC methods the player made.
package.path = "./vendor/?.lua;" .. package.path -- dkjson
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local prt = require("prt")
local cast = require("prt-cast")
local eth = require("prt-ethereum")

local scenario = assert(arg[1], "usage: run-player.lua SCENARIO")
local geometry = prt.new_geometry(10) -- the recipe factory: heights 62/30, log2step 30/0

local function address(tag)
    return "0x" .. string.rep("0", 40 - #tag) .. tag
end
local APP, CONSENSUS, INPUT_BOX = address("a1"), address("c0"), address("b0")
local FACTORY, STATE_TRANSITION = address("f0"), address("5e")

local function fn(name, inputs)
    return { type = "function", name = name, inputs = inputs or {}, outputs = {} }
end
local fake_abi = {
    abi = {
        fn("getOutputsMerkleRootValidator"),
        fn("getInputBox"),
        fn("getApplicationContract"),
        fn("getTournamentFactory"),
        fn("getDeploymentBlockNumber"),
        fn("getClaimStagingPeriod"),
        fn("stateTransition"),
        fn("getTemplateHash"),
        fn("tournamentLevelCount"),
        fn("tournamentParameters", { { type = "uint64", name = "level" } }),
    },
}
eth.artifact = function()
    return fake_abi
end

local calls = {}
local names = {}
local function answer(to, signature, args, types, values)
    local data = evmu.encode_calldata_hex(signature, args or {})
    calls[to .. ":" .. data] = eth.hex(evmu.encode_abi(types, values))
    names[to .. ":" .. data] = signature
end
answer(APP, "getOutputsMerkleRootValidator()", nil, "(address)", { CONSENSUS })
answer(CONSENSUS, "getInputBox()", nil, "(address)", { INPUT_BOX })
answer(CONSENSUS, "getApplicationContract()", nil, "(address)", { APP })
answer(CONSENSUS, "getTournamentFactory()", nil, "(address)", { FACTORY })
answer(CONSENSUS, "getDeploymentBlockNumber()", nil, "(uint256)", { 1 })
answer(CONSENSUS, "getClaimStagingPeriod()", nil, "(uint256)", { 10 })
answer(FACTORY, "stateTransition()", nil, "(address)", { STATE_TRANSITION })
answer(APP, "getTemplateHash()", nil, "(bytes32)", { eth.hex(string.rep("\x11", 32)) })
answer(FACTORY, "tournamentLevelCount()", nil, "(uint64)", { 2 })
answer(
    FACTORY,
    "tournamentParameters(uint64)",
    { 0 },
    "(uint64,uint64,uint64,uint64,uint64,uint64)",
    { 1000, geometry.uarch_height, geometry.mcycle_height, 0, 0, 0 }
)
answer(
    FACTORY,
    "tournamentParameters(uint64)",
    { 1 },
    "(uint64,uint64,uint64,uint64,uint64,uint64)",
    { 1000, 0, geometry.uarch_height, 0, 0, 0 }
)

-- The deployed state-transition contract of each scenario.
local pristine, marchid, code
if scenario == "pristine-mismatch" then
    pristine, marchid = string.rep("\xee", 32), cartesi.MARCHID
    code = "0x6080604052" .. string.rep("ee", 64)
elseif scenario == "marchid-mismatch" then
    pristine, marchid = cartesi.UARCH_PRISTINE_STATE_HASH, cartesi.MARCHID + 1
    code = "0x6080604052" .. string.rep("23", 64)
elseif scenario == "split-mismatch" then
    -- Same published constants; the bytecode differs because INPUT_MASK = 2^67-1, the
    -- SendCmioResponse deadline is 2^47-1 and the epoch span is 2^92 split as 25+47+20.
    pristine, marchid = cartesi.UARCH_PRISTINE_STATE_HASH, cartesi.MARCHID
    code = "0x6080604052" .. string.rep("47", 64)
else
    error("unknown scenario " .. scenario)
end
answer(STATE_TRANSITION, "UARCH_PRISTINE_STATE_HASH()", nil, "(bytes32)", { eth.hex(pristine) })
answer(STATE_TRANSITION, "CM_MARCHID()", nil, "(uint64)", { marchid })

local made = {}
local function rpc(_, method, params)
    if method == "eth_chainId" then
        made[#made + 1] = method
        return "0x7a69"
    elseif method == "eth_call" then
        local call = params[1]
        local key = call.to .. ":" .. call.data
        made[#made + 1] = "eth_call " .. (names[key] or call.data)
        -- An unknown view (e.g. a version probe a fixed player might add) reverts, as on-chain.
        return calls[key], calls[key] == nil and { message = "execution reverted" } or nil
    elseif method == "eth_getCode" then
        made[#made + 1] = method
        return code
    end
    made[#made + 1] = method
    error("harness: unexpected rpc " .. tostring(method) .. " during startup")
end
local real_new = cast.new
cast.new = function(url, timeout)
    local chain = real_new(url, timeout)
    chain.rpc = rpc
    return chain
end
local SENTINEL = "SENTINEL: every deployment check of the player has passed"
cast.run = function()
    error(SENTINEL, 0)
end

local work = os.tmpname()
os.remove(work)
arg = {
    [0] = "prt-player.lua",
    "--rpc=http://127.0.0.1:1/",
    "--application=" .. APP,
    "--keystore=/nonexistent/keystore",
    "--password-file=/nonexistent/password",
    "--state=" .. work .. "-state",
    "--checkpoints=" .. work .. "-checkpoints",
    "--dave=/nonexistent/dave",
    "--kind=honest",
}
local player = assert(loadfile(os.getenv("REPO_DIR") .. "/doc/recipes/prt-player.lua"))
local ok, err = pcall(player)
io.write("CALLS ", table.concat(made, ", "), "\n")
if not ok and tostring(err):find(SENTINEL, 1, true) then
    io.write("RESULT accepted\n")
elseif ok then
    io.write("RESULT harness-error prt-player returned without reaching the sentinel\n")
else
    io.write("RESULT refused ", (tostring(err):gsub("\n.*", "")), "\n")
end
