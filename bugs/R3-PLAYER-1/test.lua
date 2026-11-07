#!/usr/bin/env lua5.4
-- R3-PLAYER-1: the honest player cannot sign the winLeafMatch transaction that proves the input-delivery leaf of
-- an input of about 36 KB or more.
--
-- Every honest transaction goes prt-bridge attempt -> prt-transactions submit -> chain:sign (doc/recipes/prt-cast.lua
-- methods:sign), which passes the whole calldata as ONE argument of `cast mktx` through M.run. M.run joins the quoted
-- arguments into one string and runs it with io.popen, i.e. execve("/bin/sh", {"sh", "-c", <string>}). Linux rejects
-- any single argv string longer than MAX_ARG_STRLEN (32 pages = 131072 bytes) with E2BIG, so io.popen returns nil and
-- the assert raises "Argument list too long". Nothing on the bridge/player path catches it, so the player process dies
-- (and prt-supervise.sh relaunches it into the same crash).
--
-- At mcycle 0 / uarch cycle 0 of an input slot the transition form is "delivery of that input followed by a uarch
-- step", and prt-ethereum transition_proof embeds the whole input in winLeafMatch's bytes argument (as the Solidity
-- verifier requires), plus the send_cmio and step access logs (~27 KB). A 40,000-byte input therefore gives a ~68 KB
-- proof (calldata ~137 K hex characters), which fits Ethereum's per-transaction limits (geth's 128 KiB pool limit,
-- ~1.1M calldata gas) but not one shell argument.
--
-- What the test does (all deterministic, no chain, no network):
--   1. builds a bare-metal rolling guest (guest/), stores a valid template (accepted yield, empty outputs root);
--   2. creates the honest forked player, delivers a 1,024-byte and a 40,000-byte input, seals the epoch;
--   3. for each input k, builds exactly what prt-bridge prepare("winLeafMatch") builds for the delivery leaf
--      (prove_state_transition(k, 0, 0) and eth.transition_proof at cycle k<<68) and checks, as the bridge's
--      proof_check does, that eth.verify_transition from the agreed mcycle leaf reaches the honest uarch leaf 0;
--   4. encodes the Dave LeafTournament winLeafMatch calldata and submits it through the REAL prt-transactions
--      journal and the REAL prt-cast sign/verify_signed code. Only the node's JSON-RPC (an in-process stub) and the
--      `cast` binary (fakebin/cast, which logs that it ran and answers like cast) are replaced.
--
-- Correct behaviour asserted (R4, R12 "every honest proof fits the chain's per-transaction limits" and must be
-- submittable, A7, section 1 completeness): the honest, valid proof of every leaf that fits chain limits is signed
-- and published. On feature/prt-audit the 1 KB input succeeds and the 40 KB input fails with E2BIG before cast runs.
package.path = "./vendor/?.lua;" .. package.path
local json = require("dkjson")
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local evmu = require("cartesi.evmu")
local prt = require("prt")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local transactions = require("prt-transactions")

local here = assert(io.popen("pwd")):read("l")
local signer_address = "0x" .. string.rep("11", 20)
-- Re-run with the stub `cast` first on PATH, so prt-cast's own command string reaches io.popen unchanged.
if not os.getenv("FAKE_CAST_DIR") then
    local work = assert(io.popen("mktemp -d")):read("l")
    assert(os.execute("mkdir -p '" .. work .. "/cast'"))
    local _, _, status = os.execute(string.format(
        "PATH='%s/fakebin':\"$PATH\" FAKE_CAST_DIR='%s/cast' FAKE_CAST_SIGNER='%s' lua5.4 ./test.lua",
        here, work, signer_address))
    os.execute("rm -rf '" .. work .. "'")
    os.exit(status)
end
local cast_dir = os.getenv("FAKE_CAST_DIR")
local work = cast_dir:match("^(.*)/cast$")
local function cleanup()
    os.execute("rm -rf '" .. work .. "'")
end
local function fail(message)
    io.stderr:write("R3-PLAYER-1: ", message, "\n")
    cleanup()
    os.exit(1)
end

-- 1. guest and template
assert(os.execute("bash '" .. here .. "/guest/build.sh' '" .. work .. "'"), "guest build failed")
local template = work .. "/template"
do
    local m <close> = cartesi.new():create({
        ram = { backing_store = { data_filename = work .. "/guest.bin" }, length = 1 << 20 },
    })
    local empty_root =
        hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
    m:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, empty_root)
    assert(m:run(1 << 20) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    m:store(template)
end

-- 2. honest player, two inputs
local tm <close> = cartesi.machine(template)
local dapp = { initial_state_hash = tm:get_root_hash(), machine_directory = template, geometry = prt.new_geometry(10) }
local player <close> = prt.new_forked_player(dapp, "honest")
local sizes = { 1024, 40000 }
for i, size in ipairs(sizes) do
    local path = string.format("%s/input-%d.bin", work, i - 1)
    fs.write_file("A\10\0" .. string.rep("x", size - 3), path) -- accepted after a 10-iteration spin
    player.event_handler.input_added(player, i - 1, path)
end
player.event_handler.epoch_sealed(player, #sizes)
local mc = player.event_handler.commit_mcycle_claim(player)
local mtree = assert(player.trees[cartesi.keccak256(mc.computation_hash_left, mc.computation_hash_right)])

-- 4. node stub (JSON-RPC answers only) + real prt-cast signing with a stub `cast` binary first on PATH
local block = { number = "0x10", hash = "0x" .. string.rep("ab", 32), baseFeePerGas = "0x3b9aca00", gasLimit = "0x1c9c380" }
local published = {}
local chain = cast.new("http://127.0.0.1:1")
function chain.rpc(_, method, params)
    if method == "eth_chainId" then
        return "0x7a69"
    elseif method == "eth_getBlockByNumber" then
        return block
    elseif method == "eth_getTransactionCount" then
        return "0x0"
    elseif method == "eth_maxPriorityFeePerGas" then
        return "0x3b9aca00"
    elseif method == "eth_call" then
        return "0x"
    elseif method == "eth_estimateGas" then
        return "0x200000"
    elseif method == "eth_getTransactionReceipt" or method == "eth_getTransactionByHash" then
        return json.null
    elseif method == "eth_sendRawTransaction" then
        published[#published + 1] = params[1]
        return "0x" .. string.rep("33", 32)
    end
    error("unexpected RPC " .. method)
end
local function cast_log()
    local f = io.open(cast_dir .. "/log", "r")
    if not f then
        return ""
    end
    local s = f:read("a")
    f:close()
    os.remove(cast_dir .. "/log")
    return s
end

-- popen's error message starts with the whole command line; keep its head and its errno text.
local function brief(message)
    message = message:gsub("%s+$", "")
    if #message <= 160 then
        return message
    end
    return message:sub(1, 80) .. " ... " .. message:sub(-40)
end

local signer = { address = signer_address, keystore = "keystore", password_file = "password" }
local results = {}
for i, size in ipairs(sizes) do
    local k = i - 1
    -- 3. what prt-bridge prepare("winLeafMatch") builds for the delivery leaf of input k
    local response = player.event_handler.prove_state_transition(player, k, 0, 0)
    local cycle = evmu.bint(k) << 68
    local input = player:read_input(k)
    assert(#input == size)
    local proof = eth.transition_proof(response, cycle, input)
    local before = k == 0 and eth.hex(dapp.initial_state_hash) or eth.hex(mtree:get_node_hash((k << 38) - 1, 0))
    local uc = player.event_handler.commit_uarch_claim(player, k, 0)
    local utree = assert(player.trees[cartesi.keccak256(uc.computation_hash_left, uc.computation_hash_right)])
    local ok, obtained = pcall(eth.verify_transition, response, cycle, input, before)
    assert(ok and obtained == eth.hex(utree:get_node_hash(0, 0)), "harness: honest proof does not verify natively")
    local z = eth.zero
    local data = evmu.encode_calldata_hex(
        "winLeafMatch((bytes32,bytes32),bytes32,bytes32,bytes)",
        { { z, z }, z, z, proof }
    )
    local calldata_bytes = (#data - 2) // 2
    assert(calldata_bytes < 128 * 1024, "harness: transaction would exceed the 128 KiB pool limit")
    -- submit through the real journal and signer
    local manager = transactions.new({ chain = chain, path = string.format("%s/journal-%d.json", work, k) })
    local observation = { head = 16, hash = block.hash }
    local okay, result = pcall(manager.submit, manager, signer, {
        key = "winLeafMatch:" .. k,
        kind = "winLeafMatch",
        first = 0,
        last = 1000,
        to = "0x" .. string.rep("22", 20),
        data = data,
        value = "0",
        context = { epoch = "0", root = "root" },
    }, observation)
    local log = cast_log()
    local signed = okay and result.published == true and log:find("^mktx") ~= nil
    results[i] = signed
    print(string.format("input %6d bytes: proof %6d bytes, calldata %6d bytes (%6d hex chars), native verify OK -> %s",
        size, (#proof - 2) // 2, calldata_bytes, #data,
        signed and "signed and published (cast ran: " .. log:gsub("\n", "; ") .. ")"
            or ("NOT signed: " .. (okay and json.encode(result) or brief(tostring(result))) ..
                (log == "" and " [stub cast never ran]" or ""))))
end

if not results[1] then
    fail("harness error: even the 1 KB input could not be signed")
end
for i, size in ipairs(sizes) do
    if not results[i] then
        fail(string.format(
            "honest valid winLeafMatch proof for the delivery of a %d-byte input fits chain limits but cannot be signed: "
                .. "prt-cast passes the calldata as one shell argument, popen fails with E2BIG (> 128 KiB argument) "
                .. "and the error escapes submit, crashing the player",
            size
        ))
    end
end
cleanup()
print("R3-PLAYER-1: every honest winLeafMatch proof was signed")
