#!/usr/bin/env lua5.4
-- R4-VARSTATE-1: a relaunched honest player silently keeps the epoch it stored after a reorganization
-- replaced confirmed input history or the seal; only the running process fails closed.
--
-- Threat model: R4 (the honest operator can always compute the claim), R2 (persisting and restoring must
-- agree with an uninterrupted run), A3 (input bytes come from the on-chain input record), section 2
-- honest operator's path (storing and reloading the machine, computing claims) and honest claim,
-- section 1 completeness failure.
--
-- The epoch listener (doc/recipes/prt-epoch.lua) fails closed when confirmed InputAdded/EpochSealed logs
-- change, by comparing log identities with self.applied, which lives only in memory; once sealed it
-- asserts that the seal's block is still canonical. prt-supervise.sh relaunches the aborted process. The
-- relaunched listener has an empty self.applied and re-delivers the replacement branch, and the reopened
-- stored player (doc/recipes/prt.lua):
--   * input_added returns for every offset < input_count without comparing the bytes with inputs/<n>.bin;
--   * epoch_sealed returns when the mcycle forest exists, before 'sealed input count mismatch';
--   * reopen_epoch_directory records/checks no input identity against the chain.
-- So the player keeps the claim computed over the replaced branch, while the listener (and the bridge's
-- winLeafMatch proofs) use the chain's new bytes.
--
-- Real code throughout: prt.new_stored_player, prt-epoch listener, prt-bridge construction, over a mock
-- chain (as prt-bridge-test.lua does) and a 7-instruction bare-metal template that yields manually with
-- the accepted reason, with the empty outputs root in the TX buffer. No Linux boot.
--
-- Three scenarios, each comparing the relaunched player's root claim with a fresh honest player's claim
-- over the canonical (replacement) chain:
--   1 open epoch: input 3's bytes replaced before the seal; branch later sealed.
--   2 sealed epoch: reorg across the seal replaces input 3's bytes; the seal is re-mined.
--   3 sealed epoch: reorg across the seal drops input 4; the re-mined seal covers 1 input instead of 2.
-- Correct behavior: the relaunched process either fails closed (poll raises) or computes the canonical
-- claim. The test exits nonzero if any scenario yields a different claim.
package.path = "./vendor/?.lua;" .. package.path
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")
local epoch = require("prt-epoch")
local cast = require("prt-cast")
local eth = require("prt-ethereum")

local work = os.getenv("R4_VARSTATE_WORK") or "./work"
os.execute("rm -rf '" .. work .. "' && mkdir -p '" .. work .. "'")

-- Template: lui t0,0x40008; lui t1,0x2010; addi t1,t1,1; slli t1,t1,32; addi t1,t1,32; sd t1,0(t0); j .-4
-- i.e. write HTIF tohost = yield manual, accepted reason, 32 bytes of data, forever.
local code = string.pack(
    "<I4I4I4I4I4I4I4",
    0x400082b7,
    0x02010337,
    0x00130313,
    0x02031313,
    0x02030313,
    0x0062b023,
    0xffdff06f
)
local m = cartesi.machine({
    ram = { length = 0x10000 },
    processor = {
        registers = {
            htif = { iyield = cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK | cartesi.HTIF_YIELD_CMD_MANUAL_MASK },
        },
    },
})
m:write_memory(0x80000000, code)
local empty_root =
    hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
m:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, empty_root)
assert(m:run(1000) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness: template did not yield")
local template = work .. "/template"
m:store(template)
local h = m:get_root_hash()
m:destroy()
local dapp = { initial_state_hash = h, machine_directory = template, geometry = prt.new_geometry(10) }

-- Mock chain: tip 10, input policy 4 (head 6). A reorg renames every block from 1 on.
local EPOCH, INPUT_BEGIN = 2, 3
local chain_state = { branch = "orig", logs = nil }
local function block_hash(n)
    return chain_state.branch .. "-block" .. n
end
local source = cast.new("http://unused")
source.tip = 10
function source:rpc(method, args)
    assert(method == "eth_getBlockByNumber", "harness: unexpected rpc " .. method)
    local n = args[1] == "latest" and self.tip or tonumber(args[1])
    return { number = string.format("0x%x", n), hash = block_hash(n) }
end
function source.logs(_, address, head, first_block)
    local result = {}
    for _, item in ipairs(chain_state.logs) do
        local number = item.block
        if item.address == address and number >= (first_block or 0) and number <= head then
            result[#result + 1] = {
                address = item.address,
                blockNumber = string.format("0x%x", number),
                blockHash = block_hash(number),
                logIndex = "0x0",
                removed = false,
                event = item.event,
            }
        end
    end
    return result
end
local function input_log(block, index, bytes)
    return {
        address = "inputbox",
        block = block,
        event = { name = "InputAdded", appContract = "app", index = index, input = eth.hex(bytes) },
    }
end
local function seal_log(block, upper)
    return {
        address = "consensus",
        block = block,
        event = {
            name = "EpochSealed",
            epochNumber = EPOCH,
            initialMachineStateHash = eth.hex(h),
            outputsMerkleRoot = eth.zero,
            inputIndexLowerBound = INPUT_BEGIN,
            inputIndexUpperBound = upper,
            tournament = "tournament",
        },
    }
end

local function new_session(player)
    return epoch.new({
        geometry = dapp.geometry,
        transactions = {},
        chain = source,
        input_policy = 4,
        abi = {
            event = function(_, item)
                return item.event
            end,
        },
        app = "app",
        input_box = "inputbox",
        consensus = "consensus",
        factory = "factory",
        epoch = EPOCH,
        input_begin = INPUT_BEGIN,
        initial_hash = eth.hex(h),
        previous_outputs_root = eth.zero,
        player = player,
        signer = {},
        label = "honest",
    })
end

local function inputs_of(player)
    local list = {}
    for i = 0, player.input_count - 1 do
        list[#list + 1] = player:read_input(i)
    end
    return table.concat(list, ",")
end

local function run_scenario(n, title, before, after)
    print(string.format("== scenario %d: %s", n, title))
    local dir = work .. "/s" .. n
    fs.create_directory(dir)
    local epoch_dir = dir .. "/epoch"
    fs.create_directory(epoch_dir)
    -- Phase A: the running honest process observes the original branch.
    chain_state.branch, chain_state.logs = "orig" .. n, before
    do
        local player <close> = prt.new_stored_player(dapp, "honest", nil, epoch_dir)
        local session = new_session(player)
        session:poll()
        print("  running process stored inputs: " .. inputs_of(player), "sealed:", player.mcycle_forest ~= nil)
        -- Reorg deeper than the input policy: every block from 1 is replaced.
        chain_state.branch, chain_state.logs = "reorg" .. n, after
        local ok, err = pcall(session.poll, session)
        print("  running process after reorg: fails closed =", not ok, err)
        assert(not ok, "harness: running listener should fail closed on the reorg")
    end
    -- Phase B: relaunch (prt-supervise.sh) on the same epoch directory.
    local relaunch_ok, relaunch_err, root_b, stored_b, chain_b
    do
        local player <close> = prt.new_stored_player(dapp, "honest", nil, epoch_dir)
        local session = new_session(player)
        relaunch_ok, relaunch_err = pcall(session.poll, session)
        print("  relaunched process: poll ok =", relaunch_ok, relaunch_err)
        if relaunch_ok then
            assert(session.dispute, "harness: relaunched epoch should be sealed")
            stored_b, chain_b = inputs_of(player), table.concat(session.dispute.inputs, ",")
            root_b = player:new_mcycle_tree():get_root_hash()
        end
    end
    -- Phase C: a fresh honest player over the canonical (replacement) chain.
    local root_c
    do
        local fresh_dir = dir .. "/fresh"
        fs.create_directory(fresh_dir)
        local player <close> = prt.new_stored_player(dapp, "honest", nil, fresh_dir)
        local session = new_session(player)
        session:poll()
        assert(session.dispute, "harness: fresh epoch should be sealed")
        root_c = player:new_mcycle_tree():get_root_hash()
    end
    if not relaunch_ok then
        print("  OK: relaunched process failed closed")
        return true
    end
    print("  relaunched player's stored inputs:   " .. stored_b)
    print("  bridge's (chain) inputs for proofs:  " .. chain_b)
    print("  relaunched claim: " .. cartesi.tohex(root_b))
    print("  canonical claim:  " .. cartesi.tohex(root_c))
    if root_b ~= root_c then
        print(string.format("  FAIL scenario %d: relaunched honest player's root claim is not the canonical claim", n))
        return false, n
    end
    print("  OK")
    return true
end

local failed = {}
local function check(...)
    local ok, n = run_scenario(...)
    if not ok then
        failed[#failed + 1] = n
    end
end

check(
    1,
    "open epoch, reorg replaces input 3's bytes before the seal",
    { input_log(1, 3, "original-input") },
    { input_log(1, 3, "replacement-input"), seal_log(2, 4) }
)
check(
    2,
    "sealed epoch, reorg across the seal replaces input 3's bytes",
    { input_log(1, 3, "original-input"), seal_log(2, 4) },
    { input_log(1, 3, "replacement-input"), seal_log(2, 4) }
)
check(
    3,
    "sealed epoch, reorg across the seal changes the sealed input count from 2 to 1",
    { input_log(1, 3, "input-a"), input_log(2, 4, "input-b"), seal_log(3, 5) },
    { input_log(1, 3, "input-a"), seal_log(2, 4) }
)

os.execute("rm -rf '" .. work .. "'")
if #failed > 0 then
    io.stderr:write(
        "R4-VARSTATE-1: after a reorg aborts the running player, the relaunched player reuses its stored epoch "
            .. "and claims over replaced inputs (scenarios "
            .. table.concat(failed, ",")
            .. "): its root claim differs from the canonical claim instead of failing closed\n"
    )
    os.exit(1)
end
print("all scenarios fail closed or compute the canonical claim")
