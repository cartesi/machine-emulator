#!/usr/bin/env lua5.4
-- R1-PLAYER-3: the honest player's get_seal reads the consensus logs with one unpaged eth_getLogs over
-- [deployment block, tip], so once the chain is older than the node's log-filter block range the
-- player's pass() raises before any listener polls or any dispute bridge ticks
-- (doc/recipes/prt-player.lua get_seal/open_epochs/pass, doc/recipes/prt-cast.lua methods:logs).
--
-- Threat model: R4 (the honest operator can always respond), A7 (clocks sized for the honest claim to
-- play its matches), section 4 (paths carrying node data report errors without terminating), section 1
-- completeness failure. The player's own listener and bridge fetch logs through prt-log-history, which
-- pages "because providers limit the block range or log count of a request". get_seal does not, has no
-- pcall, and runs first in every pass(): the player's main loop calls pass() unprotected, the process
-- exits, prt-supervise.sh relaunches it, and the relaunch replays open_epochs() from --first-epoch and
-- calls get_seal again, which fails the same way. Its claim then loses on time.
--
-- The test runs the player's real code. It extracts prt-player.lua's text from get_seal through pass()
-- verbatim and loads it with the player's upvalues bound to: a real prt-cast chain talking HTTP to a stub
-- node (server.lua) that refuses eth_getLogs over more than 1000 blocks (as Reth's
-- --rpc.max-blocks-per-filter or a hosted provider's cap does); the deployment at block 0, the tip at
-- 5000, and an EpochSealed(0) log at block 4800; checkpoints/epoch-0 and checkpoints/epoch-1 present,
-- which is what the honest player leaves after it processes the seal of epoch 0. The listeners and the
-- checkpoint loader are stubs that record that they ran. Control: prt-log-history, which the player's
-- listener uses, fetches the same consensus logs from the same node successfully.
--
-- Correct behavior: pass() completes and polls the listeners of epochs 0 and 1 (and a relaunch does
-- too). Exit 1 while the defect exists.
package.path = "./vendor/?.lua;" .. package.path

local evmu = require("cartesi.evmu")
local fs = require("cartesi.filesystem")
local json = require("dkjson")
local socket = require("socket")
local cast = require("prt-cast")
local eth = require("prt-ethereum")
local log_history = require("prt-log-history")

local REPO = assert(os.getenv("REPO_DIR"), "source bugs/env.sh")
local TIP, SEAL_BLOCK, DEPLOYMENT = 5000, 4800, 0
-- The node's log-filter block range (override only to check the harness against an unlimited node).
local MAX_RANGE = math.tointeger(tonumber(os.getenv("R1_PLAYER_3_MAX_RANGE") or "1000"))
local CONSENSUS = "0x" .. string.rep("c0", 20)
local TOURNAMENT = "0x" .. string.rep("7a", 20)
local INITIAL = "0x" .. string.rep("11", 32)
local OUTPUTS = "0x" .. string.rep("22", 32)

-- The fields prt-epoch.lua and prt-player.lua read from DaveConsensus's EpochSealed.
local abi = eth.abi({
    {
        abi = {
            {
                type = "event",
                name = "EpochSealed",
                inputs = {
                    { name = "epochNumber", type = "uint256", indexed = false },
                    { name = "inputIndexLowerBound", type = "uint256", indexed = false },
                    { name = "inputIndexUpperBound", type = "uint256", indexed = false },
                    { name = "initialMachineStateHash", type = "bytes32", indexed = false },
                    { name = "outputsMerkleRoot", type = "bytes32", indexed = false },
                    { name = "tournament", type = "address", indexed = false },
                },
            },
        },
    },
})
local topic = next(abi.events)
local seal_log = {
    address = CONSENSUS,
    topics = { topic },
    data = eth.hex(evmu.encode_abi("(uint256,uint256,uint256,bytes32,bytes32,address)", {
        0,
        0,
        3,
        INITIAL,
        OUTPUTS,
        TOURNAMENT,
    })),
    blockNumber = string.format("0x%x", SEAL_BLOCK),
    blockHash = string.format("0x%064x", SEAL_BLOCK + 0xb10c0000),
    logIndex = "0x0",
    transactionHash = "0x" .. string.rep("ee", 32),
    transactionIndex = "0x0",
    removed = false,
}

-- Scratch space: the stub node's fixture and the checkpoint directories.
local work = os.tmpname()
os.remove(work)
fs.create_directory(work)
local function write(path, data)
    local file = assert(io.open(path, "w"))
    file:write(data)
    file:close()
end
write(work .. "/fixture.json", json.encode({ tip = TIP, max_range = MAX_RANGE, logs = { seal_log } }))
fs.create_directory(work .. "/checkpoints")
fs.create_directory(work .. "/checkpoints/epoch-0")
fs.create_directory(work .. "/checkpoints/epoch-1")

local port_file = work .. "/port"
assert(os.execute(string.format(
    "lua5.4 -e 'package.path=\"./vendor/?.lua;\"..package.path' ./server.lua %q %q > %q 2>&1 &",
    work .. "/fixture.json",
    port_file,
    work .. "/server.log"
)))
local port
for _ = 1, 100 do
    local file = io.open(port_file)
    if file then
        port = tonumber(file:read("a"))
        file:close()
        break
    end
    socket.sleep(0.1)
end
assert(port, "stub node did not start")
local url = "http://127.0.0.1:" .. port

local function cleanup()
    pcall(function()
        cast.new(url, 5):rpc("test_shutdown")
    end)
    os.execute(string.format("rm -rf %q", work))
end

-- The player's code from get_seal through pass(), verbatim.
local source = fs.read_file(REPO .. "/doc/recipes/prt-player.lua")
local first = assert(source:find("-- The consensus's seal of an epoch", 1, true), "get_seal not found")
local last = assert(source:find("-- The status replaces the previous one whole", 1, true), "pass not found")
local code = source:sub(first, last - 1) .. "\nreturn pass\n"

-- One process of the player: its upvalues as prt-player.lua binds them, with the checkpoint loader,
-- the listeners and the players stubbed to record what ran.
local function launch(trace)
    local chain = cast.new(url, 10)
    local env = setmetatable({
        chain = chain,
        abi = abi,
        eth = eth,
        fs = fs,
        consensus = CONSENSUS,
        first_block = DEPLOYMENT,
        first_epoch = 0,
        options = { checkpoints = work .. "/checkpoints", state = work .. "/state", cleanup = "no" },
        template_hash = INITIAL,
        app = "0x" .. string.rep("a0", 20),
        input_box = "0x" .. string.rep("1b", 20),
        factory = "0x" .. string.rep("fa", 20),
        geometry = {},
        signer = {},
        label = "honest",
        transactions = {},
        staging_period = 10,
        input_policy = "finalized",
        dispute_policy = 4,
        measure = function(_, f, ...)
            return f(...)
        end,
        prt = {
            load_epoch_checkpoint = function(directory)
                trace.loaded[#trace.loaded + 1] = directory:match("epoch%-%d+$")
                return { initial_state_hash = assert(eth.raw(INITIAL)) }, {}, {
                    final_state_hash = INITIAL,
                    outputs_root = OUTPUTS,
                }
            end,
        },
        epoch = {
            new = function(args)
                return {
                    epoch = args.epoch,
                    inputs = {},
                    poll = function(self)
                        trace.polled[#trace.polled + 1] = self.epoch
                        return nil
                    end,
                }
            end,
        },
        new_player = function()
            return {}
        end,
    }, { __index = _G })
    return assert(load(code, "=prt-player.lua(get_seal..pass)", "t", env))()
end

-- Control: the listener's paged log history reads the same logs from the same node.
local history = log_history.new(cast.new(url, 10))
local tip, tip_hash = cast.new(url, 10):head()
history:observe(tip, tip_hash)
local ok_history, history_logs = pcall(history.get_logs, history, CONSENSUS, DEPLOYMENT)
if not ok_history or #history_logs ~= 1 or history_logs[1].blockNumber ~= seal_log.blockNumber then
    print("HARNESS ERROR: prt-log-history could not read the stub node's logs: " .. tostring(history_logs))
    cleanup()
    os.exit(2)
end
print(string.format("control: prt-log-history paged [%d, %d] and found the EpochSealed(0) log at block %d", DEPLOYMENT, tip, SEAL_BLOCK))

-- The player after the seal of epoch 0, then two relaunches, as prt-supervise.sh would run them.
local failures, reasons = 0, {}
for run = 1, 3 do
    local trace = { loaded = {}, polled = {} }
    local pass = launch(trace)
    local ok, status = pcall(pass)
    if ok then
        local polled = table.concat(trace.polled, ",")
        print(string.format("run %d: pass() completed; polled epochs {%s}", run, polled))
        if polled ~= "0,1" or not status.epochs["0"] or not status.epochs["1"] then
            failures = failures + 1
            reasons[#reasons + 1] = "pass() did not poll epochs 0 and 1"
        end
    else
        failures = failures + 1
        status = type(status) == "table" and json.encode(status) or tostring(status)
        reasons[#reasons + 1] = status
        print(string.format(
            "run %d: pass() raised after loading checkpoints {%s} and polling epochs {%s}: %s",
            run,
            table.concat(trace.loaded, ","),
            table.concat(trace.polled, ","),
            status
        ))
    end
end

local requests = cast.new(url, 5):rpc("test_requests") or {}
for _, r in ipairs(requests) do
    print(string.format("  node saw eth_getLogs [%d, %d] (%d blocks): %s", r.fromBlock, r.toBlock, r.toBlock - r.fromBlock + 1, r.outcome))
end
cleanup()

if failures > 0 then
    print(string.format(
        "FAIL: the honest player's pass() crashes in get_seal on every (re)launch (%d/3): one unpaged eth_getLogs "
            .. "over [deployment %d, tip %d] exceeds the node's %d-block filter range, so no listener polls and no "
            .. "dispute ticks (R4, A7, section 4): %s",
        failures,
        DEPLOYMENT,
        TIP,
        MAX_RANGE,
        reasons[1]
    ))
    os.exit(1)
end
print("OK: the player's pass() survives a node that limits the log-filter block range")
os.exit(0)
