#!/usr/bin/env lua5.4
-- R1-PLAYER-4: the honest player's epoch listener (doc/recipes/prt-epoch.lua) fetches, retains and
-- re-processes on every poll every InputAdded log of the shared InputBox, of every application, since
-- the consensus deployment block. It uses only the application's own ones.
--
-- prt-cast's chain:logs filters eth_getLogs only by address (no topics, although InputAdded's
-- appContract is an indexed topic). prt-log-history keeps every returned log. prt-epoch's poll()
-- iterates, validates, sorts and indexes all of them on every poll. prt-player creates one listener
-- per epoch, each with its own history starting at the deployment block, and never drops a sealed
-- listener. So the memory the process retains grows with (epochs x global InputBox volume), and the
-- cost of every poll grows with the global InputBox volume, both driven by inputs to OTHER
-- applications that anyone can send permissionlessly (THREAT_MODEL section 4 "input senders (any
-- bytes, any count)", "data relayed by the node from others", section 7). The honest operator does
-- not need these logs, so it may decline them; section 4 requires such paths to be bounded, and
-- section 8 rates unbounded allocation/hang from declinable relayed data High. Unbounded poll time
-- eats the response windows that A7 sizes for the honest claim (R4 completeness, section 1).
--
-- The test drives the real prt-epoch / prt-log-history / prt-cast code (with prt-cast's JSON-RPC
-- transport replaced by an in-memory node that implements eth_getLogs with address AND topics
-- filtering, returning fresh copies as a JSON decoder would). It replays prt-player's open_epochs /
-- pass loop over E epochs, each with the application's own inputs, K spam InputAdded logs to other
-- applications, and the seal. It runs with K = 0 (baseline) and K > 0 and compares:
--   1. memory retained by the listeners (Lua heap after full GC, listeners alive minus dropped);
--   2. Lua VM instructions of one steady-state poll (no new logs) of the open epoch's listener
--      (deterministic, counted with debug.sethook);
--   3. other applications' logs downloaded from the node.
-- Correct behavior: none of these depends on other applications' inputs (within a small slack), and
-- the inputs delivered to the player are identical. Exit 1 while the defect exists.

-- dkjson is not installed here. The in-memory node returns Lua tables directly, so the transport only
-- needs json.null.
if not pcall(require, "dkjson") then
    package.loaded.dkjson = nil
    package.preload.dkjson = function()
        local function unused()
            error("dkjson stub")
        end
        return { null = setmetatable({}, { __name = "json.null" }), decode = unused, encode = unused }
    end
end

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local json = require("dkjson")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local epoch = require("prt-epoch")
local prt = require("prt")

local geometry = prt.new_geometry(10)
local EPOCHS = 3 -- sealed epochs; one more is open at the end, as in a running player
local APP_INPUTS = 2 -- the application's own inputs per epoch
local SPAM_PER_BLOCK = 50
local K = tonumber(os.getenv("SPAM_PER_EPOCH") or "1000") -- other applications' inputs per epoch

local function topic_address(address)
    return "0x" .. string.rep("0", 24) .. address:sub(3)
end
local function topic_uint(n)
    return string.format("0x%064x", n)
end

-- A hand-written ABI with the two events the listener reads (cartesi-rollups v2 InputBox and
-- DaveConsensus shapes). The listener decodes logs through the real prt-ethereum ABI decoder.
local abi = eth.abi({
    {
        abi = {
            {
                type = "event",
                name = "InputAdded",
                inputs = {
                    { name = "appContract", type = "address", indexed = true },
                    { name = "index", type = "uint256", indexed = true },
                    { name = "input", type = "bytes", indexed = false },
                },
            },
        },
    },
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
local INPUT_ADDED = eth.hex(cartesi.keccak256("InputAdded(address,uint256,bytes)"))
local EPOCH_SEALED = eth.hex(
    cartesi.keccak256("EpochSealed(uint256,uint256,uint256,bytes32,bytes32,address)")
)
assert(abi.events[INPUT_ADDED] and abi.events[EPOCH_SEALED], "test ABI is broken")

local APP = "0x" .. string.rep("a1", 20)
local INPUT_BOX = "0x" .. string.rep("b2", 20)
local CONSENSUS = "0x" .. string.rep("c3", 20)
local FACTORY = "0x" .. string.rep("d4", 20)
local ROOT = "0x" .. string.rep("e5", 20)
local STATE_HASH = "0x" .. string.rep("11", 32)
local DEPLOYMENT_BLOCK = 10

-- The node: blocks with deterministic hashes, logs per address sorted by block, and an eth_getLogs
-- with JSON-RPC filter semantics (address, fromBlock, toBlock, topics with null / string / array).
local function new_node()
    local node = { tip = DEPLOYMENT_BLOCK, logs = {}, next_index = {}, served = { own = 0, foreign = 0 } }
    local function block_hash(n)
        return string.format("0x%064x", n + 0x1000)
    end
    node.block_hash = block_hash
    function node:mine()
        self.tip = self.tip + 1
        self.log_index = 0
        return self.tip
    end
    function node:emit(address, topics, data)
        local list = self.logs[address] or {}
        self.logs[address] = list
        list[#list + 1] = {
            address = address,
            topics = topics,
            data = data,
            blockNumber = string.format("0x%x", self.tip),
            blockHash = block_hash(self.tip),
            logIndex = string.format("0x%x", self.log_index),
            transactionHash = string.format("0x%064x", self.tip * 100000 + self.log_index),
            transactionIndex = string.format("0x%x", self.log_index),
            removed = false,
        }
        self.log_index = self.log_index + 1
    end
    function node:add_input(app, payload)
        local index = self.next_index[app] or 0
        self.next_index[app] = index + 1
        self:emit(
            INPUT_BOX,
            { INPUT_ADDED, topic_address(app), topic_uint(index) },
            eth.hex(evmu.encode_abi("(bytes)", { eth.hex(payload) }))
        )
        return index
    end
    local function topic_match(want, have)
        if want == nil or want == json.null then
            return true
        end
        if type(want) == "table" then
            for _, w in ipairs(want) do
                if w == have then
                    return true
                end
            end
            return false
        end
        return want == have
    end
    local function copy(log)
        local t = {}
        for k, v in pairs(log) do
            t[k] = v
        end
        local topics = {}
        for i, v in ipairs(log.topics) do
            topics[i] = v
        end
        t.topics = topics
        return t
    end
    function node:rpc(method, params)
        if method == "eth_getBlockByNumber" then
            local selector = params[1]
            local n = (selector == "latest" or selector == "safe" or selector == "finalized") and self.tip
                or tonumber(selector)
            if not n or n > self.tip then
                return json.null
            end
            return { number = string.format("0x%x", n), hash = block_hash(n) }
        elseif method == "eth_getLogs" then
            local filter = params[1]
            local from, to = tonumber(filter.fromBlock), tonumber(filter.toBlock)
            local addresses = type(filter.address) == "table" and filter.address or { filter.address }
            local result = {}
            for _, address in ipairs(addresses) do
                local list = self.logs[address] or {}
                -- first log with block >= from
                local lo, hi = 1, #list + 1
                while lo < hi do
                    local mid = (lo + hi) // 2
                    if tonumber(list[mid].blockNumber) < from then
                        lo = mid + 1
                    else
                        hi = mid
                    end
                end
                for i = lo, #list do
                    local log = list[i]
                    if tonumber(log.blockNumber) > to then
                        break
                    end
                    local ok = true
                    for position, want in pairs(filter.topics or {}) do
                        if not topic_match(want, log.topics[position]) then
                            ok = false
                            break
                        end
                    end
                    if ok then
                        if address == INPUT_BOX then
                            if log.topics[2] == topic_address(APP) then
                                self.served.own = self.served.own + 1
                            else
                                self.served.foreign = self.served.foreign + 1
                            end
                        end
                        result[#result + 1] = copy(log)
                    end
                end
            end
            return result
        end
        error("unexpected rpc " .. tostring(method))
    end
    return node
end

-- One run of prt-player's loop. Returns the measurements and the inputs the players received.
local function run(spam)
    local node = new_node()
    local chain = cast.new("http://unused")
    function chain.rpc(_, method, params)
        -- Harness check only (off by default): R1_PLAYER_4_SIMULATE_FIX=yes adds the topic filter a
        -- fixed listener would send (InputAdded of this application), so the test must then pass.
        if os.getenv("R1_PLAYER_4_SIMULATE_FIX") == "yes" and method == "eth_getLogs" then
            if params[1].address == INPUT_BOX and not params[1].topics then
                params[1].topics = { INPUT_ADDED, topic_address(APP) }
            end
        end
        return node:rpc(method, params)
    end
    local delivered = {}
    local function new_player(number)
        delivered[number] = {}
        return {
            event_handler = {
                input_added = function(_, index, path)
                    local f = assert(io.open(path, "rb"))
                    delivered[number][index + 1] = f:read("a")
                    f:close()
                end,
                epoch_sealed = function(_, count)
                    delivered[number].sealed = count
                end,
            },
        }
    end
    local listeners = {}
    local seals = {}
    local function open(number)
        local previous = seals[number - 1]
        listeners[#listeners + 1] = epoch.new({
            chain = chain,
            transactions = {},
            abi = abi,
            app = APP,
            input_box = INPUT_BOX,
            consensus = CONSENSUS,
            factory = FACTORY,
            epoch = number,
            input_begin = previous and previous.upper or 0,
            initial_hash = STATE_HASH,
            previous_outputs_root = previous and STATE_HASH or eth.zero,
            geometry = geometry,
            player = new_player(number),
            signer = { address = "0x" .. string.rep("f6", 20) },
            label = "honest",
            cleanup = true,
            claim_staging_period = 10,
            input_policy = 0,
            dispute_policy = 0,
            first_block = DEPLOYMENT_BLOCK,
        })
    end
    local function pass()
        for _, listener in ipairs(listeners) do
            listener:poll() -- the bridge's tick is not exercised
        end
    end
    local spammer = 0
    local function spam_blocks(count)
        local left = count
        while left > 0 do
            node:mine()
            for _ = 1, math.min(SPAM_PER_BLOCK, left) do
                spammer = spammer + 1
                -- other applications, 4-byte payloads
                local other = string.format("0x%040x", 0x100000 + (spammer % 997))
                node:add_input(other, "spam")
            end
            left = left - SPAM_PER_BLOCK
        end
    end
    local lower = 0
    for number = 0, EPOCHS do
        open(number)
        pass()
        spam_blocks(spam // 2)
        node:mine()
        for i = 1, APP_INPUTS do
            node:add_input(APP, "epoch " .. number .. " input " .. i)
        end
        pass()
        spam_blocks(spam - spam // 2)
        pass()
        if number < EPOCHS then
            node:mine()
            local upper = node.next_index[APP]
            node:emit(
                CONSENSUS,
                { EPOCH_SEALED },
                eth.hex(evmu.encode_abi("(uint256,uint256,uint256,bytes32,bytes32,address)", {
                    number,
                    lower,
                    upper,
                    STATE_HASH,
                    number == 0 and eth.zero or STATE_HASH,
                    ROOT,
                }))
            )
            seals[number] = { upper = upper }
            lower = upper
            pass()
            assert(listeners[#listeners].dispute, "harness error: epoch " .. number .. " did not seal")
        end
    end
    -- Steady state: one empty block, one pass. Count the Lua VM instructions of the open epoch's poll.
    node:mine()
    local open_listener = listeners[#listeners]
    local steps = 0
    debug.sethook(function()
        steps = steps + 1
    end, "", 1000)
    local start = os.clock()
    open_listener:poll()
    local seconds = os.clock() - start
    debug.sethook()
    -- Memory retained by the listeners.
    collectgarbage("collect")
    collectgarbage("collect")
    local with = collectgarbage("count")
    open_listener = nil -- luacheck: ignore 311
    for i = #listeners, 1, -1 do
        listeners[i] = nil
    end
    collectgarbage("collect")
    collectgarbage("collect")
    local without = collectgarbage("count")
    return {
        retained_kib = with - without,
        poll_kinstr = steps,
        poll_seconds = seconds,
        foreign_served = node.served.foreign,
        own_served = node.served.own,
        delivered = delivered,
    }
end

local function same_delivery(a, b)
    for number = 0, EPOCHS do
        local x, y = a[number], b[number]
        if #x ~= #y or x.sealed ~= y.sealed then
            return false
        end
        for i = 1, #x do
            if x[i] ~= y[i] then
                return false
            end
        end
    end
    return true
end

local base = run(0)
local spammed = run(K)
local double = run(2 * K)

-- Harness sanity: the application's own inputs are delivered identically whatever the spam.
assert(#base.delivered[0] == APP_INPUTS and base.delivered[0].sealed == APP_INPUTS, "harness error: no inputs delivered")
assert(same_delivery(base.delivered, spammed.delivered), "harness error: spam changed the delivered inputs")
assert(same_delivery(base.delivered, double.delivered), "harness error: spam changed the delivered inputs")

local function report(name, r)
    print(
        string.format(
            "%-22s retained by listeners %9.1f KiB | steady poll %8d k Lua instr, %.3f s | other apps' logs downloaded %7d (own %d)",
            name,
            r.retained_kib,
            r.poll_kinstr,
            r.poll_seconds,
            r.foreign_served,
            r.own_served
        )
    )
end
print(string.format("%d sealed epochs + 1 open, %d own inputs per epoch", EPOCHS, APP_INPUTS))
report("no foreign inputs", base)
report(string.format("%d foreign/epoch", K), spammed)
report(string.format("%d foreign/epoch", 2 * K), double)
print(
    string.format(
        "growth K->2K: retained +%.1f KiB, steady poll +%d k instr (base->K: +%.1f KiB, +%d k instr)",
        double.retained_kib - spammed.retained_kib,
        double.poll_kinstr - spammed.poll_kinstr,
        spammed.retained_kib - base.retained_kib,
        spammed.poll_kinstr - base.poll_kinstr
    )
)

local failures = {}
-- Slack: 64 KiB of retained memory and 2x + 50k instructions per poll, far below one byte or one
-- instruction per foreign log.
if double.retained_kib > base.retained_kib + 64 then
    failures[#failures + 1] = string.format(
        "listeners retain %.1f MiB for %d other applications' inputs they never use (baseline %.1f KiB)",
        (double.retained_kib - base.retained_kib) / 1024,
        2 * K * (EPOCHS + 1),
        base.retained_kib
    )
end
if double.poll_kinstr > 2 * base.poll_kinstr + 50 then
    failures[#failures + 1] = string.format(
        "a steady-state poll costs %dx the baseline Lua instructions (%dk vs %dk)",
        double.poll_kinstr // math.max(1, base.poll_kinstr),
        double.poll_kinstr,
        base.poll_kinstr
    )
end
if double.foreign_served > 0 then
    failures[#failures + 1] =
        string.format("%d other applications' InputAdded logs were downloaded", double.foreign_served)
end
if #failures > 0 then
    print(
        "FAIL: epoch listener cost grows with other applications' InputBox inputs (unbounded, declinable relayed data): "
            .. table.concat(failures, "; ")
    )
    os.exit(1)
end
print("OK: epoch listener cost is independent of other applications' inputs")
os.exit(0)
