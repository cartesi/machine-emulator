#!/usr/bin/env lua5.4
-- R2-ROBUST-1: every past epoch's dispute bridge keeps observing, and keeps its own full copy of the
-- factory / consensus / tournament log history, on every pass, forever.
--
-- prt-player.lua's pass() polls every listener ever opened and ticks the dispute bridge of every
-- sealed epoch; listeners are never retired. prt-bridge's tick() always calls refresh() -> observe(),
-- even when the epoch is settled (the next epoch's EpochSealed was observed) and even when the
-- bridge is done. Each observe() fetches the factory, the consensus and the tournaments from the
-- consensus deployment block (prt-epoch passes first_block = deployment block), with no topic
-- filter; each bridge's prt-log-history keeps every log forever; and every observe() copies all of
-- them into one list, sorts it, scans it and keeps every decoded event in snapshot.events. The
-- factory's TournamentCreated logs come from any instantiation of the shared factory (permissionless
-- relayed data the operator may decline: THREAT_MODEL section 4 "data relayed by the node from
-- others", section 8 High "unbounded allocation caused by relayed data that the honest operator may
-- decline"). The live epoch's bridge is ticked last, so every pass serves the live dispute only after
-- (number of past epochs) x (shared log history) of work. That latency grows with the application's
-- age even without an adversary, so no fixed sizing (A7, R12) bounds it and the honest player can
-- eventually miss a dispute clock (R4, section 1 completeness failure).
--
-- The test drives the real prt-epoch / prt-bridge / prt-log-history / prt-cast code. prt-cast's
-- JSON-RPC transport is replaced by an in-memory node (eth_getBlockByNumber, eth_getLogs with address
-- and topics filtering, returning fresh copies of each log as a JSON decoder would). The ABI decoder is
-- a stub that builds each event from a side table. It replays prt-player's open_epochs / pass loop:
-- E epochs are sealed, staged and settled (each next epoch's seal settles the previous one), and one
-- more epoch is live. Between seals, K foreign TournamentCreated logs (other instantiations of the
-- shared factory) are emitted. It then measures one steady-state pass (one empty new block):
--   1. Lua VM instructions spent before the live epoch's bridge tick starts (deterministic, counted
--      with debug.sethook) and the chain reads issued by settled bridges;
--   2. memory retained by the dispute bridges (Lua heap after full GC, bridges alive minus dropped).
-- Correct behavior: the work that delays the live dispute and the memory the bridges retain do not
-- grow with the number of past epochs or with foreign factory logs (within a small slack). Exit 1
-- while the defect exists.

if not pcall(require, "dkjson") then
    package.loaded.dkjson = nil
    package.preload.dkjson = function()
        local function unused()
            error("dkjson stub")
        end
        return { null = setmetatable({}, { __name = "json.null" }), decode = unused, encode = unused }
    end
end

local evmu = require("cartesi.evmu")
local json = require("dkjson")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local epoch = require("prt-epoch")
local prt = require("prt")

local geometry = prt.new_geometry(10)
local K = tonumber(os.getenv("FOREIGN_PER_EPOCH") or "200") -- foreign TournamentCreated per epoch
local SMALL_E, BIG_E = 2, 8 -- settled epochs before the live one
local PER_BLOCK = 20

local APP = "0x" .. string.rep("a1", 20)
local INPUT_BOX = "0x" .. string.rep("b2", 20)
local CONSENSUS = "0x" .. string.rep("c3", 20)
local FACTORY = "0x" .. string.rep("d4", 20)
local STATE_HASH = "0x" .. string.rep("11", 32)
local SIGNER = "0x" .. string.rep("f6", 20)
local DEPLOYMENT_BLOCK = 10
local ALLOWANCE = 5 -- joining window of a root tournament, in blocks

local function root_address(number)
    return string.format("0x%040x", 0xe50000 + number)
end

-- The stub ABI: the event of a log is rebuilt from the node's side table, keyed by the log's
-- transaction hash (which a JSON decoder would also deliver). It is called once per log by the
-- bridge's cache and once per log by the listener, as the real decoder is.
local specs = {}
local function decode_value(v)
    if type(v) == "table" and v.bint then
        return evmu.bint(v.bint)
    elseif type(v) == "table" then
        local t = {}
        for k, x in pairs(v) do
            t[k] = decode_value(x)
        end
        return t
    end
    return v
end
local abi = {
    event = function(_, log)
        local spec = specs[log.transactionHash]
        if not spec then
            return nil
        end
        local value = decode_value(spec)
        value.address, value.log = log.address, log
        return value
    end,
    calldata = function()
        error("harness error: no transaction is expected")
    end,
}

local function new_node()
    local node = { tip = DEPLOYMENT_BLOCK, logs = {}, log_index = 0, serial = 0 }
    local function block_hash(n)
        return string.format("0x%064x", n + 0x1000)
    end
    function node:mine()
        self.tip = self.tip + 1
        self.log_index = 0
        return self.tip
    end
    function node:emit(address, spec)
        self.serial = self.serial + 1
        local transaction = string.format("0x%064x", self.serial)
        specs[transaction] = spec
        local list = self.logs[address] or {}
        self.logs[address] = list
        list[#list + 1] = {
            address = address,
            topics = { string.format("0x%064x", #spec.name) },
            data = "0x" .. string.rep("00", 192),
            blockNumber = string.format("0x%x", self.tip),
            blockHash = block_hash(self.tip),
            logIndex = string.format("0x%x", self.log_index),
            transactionHash = transaction,
            transactionIndex = string.format("0x%x", self.log_index),
            removed = false,
        }
        self.log_index = self.log_index + 1
    end
    local function copy(log)
        local t = {}
        for k, v in pairs(log) do
            t[k] = v
        end
        t.topics = { table.unpack(log.topics) }
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
            local result = {}
            for _, log in ipairs(self.logs[filter.address] or {}) do
                local n = tonumber(log.blockNumber)
                if n >= from and n <= to then
                    result[#result + 1] = copy(log)
                end
            end
            return result
        end
        error("unexpected rpc " .. tostring(method))
    end
    return node
end

local function tournament_created(root, block)
    return {
        name = "TournamentCreated",
        tournament = root,
        bondValue = { bint = 1 },
        descriptor = {
            initialHash = STATE_HASH,
            baseCycle = { bint = 0 },
            height = { bint = geometry.mcycle_height },
            log2Stride = { bint = geometry.uarch_height },
            level = { bint = 0 },
            kind = { bint = 0 },
            startInstant = { bint = block },
            allowance = { bint = ALLOWANCE },
        },
    }
end

local SIMULATE_FIX = os.getenv("R2_ROBUST_1_SIMULATE_FIX") == "yes"

local function run(settled_epochs, foreign)
    specs = {}
    local seal_blocks = {}
    local node = new_node()
    local chain = cast.new("http://unused")
    local reads = 0
    function chain.rpc(_, method, params)
        reads = reads + 1
        local result = node:rpc(method, params)
        -- Harness check only (off by default): R2_ROBUST_1_SIMULATE_FIX=yes serves factory logs only
        -- from seal blocks, as a bridge fetching just its root's creation block would request.
        if SIMULATE_FIX and method == "eth_getLogs" and params[1].address == FACTORY then
            local kept = {}
            for _, log in ipairs(result) do
                if seal_blocks[log.blockNumber] then
                    kept[#kept + 1] = log
                end
            end
            result = kept
        end
        return result
    end
    local foreign_serial = 0
    local function emit_foreign(count)
        while count > 0 do
            node:mine()
            for _ = 1, math.min(PER_BLOCK, count) do
                foreign_serial = foreign_serial + 1
                node:emit(FACTORY, tournament_created(string.format("0x%040x", 0x700000 + foreign_serial), node.tip))
            end
            count = count - PER_BLOCK
        end
    end
    local function seal(number)
        node:mine()
        seal_blocks[string.format("0x%x", node.tip)] = true
        -- DaveConsensus instantiates the root through the factory and seals in one transaction.
        node:emit(FACTORY, tournament_created(root_address(number), node.tip))
        node:emit(CONSENSUS, {
            name = "EpochSealed",
            epochNumber = { bint = number },
            inputIndexLowerBound = { bint = 0 },
            inputIndexUpperBound = { bint = 0 },
            initialMachineStateHash = STATE_HASH,
            outputsMerkleRoot = eth.zero,
            tournament = root_address(number),
        })
    end
    local function stage(number)
        node:mine()
        node:emit(CONSENSUS, { name = "EpochStaged", epochNumber = { bint = number }, tournament = root_address(number) })
    end
    local transactions = {
        pending = function()
            return nil
        end,
        receipt = function()
            return nil
        end,
    }
    local function new_player()
        return {
            event_handler = {
                input_added = function()
                    error("harness error: no input expected")
                end,
                epoch_sealed = function() end,
                commit_mcycle_claim = function()
                    return "nothing"
                end,
            },
        }
    end
    local listeners = {}
    local function open(number)
        listeners[#listeners + 1] = epoch.new({
            chain = chain,
            transactions = transactions,
            abi = abi,
            app = APP,
            input_box = INPUT_BOX,
            consensus = CONSENSUS,
            factory = FACTORY,
            epoch = number,
            input_begin = 0,
            initial_hash = STATE_HASH,
            previous_outputs_root = eth.zero,
            geometry = geometry,
            player = new_player(),
            signer = { address = SIGNER },
            label = "honest",
            cleanup = true,
            claim_staging_period = 10,
            input_policy = 0,
            dispute_policy = 0,
            first_block = DEPLOYMENT_BLOCK,
        })
    end
    -- prt-player.lua's pass(), with per-listener instrumentation.
    local steps, trace = 0, nil
    local function pass()
        for i, listener in ipairs(listeners) do
            local dispute = listener:poll()
            if dispute and not dispute.retired then
                local before_steps, before_reads = steps, reads
                local snapshot = dispute:tick()
                assert(snapshot and snapshot.ready, "harness error: bridge observation failed")
                if trace then
                    trace[i] = {
                        steps = steps - before_steps,
                        reads = reads - before_reads,
                        settled = snapshot.settled ~= nil,
                        events = #snapshot.events,
                    }
                end
                -- Harness check only: the simulated fix retires a settled bridge with no job left.
                if SIMULATE_FIX and snapshot.settled and (dispute.done or #dispute:jobs(snapshot) == 0) then
                    dispute.retired = true
                    dispute.history:reset()
                end
            end
        end
    end
    -- Epochs 0 .. settled_epochs - 1 settle; epoch settled_epochs stays live.
    for number = 0, settled_epochs do
        open(number)
        seal(number)
        pass()
        assert(listeners[#listeners].dispute, "harness error: epoch " .. number .. " did not seal")
        if number == 0 then
            listeners[1].dispute.done = true -- this player left epoch 0's game
        end
        if number < settled_epochs then
            emit_foreign(foreign)
            stage(number)
            pass()
        end
    end
    emit_foreign(PER_BLOCK) -- some blocks past the live seal, inside its window
    pass()
    -- Steady state: one empty block, one pass.
    node:mine()
    trace = {}
    debug.sethook(function()
        steps = steps + 1
    end, "", 1000)
    local start = os.clock()
    pass()
    local seconds = os.clock() - start
    debug.sethook()
    local live = #listeners
    assert(trace[live] and not trace[live].settled, "harness error: live epoch is settled")
    local before_live, settled_reads, settled_count = 0, 0, 0
    local done_reads = trace[1] and trace[1].reads or 0
    for i = 1, live - 1 do
        trace[i] = trace[i] or { steps = 0, reads = 0, settled = true }
        assert(trace[i].settled, "harness error: past epoch " .. (i - 1) .. " is not settled")
        before_live = before_live + trace[i].steps
        settled_reads = settled_reads + trace[i].reads
        settled_count = settled_count + 1
    end
    -- Memory retained by the dispute bridges alone (the listeners stay alive).
    collectgarbage("collect")
    collectgarbage("collect")
    local with = collectgarbage("count")
    local retained_logs = 0
    for _, listener in ipairs(listeners) do
        for _, logs in pairs(listener.dispute.history.logs) do
            retained_logs = retained_logs + #logs
        end
        listener.dispute = nil
    end
    collectgarbage("collect")
    collectgarbage("collect")
    local without = collectgarbage("count")
    return {
        settled = settled_count,
        before_live_kinstr = before_live,
        live_kinstr = trace[live].steps,
        settled_reads = settled_reads,
        done_reads = done_reads,
        seconds = seconds,
        retained_kib = with - without,
        retained_logs = retained_logs,
        foreign_total = foreign_serial,
    }
end

local small = run(SMALL_E, 0)
local big = run(BIG_E, 0)
local spammed = run(BIG_E, K)

local function report(name, r)
    print(
        string.format(
            "%-34s before live tick %7dk instr (%.3f s pass) | settled bridges' chain reads %4d (done bridge %d)"
                .. " | bridges retain %8.1f KiB, %6d logs",
            name,
            r.before_live_kinstr,
            r.seconds,
            r.settled_reads,
            r.done_reads,
            r.retained_kib,
            r.retained_logs
        )
    )
end
report(string.format("%d settled epochs, no foreign", SMALL_E), small)
report(string.format("%d settled epochs, no foreign", BIG_E), big)
report(string.format("%d settled epochs, %d foreign/epoch", BIG_E, K), spammed)

local failures = {}
-- Slack: 2x the small baseline + 20k instructions, and 64 KiB of retained memory.
local bound = 2 * small.before_live_kinstr + 20
if big.before_live_kinstr > bound then
    failures[#failures + 1] = string.format(
        "work before the live dispute grows with past epochs (%dk instr for %d settled vs %dk for %d)",
        big.before_live_kinstr,
        BIG_E,
        small.before_live_kinstr,
        SMALL_E
    )
end
if spammed.before_live_kinstr > bound then
    failures[#failures + 1] = string.format(
        "work before the live dispute grows with foreign factory logs (%dk instr with %d foreign tournaments)",
        spammed.before_live_kinstr,
        spammed.foreign_total
    )
end
if spammed.retained_kib > big.retained_kib + 64 then
    failures[#failures + 1] = string.format(
        "%d bridges retain %.1f MiB for %d foreign tournaments (%d log copies)",
        BIG_E + 1,
        (spammed.retained_kib - big.retained_kib) / 1024,
        spammed.foreign_total,
        spammed.retained_logs - big.retained_logs
    )
end
if spammed.done_reads > 0 then
    failures[#failures + 1] =
        string.format("a done, settled bridge still issued %d chain reads in one pass", spammed.done_reads)
end
if #failures > 0 then
    print(
        "FAIL: settled epochs' dispute bridges re-observe and retain the whole shared log history every pass: "
            .. table.concat(failures, "; ")
    )
    os.exit(1)
end
print("OK: past epochs' bridges cost nothing per pass and retain no foreign logs")
os.exit(0)
