#!/usr/bin/env lua5.4
-- R1-PLAYER-5: the honest PRT player (doc/recipes/prt-player.lua) runs one single-threaded pass() over every
-- epoch listener in order. While epoch N is in dispute, epoch N+1's listener (doc/recipes/prt-epoch.lua poll)
-- executes every newly confirmed InputAdded synchronously, inside poll(), before the pass returns. Epoch N's
-- dispute bridge does not tick again until that whole batch is done, so the time between two consecutive
-- honest responses in epoch N's dispute includes the cost of executing epoch N+1's inputs, which the
-- adversary chooses (THREAT_MODEL.md section 7: any number of inputs, payloads chosen to maximize cost) and
-- which A7 does not budget into epoch N's clocks. A response that falls due meanwhile is missed (R4: the
-- honest operator must always be able to respond in time; A7/R12: clocks are sized for the dispute's work).
--
-- What runs for real: pass() itself (its source is extracted verbatim from prt-player.lua and executed), two
-- real prt-epoch listeners, a real prt-bridge for epoch N (real observe/jobs/tick/attempt over fake chain logs),
-- and a real stored honest player for epoch N+1 (prt.new_stored_player) that runs a bare-metal correctly designed
-- application (guest.S, built at test time) burning a fixed mcycle budget per input. Only the chain is fake:
-- its tip advances one block per BLOCK_MCYCLES mcycles the honest process executes (one block of host time per
-- adversarial input at the application's per-input bound), plus one block per idle wait.
--
-- Scenario: epoch N (7) is sealed and in a match where the honest claim must answer (MatchCreated, honest
-- claim is `one`). Epoch N+1 (8) is open. With the default 'finalized' input policy, K=32 inputs posted by the
-- adversary become final in the same 32-block jump. The adversary's match move is mined right after that, at
-- block 97, with the responder deadline WINDOW=20 blocks later. The epoch N dispute needs no computation at all
-- here (the reveal_bisection handler answers instantly), so its own work is zero.
--
-- Correct behavior (asserted): the honest advanceMatch is submitted with an inclusion block before its
-- deadline. On feature/prt-audit the next tick of epoch N happens only after all 32 inputs of epoch N+1 ran,
-- at a tip far past the deadline, so the job is never attempted and the test exits nonzero.

-- dkjson (needed by prt-cast/prt-ethereum) is not installed system-wide; a copy is vendored here.
package.path = "./vendor/?.lua;" .. package.path

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local evmu = require("cartesi.evmu")
local json = require("dkjson")
local eth = require("prt-ethereum")
local cast = require("prt-cast")
local prt = require("prt")
local epoch = require("prt-epoch")
local bridge = require("prt-bridge")

local K = 32 -- adversarial inputs to epoch N+1 that finalize together
-- Control (not the test): R1_PLAYER_5_CONTROL=interleave models a fixed scheduler that ticks epoch N's bridge
-- after every next-epoch input; the test then passes, showing the harness detects the fix.
local CONTROL = os.getenv("R1_PLAYER_5_CONTROL")
local BLOCK_MCYCLES = 100000 -- honest-process mcycles per block of wall time (about one input here)
local WINDOW = 20 -- blocks between the opponent's move and the honest responder deadline
local EPOCH_N = 7
local INPUT_BEGIN = 5 -- epoch N held inputs 0..4; epoch N+1 starts at input 5
local START_TIP = 95
local MOVE_BLOCK = 97
local DEADLINE = MOVE_BLOCK + WINDOW
local INPUT_BLOCK = 50 -- the batch lands in block 50, final from tip 96 on (finalized block 64)

local tmp = fs.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "r1-player-5-")
local _ <close> = setmetatable({}, {
    __close = function()
        os.execute("rm -rf '" .. tmp .. "'")
    end,
})

assert(os.execute("bash ./build.sh " .. tmp), "harness error: failed to build guest.bin")

-- Rolling template: waits at a manual yield with RX_ACCEPTED, transmit buffer holds the empty outputs root.
local template_dir = tmp .. "/template"
local template_hash
do
    local m <close> =
        cartesi.new():create({ ram = { backing_store = { data_filename = tmp .. "/guest.bin" }, length = 1 << 20 } })
    local empty_root =
        hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))
    m:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, empty_root)
    assert(m:run(1 << 20) == cartesi.BREAK_REASON_YIELDED_MANUALLY, "harness error: guest did not yield")
    assert(m:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, "harness error: reason")
    m:store(template_dir)
    template_hash = m:get_root_hash()
end
local geometry = prt.new_geometry(10)

-- ---------------------------------------------------------------------------------------------------------------
-- Fake chain. Blocks are named "b<n>". 'finalized' trails the tip in 32-block jumps.
-- ---------------------------------------------------------------------------------------------------------------
local tip = START_TIP
local function finalized()
    return math.max(0, tip - tip % 32 - 32)
end
local streams = { factory = {}, consensus = {}, root = {}, inputbox = {} }
local function add_log(address, block, index, event)
    local log = {
        address = address,
        blockNumber = string.format("0x%x", block),
        blockHash = "b" .. block,
        logIndex = string.format("0x%x", index),
        removed = false,
        event = event,
    }
    event.address, event.log = address, log
    table.insert(streams[address], log)
end
local chain = cast.new("http://unused")
function chain.rpc(_, method, params)
    assert(method == "eth_getBlockByNumber", "harness error: unexpected RPC " .. tostring(method))
    local selector, number = params[1], nil
    if selector == "latest" then
        number = tip
    elseif selector == "finalized" then
        number = finalized()
    else
        number = assert(tonumber(selector))
        if number > tip then
            return json.null
        end
    end
    return { number = string.format("0x%x", number), hash = "b" .. number }
end
function chain.logs(_, address, last_block, first_block)
    local result = {}
    for _, log in ipairs(assert(streams[address], "harness error: unknown address " .. tostring(address))) do
        local n = tonumber(log.blockNumber)
        if n >= (first_block or 0) and n <= last_block and n <= tip then
            result[#result + 1] = log
        end
    end
    return result
end
local abi = {
    event = function(_, log)
        return log.event
    end,
    calldata = function(_, name)
        return "0x" .. name
    end,
}

-- Epoch N's tournament, its seal, and the opponent's move that the honest claim must answer.
local initial_hash_n = eth.hex(cartesi.keccak256("epoch N initial state"))
local ONE = eth.hex(cartesi.keccak256("honest claim"))
local TWO = eth.hex(cartesi.keccak256("dishonest claim"))
add_log("factory", 10, 0, {
    name = "TournamentCreated",
    tournament = "root",
    bondValue = 0,
    descriptor = {
        initialHash = initial_hash_n,
        baseCycle = evmu.bint(0),
        height = geometry.mcycle_height,
        log2Stride = geometry.uarch_height,
        level = 0,
        kind = 1,
        startInstant = 0,
        allowance = 1, -- joining window long closed
    },
})
add_log("consensus", 10, 1, {
    name = "EpochSealed",
    epochNumber = EPOCH_N,
    tournament = "root",
    initialMachineStateHash = initial_hash_n,
    inputIndexLowerBound = 0,
    inputIndexUpperBound = INPUT_BEGIN,
    outputsMerkleRoot = eth.zero,
})
add_log("root", MOVE_BLOCK, 0, {
    name = "MatchCreated",
    matchIdHash = "match",
    one = ONE,
    two = TWO,
    leftOfTwo = eth.hex(cartesi.keccak256("left of two")),
    responderDeadline = DEADLINE,
    eliminableAt = DEADLINE + 100,
})
-- The adversary's inputs to epoch N+1.
for i = 0, K - 1 do
    add_log("inputbox", INPUT_BLOCK, i, {
        name = "InputAdded",
        appContract = "app",
        index = INPUT_BEGIN + i,
        input = eth.hex(string.pack("<I8", i)),
    })
end

-- ---------------------------------------------------------------------------------------------------------------
-- Transaction journal stub: records what the bridge submits and the inclusion block it targets.
-- ---------------------------------------------------------------------------------------------------------------
local submitted = {}
local journal = {
    receipt = function() end,
    pending = function() end,
    submit = function(_, _, request)
        if request then
            submitted[#submitted + 1] = { kind = request.kind, inclusion = tip + 1, last = request.last }
        end
        return { published = true }
    end,
}
local signer = { address = "honest" }

-- Epoch N: its player's dispute work is free (it answers bisections instantly).
local node = string.rep("\x11", 32)
local player_n = {
    event_handler = {
        reveal_bisection = function()
            return {
                turn_left_node = node,
                turn_right_node = node,
                turn_next_left_node = node,
                turn_next_right_node = node,
            }
        end,
    },
}
local function listener_args(n, player, input_begin)
    return {
        chain = chain,
        transactions = journal,
        abi = abi,
        app = "app",
        input_box = "inputbox",
        consensus = "consensus",
        factory = "factory",
        epoch = n,
        input_begin = input_begin,
        initial_hash = n == EPOCH_N and initial_hash_n or eth.hex(template_hash),
        previous_outputs_root = eth.zero,
        geometry = geometry,
        player = player,
        signer = signer,
        label = "honest",
        cleanup = false,
        claim_staging_period = 10,
        input_policy = "finalized", -- prt-player.lua's default
        dispute_policy = 4, -- prt-player.lua's default
        first_block = 0,
    }
end
local listener_n = epoch.new(listener_args(EPOCH_N, player_n, 0))
local dispute_n = bridge.new({
    chain = chain,
    transactions = journal,
    abi = abi,
    root = "root",
    epoch = EPOCH_N,
    initial_hash = initial_hash_n,
    factory = "factory",
    consensus = "consensus",
    player = player_n,
    signer = signer,
    label = "honest",
    cleanup = false,
    geometry = geometry,
    inputs = listener_n.inputs,
    claim_staging_period = 10,
    observation_policy = 4,
    seal_block = 10,
    seal_hash = "b10",
    first_block = 0,
})
dispute_n.claims = { root = { root = ONE } } -- the honest claim joined the root tournament
listener_n.dispute, listener_n.seal_block, listener_n.seal_hash = dispute_n, 10, "b10"

-- Epoch N+1: a real stored honest player. Its machine's mcycles drive the fake chain's clock.
local epoch_directory = tmp .. "/epoch-" .. (EPOCH_N + 1)
fs.create_directory(epoch_directory)
local player_n1 = prt.new_stored_player(
    { initial_state_hash = template_hash, machine_directory = template_dir, geometry = geometry },
    "honest",
    nil,
    epoch_directory,
    nil
)
local inputs_done, pending_mcycles, per_input_max = 0, 0, 0
local listeners
do
    local handlers = {}
    for name, handler in pairs(player_n1.event_handler) do
        handlers[name] = handler
    end
    local input_added = handlers.input_added
    handlers.input_added = function(self, ...)
        local before = self.epoch_pair.machine:read_reg("mcycle")
        input_added(self, ...)
        local used = self.epoch_pair.machine:read_reg("mcycle") - before
        per_input_max = math.max(per_input_max, used)
        inputs_done = inputs_done + 1
        pending_mcycles = pending_mcycles + used
        while pending_mcycles >= BLOCK_MCYCLES do
            tip, pending_mcycles = tip + 1, pending_mcycles - BLOCK_MCYCLES
        end
        if CONTROL == "interleave" then
            listeners[1].dispute:tick()
        end
    end
    player_n1.event_handler = handlers
end
local listener_n1 = epoch.new(listener_args(EPOCH_N + 1, player_n1, INPUT_BEGIN))

-- Record every tick of epoch N's bridge: the tip it sees and the next-epoch inputs run since the previous tick.
local ticks, last_tick_inputs = {}, 0
do
    local tick = dispute_n.tick
    dispute_n.tick = function(self)
        ticks[#ticks + 1] = { tip = tip, inputs_between = inputs_done - last_tick_inputs }
        last_tick_inputs = inputs_done
        return tick(self)
    end
end

-- ---------------------------------------------------------------------------------------------------------------
-- pass(), extracted verbatim from prt-player.lua and run over the two listeners.
-- ---------------------------------------------------------------------------------------------------------------
listeners = { listener_n, listener_n1 }
local pass
do
    local source = assert(io.open(os.getenv("REPO_DIR") .. "/doc/recipes/prt-player.lua")):read("a")
    local body = assert(source:match("\nlocal function pass%(%)\n(.-\n)end\n"), "harness error: pass() not found")
    local env = setmetatable({
        open_epochs = function() end,
        listeners = listeners,
        measure = function(_, f, ...)
            return f(...)
        end,
    }, { __index = _G })
    pass = assert(load("local function pass()\n" .. body .. "end\nreturn pass", "=prt-player.lua:pass", "t", env))()
end

-- The player's main loop: pass on every new tip (or right away after publishing / a retry), else wait a block.
-- It stops once epoch N's bridge has ticked at a tip past the deadline, or once it submitted.
local socket = require("socket")
local stderr, lines = io.stderr, 0
io.stderr = { -- the listener logs one line per input; count them instead
    write = function()
        lines = lines + 1
    end,
}
local wall = socket.gettime()
while #submitted == 0 and (#ticks == 0 or ticks[#ticks].tip < DEADLINE + 2) do
    local before = tip
    local status = pass()
    if tip == before and not status.published and not status.retry then
        tip = tip + 1
    end
end
wall = socket.gettime() - wall
io.stderr = stderr

assert(inputs_done == K or #submitted > 0, "harness error: epoch N+1 did not process the input batch")
assert(per_input_max >= BLOCK_MCYCLES and per_input_max < 2 * BLOCK_MCYCLES, "harness error: per-input usage")
local worst = 0
local trace = {}
for _, t in ipairs(ticks) do
    worst = math.max(worst, t.inputs_between)
    trace[#trace + 1] = string.format("%d(+%d)", t.tip, t.inputs_between)
end
print(
    string.format(
        "epoch %d move at block %d, responder deadline %d (visible from tip %d with observation depth 4); "
            .. "epoch %d: %d inputs x %d mcycles (1 block each), host wall time %.2fs",
        EPOCH_N,
        MOVE_BLOCK,
        DEADLINE,
        MOVE_BLOCK + 4,
        EPOCH_N + 1,
        inputs_done,
        per_input_max,
        wall
    )
)
print("epoch " .. EPOCH_N .. " bridge ticks at tip(+next-epoch inputs run since previous tick): " .. table.concat(trace, " "))

local ok = false
for _, s in ipairs(submitted) do
    if s.kind == "advanceMatch" and s.inclusion < DEADLINE then
        ok = true
    end
end
if not ok then
    local after
    for _, t in ipairs(ticks) do
        if t.inputs_between > 0 then
            after = t.tip
            break
        end
    end
    print(
        string.format(
            "FAIL: epoch %d's due advanceMatch (window closes at block %d) was never attempted: pass() ran all %d "
                .. "confirmed epoch-%d inputs (%d blocks of work) between two ticks of epoch %d's bridge, whose "
                .. "next tick came at tip %s, past the deadline; the honest claim loses the match by timeout",
            EPOCH_N,
            DEADLINE,
            worst,
            EPOCH_N + 1,
            worst,
            EPOCH_N,
            tostring(after)
        )
    )
    os.exit(1)
end
print(string.format("OK: advanceMatch submitted for inclusion at block %d < %d", submitted[1].inclusion, DEADLINE))
