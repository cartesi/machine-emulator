-- R13-ROLECOST-2: the honest bridge's per-observation RPC cost grows linearly with the number of
-- child tournaments ever created in the epoch, including finished Sybil-vs-Sybil ones.
--
-- prt-bridge.lua observe() rebuilds its address list on every observation from the factory, the
-- consensus, the root, and the child of every NewInnerTournament event ever seen, and calls
-- history:get_logs for each one. prt-log-history.lua get_logs issues at least one eth_getLogs per
-- address whenever the observation head moved. tick() starts with refresh() -> observe(), and
-- attempt() refreshes again before publishing (which re-polls everything if the head moved while
-- the player computed). So every honest move pays (3 + T) sequential RPC round trips per new block,
-- where T is the number of child tournaments, which an attacker inflates with Sybil pairs that seal
-- leaf matches in the root (section 7). PRT keeps the honest claim's cost logarithmic in the
-- number of Sybils (A7); this per-move latency is linear and charged to the honest clock.
--
-- The test drives the real bridge (prt-bridge.lua + prt-log-history.lua) against a fake chain that
-- counts RPCs. K finished child tournaments are created (NewInnerTournament followed by the
-- MatchDeleted that ends the parent match, i.e. eliminated Sybil-vs-Sybil tournaments the honest
-- claim never entered). After a warm-up tick, the head advances by one block and a single tick is
-- measured. Correct behavior: the RPC count of that tick does not depend on K. It exits nonzero
-- because the count is 3 + K eth_getLogs calls.
-- dkjson (needed by prt-ethereum.lua) is not installed system-wide; a vendored copy is used.
package.path = "./vendor/?.lua;" .. package.path
local evmu = require("cartesi.evmu")
local bridge = require("prt-bridge")
local prt = require("prt")
local geometry = prt.new_geometry(10)
local hash = "0x" .. string.rep("ab", 32)
local other = "0x" .. string.rep("cd", 32)

local function q(n)
    return string.format("0x%x", n)
end

-- Builds the per-address log streams for K finished Sybil child tournaments.
local function build_streams(K, live)
    local streams = { factory = {}, consensus = {}, root = {} }
    local index = {}
    local function log(address, block, value)
        streams[address] = streams[address] or {}
        index[block] = (index[block] or -1) + 1
        local item = {
            address = address,
            blockNumber = q(block),
            blockHash = "block" .. block,
            logIndex = q(index[block]),
            removed = false,
            event = value,
        }
        value.address, value.log = address, item
        local s = streams[address]
        s[#s + 1] = item
        return item
    end
    log("factory", 1, {
        name = "TournamentCreated",
        tournament = "root",
        bondValue = 1,
        descriptor = {
            initialHash = hash,
            baseCycle = evmu.bint(0),
            height = geometry.mcycle_height,
            log2Stride = geometry.uarch_height,
            level = 0,
            kind = 1,
            startInstant = 1,
            allowance = 1, -- joining window long closed: the honest bridge builds no claim here
        },
    })
    log("consensus", 1, {
        name = "EpochSealed",
        tournament = "root",
        initialMachineStateHash = hash,
        epochNumber = evmu.bint(0),
    })
    local children = {}
    for i = 1, K do
        local child = string.format("child%06d", i)
        children[#children + 1] = child
        streams[child] = {}
        log("root", 2, {
            name = "NewInnerTournament",
            matchIdHash = "m" .. i,
            childTournament = child,
            one = "sybilA" .. i,
            two = "sybilB" .. i,
            contestedFinalStateOne = hash,
            contestedFinalStateTwo = other,
            bondValue = 1,
            descriptor = {
                initialHash = hash,
                baseCycle = evmu.bint(0),
                height = geometry.uarch_height,
                log2Stride = 0,
                level = 1,
                kind = 0,
                startInstant = 2,
                allowance = 1,
            },
        })
        log(child, 2, { name = "CommitmentJoined", commitment = "sybilA" .. i, submitter = "attacker" })
    end
    -- Every Sybil child tournament is then eliminated, deleting its parent match: it is finished.
    -- With live, the last one stays open, so the cleanup bridge has a due eliminateInnerTournament job.
    for i = 1, live and K - 1 or K do
        log("root", 3, { name = "MatchDeleted", matchIdHash = "m" .. i })
    end
    return streams
end

-- rpcs_per_block, when given, makes the chain advance one block every that many RPCs: a wall
-- clock in which each RPC round trip takes block_time / rpcs_per_block.
local function new_bridge(K, live, rpcs_per_block)
    local streams = build_streams(K, live)
    local counts = { logs = 0, head = 0, is_canonical = 0 }
    local chain = { head_block = 5, rpcs = 0 }
    local function rpc()
        chain.rpcs = chain.rpcs + 1
        if rpcs_per_block and chain.rpcs % rpcs_per_block == 0 then
            chain.head_block = chain.head_block + 1
        end
    end
    function chain:head()
        counts.head = counts.head + 1
        rpc()
        return self.head_block, "h" .. self.head_block, self.head_block + 4, "t" .. self.head_block
    end
    function chain.is_canonical()
        counts.is_canonical = counts.is_canonical + 1
        rpc()
        return true
    end
    function chain.logs(_, address, last_block, first_block)
        counts.logs = counts.logs + 1
        rpc()
        local result = {}
        for _, item in ipairs(streams[address] or {}) do
            local number = tonumber(item.blockNumber)
            if number >= (first_block or 0) and number <= last_block then
                result[#result + 1] = item
            end
        end
        return result
    end
    local b = bridge.new({
        geometry = geometry,
        transactions = {
            pending = function()
                return nil
            end,
            receipt = function()
                return nil
            end,
            submit = function()
                return { published = true }
            end,
        },
        chain = chain,
        abi = {
            event = function(_, item)
                return item.event
            end,
            calldata = function(_, name)
                return name
            end,
        },
        root = "root",
        factory = "factory",
        consensus = "consensus",
        epoch = evmu.bint(0),
        initial_hash = hash,
        first_block = 1,
        player = { event_handler = {} },
        signer = { address = "honest" },
        label = "honest",
        cleanup = live or false,
        observation_policy = 0,
    })
    return b, chain, counts
end

-- Measures one tick after the head advanced by one block (no new logs anywhere).
local function measure(K)
    local b, chain, counts = new_bridge(K)
    local snapshot = assert(b:tick(), "warm-up tick failed")
    assert(snapshot.ready, "warm-up snapshot not ready")
    local children = 0
    for _, context in ipairs(snapshot.order) do
        if context.parent then
            children = children + 1
            assert(snapshot.deleted[context.parent_match], "child tournament is not finished")
        end
    end
    assert(children == K, "fixture did not create the child tournaments")
    for key in pairs(counts) do
        counts[key] = 0
    end
    chain.head_block = chain.head_block + 1
    local t0 = os.clock()
    snapshot = assert(b:tick(), "measured tick failed")
    local elapsed = os.clock() - t0
    assert(snapshot.ready and snapshot.head == chain.head_block, "measured tick did not observe the new head")
    return counts.logs, counts.logs + counts.head + counts.is_canonical, elapsed, #snapshot.logs
end

local results = {}
for _, K in ipairs({ 10, 1000 }) do
    local logs, rpcs, elapsed, nlogs = measure(K)
    results[K] = logs
    print(
        string.format(
            "K=%5d finished child tournaments: one tick after a 1-block head advance issued %d eth_getLogs (%d RPCs total), re-sorted %d logs, %.3f s Lua CPU; at 30 ms/RPC = %.1f s",
            K,
            logs,
            rpcs,
            nlogs,
            elapsed,
            rpcs * 0.030
        )
    )
end

-- Informational: with a 12 s block and 30 ms per RPC (400 RPCs per block), polling 1000 finished
-- children takes longer than a block, so the refresh inside attempt() sees a new head and re-polls
-- everything before the bridge can publish its due transaction.
do
    local K = 1000
    local b, chain, counts = new_bridge(K, true, 400)
    assert(b:tick(), "warm-up tick failed")
    for key in pairs(counts) do
        counts[key] = 0
    end
    chain.rpcs = 0
    chain.head_block = chain.head_block + 1
    local _, published = b:tick()
    local rpcs = counts.logs + counts.head + counts.is_canonical
    print(
        string.format(
            "K=%5d, 400 RPCs per 12 s block: one publishing tick issued %d eth_getLogs (%d RPCs, %.1f s at 30 ms/RPC, published=%s)",
            K,
            counts.logs,
            rpcs,
            rpcs * 0.030,
            tostring(published)
        )
    )
end

-- Correct behavior: polling cost per tick independent of the number of finished Sybil tournaments.
if results[1000] > 2 * results[10] then
    print(
        string.format(
            "FAIL: honest bridge per-tick eth_getLogs count grows linearly with Sybil child tournaments (%d for K=10, %d for K=1000 = 3+K): every finished NewInnerTournament child is re-polled on each observation (prt-bridge.lua observe, prt-log-history.lua get_logs)",
            results[10],
            results[1000]
        )
    )
    os.exit(1)
end
print("OK: per-tick polling cost does not depend on the number of child tournaments")
os.exit(0)
