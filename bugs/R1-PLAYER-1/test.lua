#!/usr/bin/env lua5.4
-- R1-PLAYER-1: a relaunched honest bridge abandons its own claim when another account joined that
-- commitment first (doc/recipes/prt-bridge.lua update_claims/joined_by/jobs).
--
-- Threat model, section 7: the adversary may "hold any claim, including the honest one, and answer for
-- it", and may race transactions. The honest claim is deterministic, so an adversary can join the honest
-- commitment from its own account before the honest player does. jobs() then schedules no join for the
-- honest player (context.joined[claim.root] already exists) and the honest player defends the claim from
-- memory. update_claims() rebinds a claim after the joining window closes only when joined_by() finds a
-- CommitmentJoined whose submitter is the bridge's own signer. So a relaunched honest process (crash,
-- prt-supervise.sh restart, operator restart; the recipe says "its bridge derives its claims from the
-- chain") binds nothing and answers nothing for the honest claim: no advanceMatch / seal / winLeafMatch /
-- winMatchByTimeout / winInnerTournament. The adversary lets the honest commitment time out and its own
-- claim wins (R4 honest completeness, A7, section 1 completeness failure).
--
-- The test drives the real bridge code end to end: methods:refresh() -> observe() over a mock chain whose
-- logs are the decoded events of the scenario, update_claims(), and jobs() filtered by due inclusion block
-- exactly as tick() does. Two scenarios, each with a control:
--   A. root tournament: adversary joins the honest mcycle commitment first, then a Sybil; a match
--      honest-vs-Sybil awaits the honest response. The window closes at block 30; the honest process is
--      relaunched at tip 60.
--   B. uarch child tournament: honest signer joined the root, a NewInnerTournament opens a child over a
--      period; the adversary joins the honest uarch commitment first, then a dishonest one; the child
--      match awaits the honest response. Its window closes at block 60; relaunch at tip 100.
-- Control: the same timeline with the honest signer as submitter of the honest join; the relaunched bridge
-- must (and does) answer. Correct behavior: the relaunched bridge must schedule the same response
-- (advanceMatch for the honest claim) as the process that never restarted. Exit 1 while the defect exists.

-- prt-ethereum requires dkjson only to read contract artifacts, which this test does not use.
package.preload.dkjson = function()
    return { null = setmetatable({}, {}), decode = function() error("dkjson stub") end, encode = function() error("dkjson stub") end }
end

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")
local bridge = require("prt-bridge")
local prt = require("prt")

local geometry = prt.new_geometry(10)
local HONEST, ADVERSARY = "0x" .. string.rep("a1", 20), "0x" .. string.rep("bd", 20)
local initial = "0x" .. string.rep("11", 32)

local function q(n)
    return string.format("0x%x", n)
end

-- A claim whose every leaf is the same state hash (a valid computation hash of the given height).
local function repeated_claim(state_hash, height)
    local root, siblings = state_hash, {}
    for i = 1, height do
        siblings[i] = root
        root = cartesi.keccak256(root, root)
    end
    return {
        computation_hash_left = siblings[height],
        computation_hash_right = siblings[height],
        final_state_hash_proof = {
            target_address = (1 << height) - 1,
            log2_target_size = 0,
            log2_root_size = height,
            target_hash = state_hash,
            root_hash = root,
            sibling_hashes = siblings,
        },
    }
end

local mcycle_response = repeated_claim(cartesi.keccak256("honest epoch state"), geometry.mcycle_height)
local uarch_response = repeated_claim(cartesi.keccak256("honest period state"), geometry.uarch_height)
local honest_root = eth.claim(mcycle_response, geometry.mcycle_height)
local honest_child = eth.claim(uarch_response, geometry.uarch_height)
local sybil_root = eth.claim(repeated_claim(cartesi.keccak256("sybil"), geometry.mcycle_height), geometry.mcycle_height)
local dishonest_child =
    eth.claim(repeated_claim(cartesi.keccak256("dishonest period"), geometry.uarch_height), geometry.uarch_height)

-- Builds the decoded log streams of a scenario. join_submitter is the account whose CommitmentJoined
-- carries the honest commitment (the honest player schedules no join of its own once it exists).
local function new_streams(child_scenario, join_submitter)
    local streams = { factory = {}, consensus = {}, root = {}, child = {} }
    local counters = {}
    local function log(address, block, value)
        counters[block] = (counters[block] or -1) + 1
        local item = {
            address = address,
            blockNumber = q(block),
            blockHash = "b" .. block,
            logIndex = q(counters[block]),
            removed = false,
            event = value,
        }
        value.address, value.log = address, item
        table.insert(streams[address], item)
    end
    log("factory", 1, {
        name = "TournamentCreated",
        tournament = "root",
        bondValue = evmu.bint(1),
        descriptor = {
            initialHash = initial,
            baseCycle = evmu.bint(0),
            height = evmu.bint(geometry.mcycle_height),
            log2Stride = evmu.bint(geometry.uarch_height),
            level = evmu.bint(0),
            kind = evmu.bint(1),
            startInstant = evmu.bint(10),
            allowance = evmu.bint(20), -- root joining window: blocks [10, 30)
        },
    })
    log("consensus", 2, {
        name = "EpochSealed",
        tournament = "root",
        epochNumber = evmu.bint(1),
        initialMachineStateHash = initial,
    })
    if not child_scenario then
        log("root", 11, { name = "CommitmentJoined", commitment = honest_root.root, submitter = join_submitter })
        log("root", 12, { name = "CommitmentJoined", commitment = sybil_root.root, submitter = ADVERSARY })
        log("root", 13, {
            name = "MatchCreated",
            matchIdHash = "m",
            one = honest_root.root, -- at the initial height, "one" responds
            two = sybil_root.root,
            leftOfTwo = sybil_root.children[1],
            responderDeadline = evmu.bint(200),
            eliminableAt = evmu.bint(400),
        })
        return streams
    end
    -- Child scenario: the honest signer joined the root itself, so the root stays bound after a relaunch.
    log("root", 11, { name = "CommitmentJoined", commitment = honest_root.root, submitter = HONEST })
    log("root", 12, { name = "CommitmentJoined", commitment = sybil_root.root, submitter = ADVERSARY })
    log("root", 13, {
        name = "MatchCreated",
        matchIdHash = "m",
        one = honest_root.root,
        two = sybil_root.root,
        leftOfTwo = sybil_root.children[1],
        responderDeadline = evmu.bint(200),
        eliminableAt = evmu.bint(400),
    })
    log("root", 40, {
        name = "NewInnerTournament",
        matchIdHash = "m",
        childTournament = "child",
        one = honest_root.root,
        two = sybil_root.root,
        contestedFinalStateOne = honest_child.final_state,
        contestedFinalStateTwo = dishonest_child.final_state,
        bondValue = evmu.bint(1),
        descriptor = {
            initialHash = initial,
            baseCycle = evmu.bint(5) << geometry.uarch_height, -- period 5 of input 0
            height = evmu.bint(geometry.uarch_height),
            log2Stride = evmu.bint(0),
            level = evmu.bint(1),
            kind = evmu.bint(0),
            startInstant = evmu.bint(40),
            allowance = evmu.bint(20), -- child joining window: blocks [40, 60)
        },
    })
    log("child", 41, { name = "CommitmentJoined", commitment = honest_child.root, submitter = join_submitter })
    log("child", 42, { name = "CommitmentJoined", commitment = dishonest_child.root, submitter = ADVERSARY })
    log("child", 43, {
        name = "MatchCreated",
        matchIdHash = "cm",
        one = honest_child.root,
        two = dishonest_child.root,
        leftOfTwo = dishonest_child.children[1],
        responderDeadline = evmu.bint(300),
        eliminableAt = evmu.bint(500),
    })
    return streams
end

-- A mock node over the streams. The tip is set by the test; the observation head is tip - 4.
local function new_chain(streams)
    local chain = { tip = 0 }
    function chain.head()
        local tip = chain.tip
        return tip - 4, "h" .. (tip - 4), tip, "t" .. tip
    end
    function chain.logs(_, address, last_block, first_block)
        local result = {}
        for _, item in ipairs(streams[address] or {}) do
            local number = eth.small(item.blockNumber)
            if number >= (first_block or 0) and number <= last_block then
                result[#result + 1] = item
            end
        end
        return result
    end
    function chain.is_canonical()
        return true
    end
    return chain
end

local function new_bridge(chain)
    local player = { event_handler = {} }
    function player.event_handler.commit_mcycle_claim()
        return mcycle_response
    end
    function player.event_handler.commit_uarch_claim(_, input, period)
        assert(input == 0 and period == 5, "harness error: unexpected uarch claim coordinates")
        return uarch_response
    end
    return bridge.new({
        geometry = geometry,
        transactions = {},
        chain = chain,
        abi = { event = function(_, item) return item.event end },
        root = "root",
        factory = "factory",
        consensus = "consensus",
        epoch = evmu.bint(1),
        initial_hash = initial,
        player = player,
        signer = { address = HONEST },
        label = "honest",
        cleanup = false,
    })
end

-- The jobs a tick would attempt at this tip, as "kind@tournament:claim".
local function due(b, chain, tip)
    chain.tip = tip
    local snapshot = assert(b:refresh(), "harness error: observation rejected")
    assert(snapshot.ready, "harness error: epoch not sealed in observation")
    local list = {}
    for _, job in ipairs(b:jobs(snapshot)) do
        if snapshot.tip + 1 >= job.first and snapshot.tip + 1 < job.last then
            list[#list + 1] = job
        end
    end
    return list
end

local function has(list, kind, address, root)
    for _, job in ipairs(list) do
        if job.kind == kind and job.context.address == address and job.root == root then
            return true
        end
    end
    return false
end

local function describe(list)
    local r = {}
    for _, job in ipairs(list) do
        r[#r + 1] = job.kind .. "@" .. job.context.address
    end
    table.sort(r)
    return "[" .. table.concat(r, ",") .. "]"
end

-- Runs one timeline. Returns the due jobs of the running process and of a relaunched process.
local function run(child_scenario, submitter)
    local streams = new_streams(child_scenario, submitter)
    local open_tip, closed_tip = 20, 60
    local address, claim = "root", honest_root.root
    if child_scenario then
        open_tip, closed_tip, address, claim = 50, 100, "child", honest_child.root
    end
    -- The process that observed the joining window open.
    local chain = new_chain(streams)
    local running = new_bridge(chain)
    local early = due(running, chain, open_tip)
    assert(not has(early, "joinTournament", address, claim), "harness error: honest join scheduled over an existing join")
    assert(has(early, "advanceMatch", address, claim), "harness error: running process does not answer " .. describe(early))
    local late = due(running, chain, closed_tip)
    assert(has(late, "advanceMatch", address, claim), "harness error: running process stopped answering " .. describe(late))
    -- The same honest operator relaunched after the window closed (fresh process, same signer and chain).
    local chain2 = new_chain(streams)
    local relaunched = new_bridge(chain2)
    local after = due(relaunched, chain2, closed_tip)
    return late, after, has(after, "advanceMatch", address, claim)
end

local failures = {}
for _, scenario in ipairs({ { false, "root (mcycle) tournament" }, { true, "uarch child tournament" } }) do
    local child_scenario, name = scenario[1], scenario[2]
    -- Control: the honest signer submitted the honest join; a relaunched bridge must still answer.
    local c_late, c_after, c_ok = run(child_scenario, HONEST)
    print(string.format("%-26s join by honest signer:  running=%s relaunched=%s", name, describe(c_late), describe(c_after)))
    assert(c_ok, "harness error: control relaunch does not answer in " .. name)
    -- The attack: the adversary joined the honest commitment first.
    local late, after, ok = run(child_scenario, ADVERSARY)
    print(string.format("%-26s join by adversary:      running=%s relaunched=%s", name, describe(late), describe(after)))
    if not ok then
        failures[#failures + 1] = name
    end
end

if #failures > 0 then
    print("FAIL: after a relaunch past the joining window, the honest bridge schedules no response "
        .. "(advanceMatch) for its own claim in the " .. table.concat(failures, " and ")
        .. " because the adversary, not the honest signer, submitted the CommitmentJoined of the honest "
        .. "commitment (prt-bridge.lua joined_by); the honest claim times out (R4/A7 completeness failure)")
    os.exit(1)
end
print("OK: a relaunched honest bridge answers for its claim whoever joined the honest commitment")
os.exit(0)
