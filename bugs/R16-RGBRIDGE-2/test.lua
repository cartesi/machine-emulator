-- R16-RGBRIDGE-2: the epoch listener (doc/recipes/prt-epoch.lua) must assign to its epoch at most the input limit
-- per epoch (2^ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = 2^24 inputs).
--
-- A3 requires the referee's input record to assign no more than 2^24 inputs to an epoch. The InputBox accepts any
-- number of inputs (section 7), so a referee that meets A3 caps the epoch at seal time and leaves the backlog
-- pending for the next epochs. Dave does exactly this (DaveConsensus.sol, cartesi/dave 7eb6c6b, after
-- v3.0.0-alpha.7):
--     uint256 constant MAX_INPUTS_PER_EPOCH = 1 << EmulatorConstants.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH;
--     function _nextInputIndexUpperBound(uint256 lowerBound) internal view returns (uint256) {
--         uint256 pendingInputs = _INPUT_BOX.getNumberOfInputs(_APP_CONTRACT) - lowerBound;
--         return lowerBound + pendingInputs.min(MAX_INPUTS_PER_EPOCH);
--     }
-- and both the constructor (epoch 0) and acceptStagedTournamentResult (epoch N+1) seal with it.
--
-- The listener instead hands the honest player every InputAdded with index >= input_begin that precedes the
-- EpochSealed log (prt-epoch.lua:62-76), with no upper bound. With more than 2^24 pending inputs at the seal it
-- delivers input offset 2^24 to the player, and then the seal check `inputIndexUpperBound == input_begin + #inputs`
-- raises "sealed input count mismatch" (prt-epoch.lua:91). The bridge is never created, and every relaunch replays
-- the same logs into the same crash, so the honest claim never joins the epoch's tournament (R4, section 1
-- completeness failure; section 8 Critical: crash caused by relayed data the honest operator must process).
--
-- The test runs the real prt-epoch.lua against a stub chain and ABI and a recording stub player, at the real
-- limit: the listener starts as if it had already received 2^24 - 1 inputs of the epoch (a proxy table whose length
-- is 2^24 - 1, so no memory is spent on them). The chain then shows InputAdded 2^24 - 1, InputAdded 2^24 (the first
-- backlog input), and EpochSealed(lower 0, upper 2^24) as the capped consensus emits. The correct behavior: the
-- listener delivers only offset 2^24 - 1, seals with 2^24 inputs, and creates the dispute bridge; input 2^24 is left
-- to the next epoch's listener (input_begin = 2^24).

-- prt-ethereum requires dkjson only to read contract artifacts, which this test does not use.
package.preload.dkjson = function()
    return {
        null = setmetatable({}, {}),
        decode = function()
            error("dkjson stub")
        end,
        encode = function()
            error("dkjson stub")
        end,
    }
end
-- The dispute bridge is replaced by a recorder: only whether and with what the listener creates it matters here.
local bridges = {}
package.preload["prt-bridge"] = function()
    return {
        new = function(args)
            bridges[#bridges + 1] = args
            return { stub_bridge = true }
        end,
    }
end

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local epoch = require("prt-epoch")

local CAP = 1 << cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH -- 2^24, Dave's MAX_INPUTS_PER_EPOCH
assert(CAP == 1 << 24, "unexpected input limit per epoch")

local function q(n)
    return string.format("0x%x", n)
end
local app, box, consensus = "0x" .. string.rep("a", 40), "0x" .. string.rep("b", 40), "0x" .. string.rep("c", 40)
local initial_hash, outputs_root = "0x" .. string.rep("1", 64), "0x" .. string.rep("2", 64)

-- Chain logs (already decoded; the ABI stub returns them as events).
local logs = {}
local function add_input(index, block)
    logs[#logs + 1] = {
        address = box,
        blockNumber = q(block),
        blockHash = "0x" .. string.format("%064x", block),
        logIndex = "0x0",
        removed = false,
        ev = { name = "InputAdded", appContract = app, index = evmu.bint(index), input = "0x" .. string.format("%08x", index) },
    }
end
add_input(CAP - 1, 10) -- the last input of the epoch
add_input(CAP, 11) -- the first input of the backlog, which the capped consensus leaves pending
local PENDING = CAP + 1
logs[#logs + 1] = {
    address = consensus,
    blockNumber = q(20),
    blockHash = "0x" .. string.format("%064x", 20),
    logIndex = "0x0",
    removed = false,
    ev = {
        name = "EpochSealed",
        epochNumber = evmu.bint(1),
        inputIndexLowerBound = evmu.bint(0),
        inputIndexUpperBound = evmu.bint(math.min(PENDING, CAP)), -- DaveConsensus._nextInputIndexUpperBound(0)
        initialMachineStateHash = initial_hash,
        outputsMerkleRoot = outputs_root,
        tournament = "0x" .. string.rep("d", 40),
    },
}

local chain = {
    head = function()
        return 30, "0x" .. string.format("%064x", 30)
    end,
    is_canonical = function()
        return true
    end,
    logs = function(_, address, last, first)
        local r = {}
        for _, l in ipairs(logs) do
            local b = tonumber(l.blockNumber)
            if l.address == address and b >= first and b <= last then
                r[#r + 1] = l
            end
        end
        return r
    end,
}
local abi = {
    event = function(_, log)
        local e = {}
        for k, v in pairs(log.ev) do
            e[k] = v
        end
        return e
    end,
}

local delivered, sealed_with = {}, nil
local player = {
    event_handler = {
        input_added = function(_, offset)
            delivered[#delivered + 1] = offset
        end,
        epoch_sealed = function(_, n)
            sealed_with = n
        end,
    },
}

local listener = epoch.new({
    chain = chain,
    abi = abi,
    app = app,
    input_box = box,
    consensus = consensus,
    factory = "0x" .. string.rep("f", 40),
    epoch = 1,
    input_begin = 0,
    initial_hash = initial_hash,
    previous_outputs_root = outputs_root,
    geometry = {},
    player = player,
    signer = {},
    label = "honest",
    first_block = 0,
    input_policy = 1,
    dispute_policy = 1,
})

-- The listener has already received inputs 0 .. 2^24 - 2 of this epoch (their logs precede the stub's first block).
-- A proxy holds only the inputs delivered from here on; its length counts the earlier ones.
local base, extra = CAP - 1, {}
listener.inputs = setmetatable({}, {
    __len = function()
        return base + #extra
    end,
    __newindex = function(_, k, v)
        assert(k == base + #extra + 1, "inputs appended out of order")
        extra[#extra + 1] = v
    end,
    __index = function(_, k)
        return k > base and extra[k - base] or nil
    end,
})

local ok, err = pcall(listener.poll, listener)
local offsets = {}
for _, o in ipairs(delivered) do
    offsets[#offsets + 1] = tostring(o)
end
print("input limit per epoch: " .. CAP .. "; pending at seal: " .. PENDING .. "; sealed upper bound: " .. CAP)
print("offsets delivered to the player: " .. table.concat(offsets, ","))
print("poll: " .. (ok and "ok" or ("raised: " .. tostring(err))))

local function fail(msg)
    print("FAIL: " .. msg)
    os.exit(1)
end
for _, o in ipairs(delivered) do
    if o >= CAP then
        fail(
            "the epoch listener delivered input offset "
                .. o
                .. " (>= the 2^24 input limit per epoch, A3) to the honest player"
                .. (ok and "" or (", then crashed at the capped EpochSealed: " .. tostring(err)))
        )
    end
end
if not ok then
    fail("the epoch listener crashed at a seal that assigns exactly 2^24 inputs: " .. tostring(err))
end
if #delivered ~= 1 or delivered[1] ~= CAP - 1 then
    fail("expected exactly offset " .. (CAP - 1) .. " to be delivered")
end
if sealed_with ~= CAP or #listener.inputs ~= CAP or #bridges ~= 1 or #bridges[1].inputs ~= CAP then
    fail("the epoch was not sealed with exactly 2^24 inputs and a dispute bridge")
end
print("OK: the listener caps the epoch at 2^24 inputs and leaves input " .. CAP .. " to the next epoch")
os.exit(0)
