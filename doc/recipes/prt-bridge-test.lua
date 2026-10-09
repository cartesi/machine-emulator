local eth = require("prt-ethereum")
local evmu = require("cartesi.evmu")
local cast = require("prt-cast")
local bridge = require("prt-bridge")

-- Independent Foundry ABI encoding, including a coordinate outside Lua's range.
local signature = "eventData(uint256,(uint64,bytes),bytes32[])"
local coordinate = evmu.bint(1) << 91
local hash = "0x" .. string.rep("ab", 32)
local expected = cast.run({ "cast", "abi-encode", signature, tostring(coordinate), "(62,0x1234)", "[" .. hash .. "]" })
local actual =
    eth.hex(evmu.encode_abi("(uint256,(uint64,bytes),bytes32[])", { coordinate, { 62, "0x1234" }, { hash } }))
assert(actual == expected:gsub("%s+$", ""), "ABI encoding differs from Foundry")
local input, period, offset = eth.coordinates((evmu.bint(7) << 68) + (evmu.bint(12345) << 30) + 54321)
assert(input == 7 and period == 12345 and offset == 54321)
assert(not pcall(eth.coordinates, evmu.bint(1) << 92))

-- A uint64 access includes the WHOLE authenticated leaf, then bottom-up siblings.
local leaf, sibling = string.rep("L", 32), string.rep("S", 32)
local step = { accesses = { { log2_size = 3, read = leaf, sibling_hashes = { sibling } } } }
assert(eth.transition_proof({ step_log = step }, 1) == eth.hex(leaf .. sibling))
assert(eth.transition_proof({ step_log = step }, 0) == eth.hex(string.rep("\0", 8) .. leaf .. sibling))
local cmio = { accesses = {} }
assert(
    eth.transition_proof({ send_cmio_log = cmio, step_log = step }, 0, "")
        == eth.hex(string.rep("\0", 8) .. leaf .. sibling)
)
assert(not pcall(eth.transition_proof, { step_log = step }, 0, ""))
assert(not pcall(eth.transition_proof, { send_cmio_log = cmio, step_log = step }, 0))
assert(not pcall(eth.transition_proof, { step_log = step }, (1 << 20) - 1))
assert(not pcall(eth.transition_proof, { step_log = step, reset_uarch_log = cmio }, 1))
step.accesses[1].read = string.rep("L", 8)
assert(not pcall(eth.transition_proof, { step_log = step }, 1))

-- Shell arguments are data even when they contain substitutions or quotes.
local argument = "dollar $HOME ; quote ' and $(exit 42)"
assert(cast.run({ "sh", "-c", 'printf "%s" "$1"', "--", argument }) == argument)
assert(not pcall(cast.run, { "sh", "-c", "exit 23" }))

-- Cleanup has no machine, local commitment, or claim ownership requirement.
local captured
local coordinator = bridge.new({
    chain = {},
    abi = {
        calldata = function(_, name, args)
            captured = { name, args }
            return "0x1234"
        end,
    },
    root = "root",
    factory = "factory",
    consensus = "consensus",
    actors = { {} },
    cleaner = {},
})
local action = coordinator:prepare({
    kind = "eliminateMatchByTimeout",
    context = { address = "tournament" },
    event = { one = "one", two = "two" },
    actor = { signer = {} },
})
assert(action.to == "tournament" and captured[1] == "eliminateMatchByTimeout")
assert(captured[2][1][1] == "one" and captured[2][1][2] == "two")

-- Scheduling uses emitted half-open block windows, including equality and
-- asymmetric leaf expiry. These expected verbs do not use contract clock math.
local one = { label = "one", player = {}, signer = { address = "alice" }, claims = { root = { root = "one" } } }
local two = { label = "two", player = {}, signer = { address = "bob" }, claims = { root = { root = "two" } } }
local scheduler = bridge.new({
    chain = {},
    abi = {},
    root = "root",
    factory = "factory",
    consensus = "consensus",
    actors = { one, two },
    cleaner = { label = "keeper" },
})
local creation = { log = { blockHash = "block0", logIndex = "0x0" } }
local context = {
    address = "root",
    creation = creation,
    descriptor = { height = 62, kind = 1, startInstant = 0, allowance = 1 },
    joined = {},
    standing = { matchCount = 1 },
}
local event = {
    name = "MatchCreated",
    address = "root",
    matchIdHash = "match",
    one = "one",
    two = "two",
    responderDeadline = 10,
    eliminableAt = 15,
    log = { blockHash = "block1", logIndex = "0x0" },
}
local snapshot = {
    head = 8,
    order = { context },
    contexts = { root = context },
    events = { event },
    matches = { ["root:match"] = event },
    deleted = {},
    recovered = {},
}
local function ready_at(block)
    local ready = {}
    for _, job in ipairs(scheduler:jobs(snapshot)) do
        if job.first <= block and block < job.last then
            ready[#ready + 1] = job.kind .. ":" .. job.actor.label
        end
    end
    return table.concat(ready, ",")
end
assert(ready_at(9) == "advanceMatch:one")
assert(ready_at(10) == "winMatchByTimeout:two")
assert(ready_at(14) == "winMatchByTimeout:two")
assert(ready_at(15) == "eliminateMatchByTimeout:keeper")
event.name, event.currentHeight = "MatchAdvanced", 61
assert(ready_at(9) == "advanceMatch:two")
assert(ready_at(10) == "winMatchByTimeout:one")
event.name, event.deadlineOne, event.deadlineTwo = "LeafMatchSealed", 10, 15
assert(ready_at(9) == "winLeafMatch:one,winLeafMatch:two")
assert(ready_at(10) == "winMatchByTimeout:two")
assert(ready_at(15) == "eliminateMatchByTimeout:keeper")
event.deadlineOne = 15
assert(ready_at(14) == "winLeafMatch:one,winLeafMatch:two")
assert(ready_at(15) == "eliminateMatchByTimeout:keeper")
snapshot.matches["root:match"] = nil
assert(ready_at(15) == "", "deleted match left a scheduled action")

-- A provider error must never be classified as a losing proof.
local transport = cast.new("http://unused")
function transport.rpc()
    return nil, { code = -32603, message = "unavailable" }
end
assert(not pcall(transport.send, transport, { address = "alice" }, "root", "0x"))
function transport.rpc()
    return nil, { code = 3, message = "execution reverted" }
end
local receipt, failure = transport:send({ address = "alice" }, "root", "0x")
assert(not receipt and failure.code == 3)

-- Observation must be complete and pinned to one canonical head. An orphaned
-- response or an epoch not bound to this root cannot produce usable jobs.
local streams = { factory = {}, consensus = {}, root = {} }
local function log(address, index, value)
    local item = {
        address = address,
        blockNumber = "0x1",
        blockHash = "block1",
        logIndex = index,
        removed = false,
        event = value,
    }
    value.address, value.log = address, item
    streams[address][#streams[address] + 1] = item
    return item
end
log("factory", "0x0", {
    name = "TournamentCreated",
    tournament = "root",
    bondValue = 1,
    descriptor = { initialHash = hash, baseCycle = evmu.bint(0) },
})
local seal = log(
    "consensus",
    "0x1",
    { name = "EpochSealed", tournament = "root", initialMachineStateHash = hash, epochNumber = evmu.bint(0) }
)
local canonical = "head"
local reader = bridge.new({
    chain = {
        head = function()
            return 3, "head"
        end,
        logs = function(_, address)
            return streams[address]
        end,
        rpc = function()
            return { hash = canonical }
        end,
    },
    abi = {
        event = function(_, item)
            return item.event
        end,
    },
    root = "root",
    factory = "factory",
    consensus = "consensus",
    epoch = evmu.bint(0),
    initial_hash = hash,
    actors = { one },
    cleaner = {},
})
assert(reader:observe().contexts.root)
canonical = "replacement"
assert(not pcall(reader.observe, reader), "replaced head was accepted")
canonical = "head"
seal.removed = true
assert(not pcall(reader.observe, reader), "removed log was accepted")
seal.removed = false
streams.consensus = {}
assert(not pcall(reader.observe, reader), "missing epoch seal was accepted")
-- Acceptance waits for the staging block plus the configured delay, including equality.
scheduler.claim_staging_period = 10
snapshot.staged = true
snapshot.staged_event = { log = { blockHash = "staging", blockNumber = "0x14", logIndex = "0x0" } }
assert(ready_at(29) == "")
assert(ready_at(30) == "acceptStagedTournamentResult:keeper")
snapshot.settled = {}
assert(ready_at(30) == "")

-- InputBox and consensus logs share an ordered stream. Inputs delivered after
-- the seal cannot enter this player's epoch, and replay cannot deliver twice.
local epoch = require("prt-epoch")
local util = require("cartesi.util")
local temporary = cast.run({ "mktemp", "-d" }):gsub("%s+$", "")
local _ <close> = setmetatable({}, {
    __close = function()
        cast.run({ "rm", "-rf", temporary })
    end,
})
local sequence = 0
local function accumulating()
    sequence = sequence + 1
    local history = { inputbox = {}, consensus = {} }
    local calls = {}
    local player = {
        event_handler = {
            input_added = function(_, index, path)
                assert(index == #calls, "input was delivered out of order or twice")
                calls[#calls + 1] = util.read_file(path)
            end,
            epoch_sealed = function(_, count)
                assert(count == #calls)
                calls.sealed = true
            end,
        },
    }
    local session = epoch.new({
        chain = {
            head = function()
                return 3, "head"
            end,
            logs = function(_, address)
                return history[address]
            end,
            rpc = function()
                return { hash = "head" }
            end,
        },
        abi = {
            event = function(_, item)
                return item.event
            end,
        },
        app = "app",
        input_box = "inputbox",
        consensus = "consensus",
        factory = "factory",
        epoch = 2,
        input_begin = 3,
        initial_hash = hash,
        previous_outputs_root = hash,
        actors = { { label = "fixture", player = player } },
        cleaner = {},
        directory = temporary .. "/" .. sequence,
    })
    local function append(address, position, observed)
        local item = {
            address = address,
            blockNumber = "0x1",
            blockHash = "block1",
            logIndex = string.format("0x%x", position),
            removed = false,
            event = observed,
        }
        observed.log = item
        history[address][#history[address] + 1] = item
        return item
    end
    local function input_event(index)
        return { name = "InputAdded", appContract = "app", index = index, input = eth.hex(tostring(index)) }
    end
    local function seal_event()
        return {
            name = "EpochSealed",
            epochNumber = evmu.bint(2),
            inputIndexLowerBound = 3,
            inputIndexUpperBound = 5,
            initialMachineStateHash = hash,
            outputsMerkleRoot = hash,
            tournament = "root",
        }
    end
    return session, calls, append, input_event, seal_event
end
do
    local session, calls, append, input_event, seal_event = accumulating()
    local first = append("inputbox", 0, input_event(3))
    assert(not session:poll() and calls[1] == "3" and not calls.sealed)
    assert(not session:poll() and #calls == 1)
    append("inputbox", 1, input_event(4))
    append("inputbox", 3, input_event(5))
    append("consensus", 2, seal_event())
    assert(session:poll() and calls.sealed and #calls == 2 and calls[2] == "4")
    session:poll()
    assert(#calls == 2)
    first.blockHash = "reorg"
    assert(not pcall(session.poll, session), "changed input history was accepted")
end
for _, field in ipairs({
    "inputIndexLowerBound",
    "inputIndexUpperBound",
    "initialMachineStateHash",
    "outputsMerkleRoot",
}) do
    local session, calls, append, input_event, seal_event = accumulating()
    append("inputbox", 0, input_event(3))
    append("inputbox", 1, input_event(4))
    local mismatched = seal_event()
    mismatched[field] = field:match("^input") and 99 or eth.zero
    append("consensus", 2, mismatched)
    assert(not pcall(session.poll, session) and not calls.sealed, "mismatched epoch seal was accepted")
end
do
    local session, calls, append, input_event = accumulating()
    append("inputbox", 0, input_event(4))
    assert(not pcall(session.poll, session) and #calls == 0, "missing input was accepted")
end
print("PRT bridge encoding, scheduling, input streaming, and process-boundary tests passed.")
