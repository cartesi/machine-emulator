local eth = require("prt-ethereum")
local evmu = require("cartesi.evmu")
local cast = require("prt-cast")
local bridge = require("prt-bridge")
local prt = require("prt")
local geometry = prt.new_geometry(10)

-- Independent Foundry ABI encoding, including a coordinate outside Lua's range.
local signature = "eventData(uint256,(uint64,bytes),bytes32[])"
local coordinate = evmu.bint(1) << 91
local hash = "0x" .. string.rep("ab", 32)
local expected = cast.run({ "cast", "abi-encode", signature, tostring(coordinate), "(62,0x1234)", "[" .. hash .. "]" })
local actual =
    eth.hex(evmu.encode_abi("(uint256,(uint64,bytes),bytes32[])", { coordinate, { 62, "0x1234" }, { hash } }))
assert(actual == expected:gsub("%s+$", ""), "ABI encoding differs from Foundry")
local input, period, offset =
    eth.coordinates((evmu.bint(7) << 68) + (evmu.bint(12345) << geometry.uarch_height) + 54321, geometry)
assert(input == 7 and period == 12345 and offset == 54321)
assert(not pcall(eth.coordinates, evmu.bint(1) << 92, geometry))

-- The geometry comes from the tournament factory's two levels: the mcycle claim strides one period
-- of uarch cycles, and the uarch claim one uarch cycle.
local function factory_chain(levels)
    local abi = {
        calldata = function(_, name, arguments)
            return name .. ":" .. tostring(arguments[1])
        end,
    }
    local chain = {
        call = function(_, address, data)
            assert(address == "factory")
            if data == "tournamentLevelCount:nil" then
                return eth.hex(evmu.encode_abi("(uint64)", { #levels + 1 }))
            end
            local level = levels[assert(tonumber(data:match("^tournamentParameters:(%d+)$")))]
            return eth.hex(evmu.encode_abi("(uint64,uint64,uint64,uint64,uint64,uint64)", {
                #levels + 1,
                level.log2step,
                level.height,
                0,
                0,
                0,
            }))
        end,
    }
    return chain, abi
end
do
    local chain, abi = factory_chain({
        [0] = { log2step = geometry.uarch_height, height = geometry.mcycle_height },
        { log2step = 0, height = geometry.uarch_height },
    })
    local read = bridge.read_geometry(chain, abi, "factory")
    assert(read.log2_mcycles_per_period == geometry.log2_mcycles_per_period, "factory geometry was misread")
    chain, abi = factory_chain({
        [0] = { log2step = geometry.uarch_height, height = geometry.mcycle_height },
        { log2step = 1, height = geometry.uarch_height },
    })
    assert(not pcall(bridge.read_geometry, chain, abi, "factory"), "a uarch level with a stride was accepted")
end

-- The log history fetches only the blocks it has not seen. After a reorg it drops the logs past
-- the newest block still canonical and fetches again from there.
do
    local log_history = require("prt-log-history")
    local canonical, stream, fetches = {}, {}, {}
    local function add(number, block_hash)
        stream[#stream + 1] = { blockNumber = string.format("0x%x", number), blockHash = block_hash, logIndex = "0x0" }
        canonical[number] = block_hash
    end
    local chain = {
        is_canonical = function(_, number, block_hash)
            return canonical[number] == block_hash
        end,
        logs = function(_, _, last_block, first_block)
            fetches[#fetches + 1] = first_block .. "-" .. last_block
            local result = {}
            for _, item in ipairs(stream) do
                local number = tonumber(item.blockNumber)
                if number >= first_block and number <= last_block and canonical[number] == item.blockHash then
                    result[#result + 1] = item
                end
            end
            return result
        end,
    }
    local history = log_history.new(chain)
    add(1, "a1")
    canonical[5] = "h5"
    history:observe(5, "h5")
    assert(#history:get_logs("a") == 1)
    add(7, "a7")
    canonical[9] = "h9"
    history:observe(9, "h9")
    assert(#history:get_logs("a") == 2)
    -- The reorg replaces block 7 and the head, keeping block 1.
    canonical[7], canonical[9] = nil, "r9"
    add(8, "r8")
    history:observe(9, "r9")
    local logs = history:get_logs("a")
    assert(#logs == 2 and logs[1].blockHash == "a1" and logs[2].blockHash == "r8", "the reorg kept a replaced log")
    assert(table.concat(fetches, ",") == "0-5,6-9,2-9", "the history fetched blocks it had already seen")
    -- A leading zero would break the ordering of positions as strings.
    stream[#stream + 1] = { blockNumber = "0x0a", blockHash = "a10", logIndex = "0x0" }
    canonical[10] = "a10"
    history:observe(10, "a10")
    assert(not pcall(history.get_logs, history, "a"), "a non-canonical log position was accepted")
end

-- The log history halves its page when a request fails and doubles it after one succeeds. A
-- failure on a single block is raised, keeping the pages fetched before it.
do
    local log_history = require("prt-log-history")
    local limit, broken, fetches = 4, nil, {}
    local chain = {
        logs = function(_, _, last_block, first_block)
            fetches[#fetches + 1] = first_block .. "-" .. last_block
            assert(last_block - first_block < limit, "range too large")
            assert(not broken or broken < first_block or broken > last_block, "block unavailable")
            return { { blockNumber = string.format("0x%x", last_block), blockHash = "b", logIndex = "0x0" } }
        end,
    }
    local history = log_history.new(chain)
    history:observe(9, "h9")
    assert(#history:get_logs("a") == 3)
    assert(table.concat(fetches, ",") == "0-9,0-4,0-1,2-5,6-9", "the page did not adapt to the provider")
    history, fetches, broken = log_history.new(chain), {}, 3
    history:observe(9, "h9")
    local ok, err = pcall(history.get_logs, history, "a")
    assert(not ok and err:find("block unavailable", 1, true), "a failure on a single block was not raised")
    assert(table.concat(fetches, ",") == "0-9,0-4,0-1,2-5,2-3,2-2,3-4,3-3", "the page did not shrink to the failure")
    fetches, broken = {}, nil
    assert(#history:get_logs("a") == 4)
    assert(table.concat(fetches, ",") == "3-9,3-5,6-9", "the history fetched again the pages it had kept")
end

-- The WebSocket client's SHA-1 matches the standard vectors, including a message whose padding
-- needs a second block, and the handshake answers the RFC 6455 example key.
do
    local websocket = require("prt-websocket")
    local cartesi = require("cartesi")
    for message, digest in pairs({
        [""] = "0xda39a3ee5e6b4b0d3255bfef95601890afd80709",
        ["abc"] = "0xa9993e364706816aba3e25717850c26c9cd0d89d",
        ["abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"] = "0x84983e441c3bd26ebaae4aa1f95129e5e54670f1",
    }) do
        assert(cartesi.tohex(websocket.sha1(message)) == digest, "SHA-1 of " .. #message .. " bytes")
    end
    assert(websocket.get_accept("dGhlIHNhbXBsZSBub25jZQ==") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    -- Frames cross every length encoding in both directions. A fragmented message is reassembled
    -- around a ping, which is answered. A message that never starts times out.
    local incoming, sent = {}, {}
    local position = 1
    local fake = {
        settimeout = function() end,
        send = function(_, data)
            sent[#sent + 1] = data
            return #data
        end,
        receive = function(_, count)
            local data = table.concat(incoming)
            if position > #data then
                return nil, "timeout"
            end
            local result = data:sub(position, position + count - 1)
            position = position + count
            return result
        end,
    }
    local function server_frame(first, payload)
        local length = #payload
        local header = length < 126 and string.pack(">BB", first, length)
            or length < 65536 and string.pack(">BBI2", first, 126, length)
            or string.pack(">BBI8", first, 127, length)
        return header .. payload
    end
    -- The payload of a client frame, which must be masked.
    local function unmask(frame)
        local first, second = frame:byte(1, 2)
        assert(second & 0x80 ~= 0, "a client frame was not masked")
        local length, mask_at = second & 0x7f, 3
        if length == 126 then
            length, mask_at = string.unpack(">I2", frame, 3)
        elseif length == 127 then
            length, mask_at = string.unpack(">I8", frame, 3)
        end
        local mask, payload = frame:sub(mask_at, mask_at + 3), {}
        for i = 1, length do
            payload[i] = string.char(frame:byte(mask_at + 3 + i) ~ mask:byte((i - 1) % 4 + 1))
        end
        assert(#frame == mask_at + 3 + length, "a client frame has trailing bytes")
        return first, table.concat(payload)
    end
    local client = websocket.new(fake)
    for _, length in ipairs({ 125, 126, 65535, 65536 }) do
        local text = string.rep("x", length)
        incoming[#incoming + 1] = server_frame(0x81, text)
        assert(client:receive(nil) == text, "a " .. length .. "-byte message was not received")
        client:send(text)
        local first, payload = unmask(sent[#sent])
        assert(first == 0x81 and payload == text, "a " .. length .. "-byte message was not sent")
    end
    incoming[#incoming + 1] = server_frame(0x01, "frag")
    incoming[#incoming + 1] = server_frame(0x89, "ping")
    incoming[#incoming + 1] = server_frame(0x80, "mented")
    assert(client:receive(nil) == "fragmented", "fragments were not reassembled around a ping")
    local first, payload = unmask(sent[#sent])
    assert(first == 0x8a and payload == "ping", "a ping was not answered with its pong")
    assert(client:receive(0) == nil, "a message that never started did not time out")
end

-- An RPC exchange reads a body given by length or in chunks, fails on a connection the node closed
-- before answering, and notices when the node will close it after answering.
do
    local function fake(response)
        local position = 1
        return {
            send = function(_, data)
                return #data
            end,
            receive = function(_, pattern)
                if position > #response then
                    return nil, "closed"
                end
                if pattern == "*l" then
                    local line_end = response:find("\r\n", position, true)
                    local line = response:sub(position, line_end - 1)
                    position = line_end + 2
                    return line
                end
                local data = response:sub(position, position + pattern - 1)
                position = position + pattern
                return data
            end,
        }
    end
    local status, data, closing =
        cast.exchange(fake('HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{"a":1}'), "node", "/", "{}")
    assert(status == 200 and data == '{"a":1}' and not closing, "a body given by length was misread")
    status, data = cast.exchange(
        fake('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{"a\r\n4\r\n":1}\r\n0\r\n\r\n'),
        "node",
        "/",
        "{}"
    )
    assert(status == 200 and data == '{"a":1}', "a chunked body was misread")
    assert(not pcall(cast.exchange, fake(""), "node", "/", "{}"), "a connection closed before answering succeeded")
    status, data, closing =
        cast.exchange(fake("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}"), "node", "/", "{}")
    assert(status == 200 and data == "{}" and closing, "a closing connection was not noticed")
end

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
    geometry = geometry,
    transactions = {},
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
    player = {},
    signer = {},
    label = "coordinator",
})
local action = coordinator:prepare({
    kind = "eliminateMatchByTimeout",
    context = { address = "tournament" },
    event = { one = "one", two = "two" },
})
assert(action.to == "tournament" and captured[1] == "eliminateMatchByTimeout")
assert(captured[2][1][1] == "one" and captured[2][1][2] == "two")

-- Scheduling uses emitted half-open block windows, including equality and
-- asymmetric leaf expiry. These expected verbs do not use contract clock math.
local one = { label = "one", player = {}, signer = { address = "alice" }, claims = { root = { root = "one" } } }
local two = { label = "two", player = {}, signer = { address = "bob" }, claims = { root = { root = "two" } } }
-- Each player has its own bridge, and each bridge also derives the cleanup jobs.
local function new_scheduler(fixture, cleanup)
    local scheduler = bridge.new({
        geometry = geometry,
        transactions = {},
        chain = {},
        abi = {},
        root = "root",
        factory = "factory",
        consensus = "consensus",
        player = fixture.player,
        signer = fixture.signer,
        label = fixture.label,
        cleanup = cleanup,
    })
    scheduler.claims = fixture.claims
    return scheduler
end
local schedulers = { new_scheduler(one), new_scheduler(two) }
local creation = { log = { blockHash = "block0", logIndex = "0x0" } }
local context = {
    address = "root",
    creation = creation,
    descriptor = { height = geometry.mcycle_height, kind = 1, startInstant = 0, allowance = 1 },
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
    head = 4,
    tip = 8,
    order = { context },
    contexts = { root = context },
    events = { event },
    matches = { ["root:match"] = event },
    deleted = {},
    recovered = {},
}
local function ready_at(block)
    local ready = {}
    for _, scheduler in ipairs(schedulers) do
        for _, job in ipairs(scheduler:jobs(snapshot)) do
            if job.first <= block and block < job.last then
                ready[#ready + 1] = job.kind .. ":" .. scheduler.label
            end
        end
    end
    return table.concat(ready, ",")
end
assert(ready_at(9) == "advanceMatch:one")
assert(ready_at(10) == "winMatchByTimeout:two")
assert(ready_at(14) == "winMatchByTimeout:two")
assert(ready_at(15) == "eliminateMatchByTimeout:one,eliminateMatchByTimeout:two")
-- A bridge created without cleanup leaves the elimination to the others.
for _, job in ipairs(new_scheduler(two, false):jobs(snapshot)) do
    assert(job.kind ~= "eliminateMatchByTimeout", "a bridge without cleanup eliminated a match")
end
event.name, event.currentHeight = "MatchAdvanced", 61
assert(ready_at(9) == "advanceMatch:two")
assert(ready_at(10) == "winMatchByTimeout:one")
event.name, event.deadlineOne, event.deadlineTwo = "LeafMatchSealed", 10, 15
assert(ready_at(9) == "winLeafMatch:one,winLeafMatch:two")
assert(ready_at(10) == "winMatchByTimeout:two")
assert(ready_at(15) == "eliminateMatchByTimeout:one,eliminateMatchByTimeout:two")
event.deadlineOne = 15
assert(ready_at(14) == "winLeafMatch:one,winLeafMatch:two")
assert(ready_at(15) == "eliminateMatchByTimeout:one,eliminateMatchByTimeout:two")
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
    geometry = geometry,
    transactions = {},
    chain = {
        head = function()
            return 3, "head", 7, "tip"
        end,
        logs = function(_, address, last_block, first_block)
            local result = {}
            for _, item in ipairs(streams[address]) do
                local number = tonumber(item.blockNumber)
                if number >= (first_block or 0) and number <= last_block then
                    result[#result + 1] = item
                end
            end
            return result
        end,
        is_canonical = function()
            return canonical == "head"
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
    player = one.player,
    signer = one.signer,
    label = one.label,
})
assert(reader:observe().contexts.root)
-- Positions order numerically, so log index 0x9 precedes 0x10.
log("root", "0x10", { name = "Unrelated" })
log("root", "0x9", { name = "Unrelated" })
reader.history:reset()
local positions = {}
for _, item in ipairs(reader:observe().logs) do
    positions[#positions + 1] = item.logIndex
end
assert(table.concat(positions, ",") == "0x0,0x1,0x9,0x10", "logs were not ordered by position")
streams.root = {}
reader.history:reset()
canonical = "replacement"
assert(not reader:observe(), "replaced head was accepted")
canonical = "head"
-- The logs of an unchanged head cannot change, so each altered stream starts a fresh history.
seal.removed = true
reader.history:reset()
assert(not reader:observe(), "removed log was accepted")
seal.removed = nil
reader.history:reset()
assert(not pcall(reader.observe, reader), "malformed log was accepted")
seal.removed = false
streams.consensus = {}
reader.history:reset()
assert(not pcall(reader.observe, reader), "missing epoch seal was accepted")
-- Acceptance waits for the staging block plus the configured delay, including equality.
for _, scheduler in ipairs(schedulers) do
    scheduler.claim_staging_period = 10
end
snapshot.staged = { log = { blockHash = "staging", blockNumber = "0x14", logIndex = "0x0" } }
assert(ready_at(29) == "")
assert(ready_at(30) == "acceptStagedTournamentResult:one,acceptStagedTournamentResult:two")
snapshot.settled = {}
assert(ready_at(30) == "")

-- InputBox and consensus logs share an ordered stream. Inputs delivered after
-- the seal cannot enter this player's epoch, and replay cannot deliver twice.
local epoch = require("prt-epoch")
local fs = require("cartesi.filesystem")
local function accumulating(policy)
    local history = { inputbox = {}, consensus = {} }
    local calls = {}
    local player = {
        event_handler = {
            input_added = function(_, index, path)
                assert(index == #calls, "input was delivered out of order or twice")
                calls[#calls + 1] = fs.read_file(path)
                calls.paths = calls.paths or {}
                calls.paths[#calls] = path
            end,
            epoch_sealed = function(_, count)
                assert(count == #calls)
                calls.sealed = true
            end,
        },
    }
    local source = cast.new("http://unused")
    source.tip = 3
    function source:rpc(method, args)
        assert(method == "eth_getBlockByNumber")
        if args[1] == "latest" then
            self.polled = true
        end
        local n = args[1] == "latest" and self.tip or tonumber(args[1])
        return { number = string.format("0x%x", n), hash = "block" .. n }
    end
    function source.logs(_, address, head, first_block)
        local result = {}
        for _, item in ipairs(history[address]) do
            local number = tonumber(item.blockNumber)
            if number >= (first_block or 0) and number <= head then
                result[#result + 1] = item
            end
        end
        return result
    end
    local session = epoch.new({
        geometry = geometry,
        transactions = {},
        chain = source,
        input_policy = policy or 0,
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
        player = player,
        signer = {},
        label = "fixture",
    })
    -- Logs appended after a poll go into a new block, as the chain only grows past an observed head.
    -- Logs appended between two polls share a block, ordered by position.
    local block = 1
    local function append(address, position, observed)
        if source.polled then
            block, source.polled = source.tip + 1, false
            source.tip = block
        end
        local item = {
            address = address,
            blockNumber = string.format("0x%x", block),
            blockHash = "block" .. block,
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
    append("inputbox", 0, input_event(3))
    assert(not session:poll() and calls[1] == "3" and not calls.sealed)
    assert(not fs.exists(calls.paths[1]), "an input file outlived its event")
    assert(not session:poll() and #calls == 1)
    append("inputbox", 1, input_event(4))
    append("inputbox", 3, input_event(5))
    append("consensus", 2, seal_event())
    assert(session:poll() and calls.sealed and #calls == 2 and calls[2] == "4")
    session:poll()
    assert(#calls == 2)
    function session.chain.is_canonical()
        return false
    end
    assert(not pcall(session.poll, session), "changed stable seal was accepted")
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
-- Depths count successors. Consensus tags use the node's block, and an
-- unavailable tag must never silently fall back to latest.
do
    local source = cast.new("http://unused")
    function source.rpc(_, method, args)
        assert(method == "eth_getBlockByNumber")
        local n = ({ latest = 40, safe = 30, finalized = 20 })[args[1]] or tonumber(args[1])
        return { number = string.format("0x%x", n), hash = "block" .. n }
    end
    local n, h, tip = source:head(4)
    assert(n == 36 and h == "block36" and tip == 40)
    assert(source:head(64) == 0)
    assert(source:head(0) == 40)
    assert(source:head("safe") == 30 and source:head("finalized") == 20)
    assert(cast.policy("12") == 12)
    for _, invalid in ipairs({ -1, 1.5, "latest", "-1", "1.5", "4foo", false }) do
        assert(not pcall(cast.policy, invalid), "invalid observation policy accepted")
    end
    local rpc = source.rpc
    function source:rpc(method, args)
        if args[1] == "safe" then
            return require("dkjson").null
        end
        return rpc(self, method, args)
    end
    assert(not pcall(source.head, source, "safe"), "missing safe block fell back to latest")
end

-- A shallow reorg can replace an unconfirmed input without touching the
-- player. Only the replacement is delivered once it has enough successors.
do
    local session, calls, append, input_event = accumulating(4)
    local pending = append("inputbox", 0, input_event(3))
    session:poll()
    assert(#calls == 0)
    pending.event.input = eth.hex("replacement")
    session.chain.tip = 4
    session:poll()
    assert(#calls == 0)
    session.chain.tip = 5
    session:poll()
    assert(#calls == 1 and calls[1] == "replacement")
    session:poll()
    assert(#calls == 1)
    pending.blockHash = "reorg"
    assert(not pcall(session.poll, session), "reorg beyond input policy was accepted")
end

-- Receipts remain distinct from confirmed completion events. A canonical
-- but unobserved receipt suppresses resending; an orphaned receipt does not.
do
    local mined = { blockNumber = "0xa", blockHash = "block10" }
    local client = bridge.new({
        geometry = geometry,
        chain = {},
        transactions = {
            receipt = function()
                return mined
            end,
        },
        abi = {},
        root = "root",
        factory = "factory",
        consensus = "consensus",
        player = {},
        signer = {},
        label = "receipts",
    })
    assert(client:awaiting_observation({ key = "work" }, { head = 8 }))
    assert(not client:awaiting_observation({ key = "work" }, { head = 10 }))
    mined = nil
    assert(not client:awaiting_observation({ key = "work" }, { head = 8 }))
end

-- Tick scheduling must not mistake a delayed observation for the current
-- inclusion block. A reverted attempt is retried on a new tip, and is not
-- permanently suppressed across replacement branches.
do
    local sends = 0
    local observed = { head = 4, hash = "block4", tip = 8, tip_hash = "block8", ready = true, order = {} }
    local signer = { address = "alice" }
    local job = {
        key = "job",
        first = 0,
        last = 10,
        kind = "test",
        context = { address = "root" },
        event = { log = { blockHash = "block4", logIndex = "0x0" } },
    }
    local source = {
        head = function()
            return observed.tip, observed.tip_hash
        end,
        is_canonical = function()
            return true
        end,
    }
    local publisher = {
        receipt = function() end,
        pending = function() end,
        submit = function()
            sends = sends + 1
            return { rejected = { code = 3, message = "fixture revert" } }
        end,
    }
    local client = bridge.new({
        geometry = geometry,
        chain = source,
        transactions = publisher,
        abi = {},
        root = "root",
        factory = "factory",
        consensus = "consensus",
        player = {},
        signer = signer,
        label = "test",
    })
    function client.observe()
        return observed
    end
    function client.jobs()
        return { job }
    end
    function client.prepare()
        return { signer = signer, to = "root", data = "0x" }
    end
    client:tick()
    client:tick()
    assert(sends == 1, "same observation resubmitted a rejected attempt")
    observed.tip_hash = "replacement8"
    client:tick()
    assert(sends == 2, "replacement branch could not retry rejected work")
    observed.tip = 9
    observed.tip_hash = "block9"
    client:tick()
    assert(sends == 2, "expired job used the delayed observation height for inclusion")
    observed.tip = 8
    observed.tip_hash = "another8"
    client.prepared = {}
    function client.prepare()
        observed.tip, observed.tip_hash = 10, "block10"
        return { signer = {}, to = "root", data = "0x" }
    end
    client:tick()
    assert(sends == 2, "work that expired during computation was submitted")
    job.first, job.last = 100000, 100010
    local _, progressed, next_block = client:tick()
    assert(not progressed and next_block == 99999, "idle interval was reduced to single-block polling")
end

-- A tick attempts the due job that expires first, whatever order the jobs were derived in.
do
    local observed = { head = 4, hash = "block4", tip = 8, tip_hash = "block8", ready = true, order = {} }
    local signer = { address = "alice" }
    local function new_job(key, last)
        return {
            key = key,
            first = 0,
            last = last,
            kind = "test",
            context = { address = "root" },
            event = { log = { blockHash = "block4", logIndex = "0x0" } },
        }
    end
    local submitted = {}
    local client = bridge.new({
        geometry = geometry,
        chain = {
            head = function()
                return observed.tip, observed.tip_hash
            end,
            is_canonical = function()
                return true
            end,
        },
        transactions = {
            receipt = function() end,
            pending = function() end,
            submit = function(_, _, request)
                submitted[#submitted + 1] = request.key
                return { rejected = { code = 3, message = "fixture revert" } }
            end,
        },
        abi = {},
        root = "root",
        factory = "factory",
        consensus = "consensus",
        player = {},
        signer = signer,
        label = "test",
    })
    function client.observe()
        return observed
    end
    function client.jobs()
        return { new_job("late", 30), new_job("open", math.maxinteger), new_job("early", 20) }
    end
    function client.prepare()
        return { signer = signer, to = "root", data = "0x" }
    end
    client:tick()
    assert(table.concat(submitted, ",") == "early", "a later-expiring job was attempted first")
end

-- The same child address can be recreated for another period. Rebind its
-- claim to the new descriptor, retain the old computation, and revalidate
-- contested final states even when returning to a previously computed period.
do
    local cartesi = require("cartesi")
    local builds = 0
    local player = { event_handler = {}, geometry = geometry }
    function player.event_handler.commit_uarch_claim(_, input_index, period_index)
        assert(input_index == 0)
        builds = builds + 1
        local state_hash = cartesi.keccak256(tostring(period_index))
        local root, siblings = state_hash, {}
        for i = 1, geometry.uarch_height do
            siblings[i] = root
            root = cartesi.keccak256(root, root)
        end
        return {
            computation_hash_left = siblings[geometry.uarch_height],
            computation_hash_right = siblings[geometry.uarch_height],
            final_state_hash_proof = {
                target_address = (1 << geometry.uarch_height) - 1,
                log2_target_size = 0,
                log2_root_size = geometry.uarch_height,
                target_hash = state_hash,
                root_hash = root,
                sibling_hashes = siblings,
            },
        }
    end
    local parent = {
        address = "root",
        creation = creation,
        descriptor = { startInstant = 0, allowance = 1 },
        joined = {},
        standing = { matchCount = 1 },
    }
    local child = {
        address = "child",
        parent = "root",
        parent_match = "root:match",
        bond = 10,
        descriptor = {
            initialHash = hash,
            baseCycle = evmu.bint(1) << geometry.uarch_height,
            height = geometry.uarch_height,
            log2Stride = 0,
            level = 1,
            kind = 0,
            startInstant = 0,
            allowance = 100,
        },
        creation = {
            one = "parent",
            two = "other",
            contestedFinalStateOne = eth.hex(cartesi.keccak256("1")),
            contestedFinalStateTwo = hash,
            log = { blockHash = "child1", logIndex = "0x0" },
        },
        joined = {},
        standing = { matchCount = 1 },
    }
    local view = {
        head = 4,
        tip = 8,
        order = { parent, child },
        contexts = { root = parent, child = child },
        events = {},
        matches = {},
        deleted = {},
        recovered = {},
    }
    local client = bridge.new({
        geometry = geometry,
        chain = {},
        abi = {
            -- This fixture exercises job derivation without publication.
            calldata = function()
                return "0x"
            end,
        },
        root = "root",
        factory = "factory",
        consensus = "consensus",
        player = player,
        signer = { address = "alice" },
        label = "replacement",
        transactions = {},
    })
    client.claims.root = { root = "parent" }
    assert(#client:jobs(view) == 0 and builds == 0 and not client.claims.child, "job query computed or bound a claim")
    client:update_claims(view)
    local original = client.claims.child
    local queries = client:jobs(view)
    assert(
        #queries == 1 and queries[1].root == original.root and builds == 1,
        "job query did not use the existing claim"
    )
    assert(builds == 1 and original.final_state == child.creation.contestedFinalStateOne)
    child.descriptor.baseCycle = evmu.bint(2) << geometry.uarch_height
    child.creation.contestedFinalStateOne = eth.hex(cartesi.keccak256("2"))
    child.creation.log.blockHash = "child2"
    child.bond = 17
    client:update_claims(view)
    local replacement = client:jobs(view)
    assert(builds == 2 and client.claims.child ~= original)
    assert(client.claims.child.final_state == child.creation.contestedFinalStateOne)
    assert(client:prepare(replacement[1]).value == "17", "replacement bond was not used")
    child.descriptor.baseCycle = evmu.bint(1) << geometry.uarch_height
    child.creation.contestedFinalStateOne = original.final_state
    child.creation.log.blockHash = "child1"
    client:update_claims(view)
    assert(builds == 2 and client.claims.child == original, "earlier child computation was lost")
    child.creation.contestedFinalStateOne = hash
    assert(not pcall(client.update_claims, client, view), "cached claim bypassed contested-state validation")
    child.creation.one, child.creation.two = "unrelated1", "unrelated2"
    client:update_claims(view)
    assert(not client.claims.child, "replacement match retained an ineligible claim association")
    child.creation.one, child.creation.contestedFinalStateOne = "parent", original.final_state
    client:update_claims(view)
    assert(builds == 2 and client.claims.child == original, "ineligible replacement erased reusable computation")

    -- Claim execution can outlive the joining window. Refresh must observe
    -- again before scheduling or deciding that pending work needs cancellation.
    child.descriptor.baseCycle = evmu.bint(3) << geometry.uarch_height
    child.creation.contestedFinalStateOne = eth.hex(cartesi.keccak256("3"))
    local observations = 0
    function client.observe()
        observations = observations + 1
        local current = {}
        for k, v in pairs(view) do
            current[k] = v
        end
        current.ready, current.tip = true, observations == 1 and 8 or 100
        return current
    end
    local refreshed = client:refresh()
    assert(observations == 2 and builds == 3 and refreshed.tip == 100)
    assert(#client:jobs(refreshed) == 0, "claim execution scheduled an expired join")
end

-- A restarted bridge binds its claims from the chain. After the joining windows close, a fresh bridge
-- binds the root and child claims its signer joined, and binds nothing for another signer's joins.
do
    local cartesi = require("cartesi")
    -- A claim whose every leaf is the same state hash.
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
    local mcycle_response = repeated_claim(cartesi.keccak256("final"), geometry.mcycle_height)
    local uarch_response = repeated_claim(cartesi.keccak256("period"), geometry.uarch_height)
    local root_claim = eth.claim(mcycle_response, geometry.mcycle_height)
    local child_claim = eth.claim(uarch_response, geometry.uarch_height)
    local function new_view(submitter)
        local parent = {
            address = "root",
            creation = creation,
            descriptor = {
                initialHash = hash,
                baseCycle = evmu.bint(0),
                height = geometry.mcycle_height,
                log2Stride = geometry.uarch_height,
                level = 0,
                kind = 1,
                startInstant = 0,
                allowance = 1,
            },
            joined = { [root_claim.root] = { submitter = submitter } },
            standing = { matchCount = 1 },
        }
        local child = {
            address = "child",
            parent = "root",
            parent_match = "root:match",
            descriptor = {
                initialHash = hash,
                baseCycle = evmu.bint(1) << geometry.uarch_height,
                height = geometry.uarch_height,
                log2Stride = 0,
                level = 1,
                kind = 0,
                startInstant = 0,
                allowance = 1,
            },
            creation = {
                one = root_claim.root,
                two = "other",
                contestedFinalStateOne = child_claim.final_state,
                contestedFinalStateTwo = hash,
                log = { blockHash = "child1", logIndex = "0x0" },
            },
            joined = { [child_claim.root] = { submitter = submitter } },
            standing = { matchCount = 1 },
        }
        return {
            head = 100,
            tip = 200,
            order = { parent, child },
            contexts = { root = parent, child = child },
            events = {},
            matches = {},
            deleted = {},
            recovered = {},
        }
    end
    local function new_client()
        local player = { event_handler = {} }
        function player.event_handler.commit_mcycle_claim()
            return mcycle_response
        end
        function player.event_handler.commit_uarch_claim()
            return uarch_response
        end
        return bridge.new({
            geometry = geometry,
            chain = {},
            abi = {},
            root = "root",
            factory = "factory",
            consensus = "consensus",
            player = player,
            signer = { address = "alice" },
            label = "restarted",
            transactions = {},
        })
    end
    local client = new_client()
    client:update_claims(new_view("alice"))
    assert(client.claims.root and client.claims.root.root == root_claim.root, "a restart lost the root claim it joined")
    assert(
        client.claims.child and client.claims.child.root == child_claim.root,
        "a restart lost the child claim it joined"
    )
    local other = new_client()
    other:update_claims(new_view("bob"))
    assert(not other.claims.root and not other.claims.child, "another signer's join bound a claim")
end

-- Pending actions are revalidated on every observation, including when no new
-- action can be prepared. A failed replacement cannot strand obsolete work.
do
    local signer = { address = "alice" }
    local observed = { head = 4, hash = "block4", tip = 8, tip_hash = "block8", ready = true, order = {} }
    local pending = { job = "live" }
    local calls = {}
    local jobs = {}
    local publisher = {
        receipt = function() end,
        pending = function(_, address)
            return address == "alice" and pending or nil
        end,
        submit = function(_, _, intent)
            calls[#calls + 1] = intent and intent.key or "cancel"
            if not intent then
                return { published = true }
            end
            if intent.key == "live" then
                return { waiting = true }
            end
            return { rejected = { code = 3, message = "replacement is already done at the live tip" } }
        end,
    }
    local client = bridge.new({
        geometry = geometry,
        chain = {
            head = function()
                return observed.tip, observed.tip_hash
            end,
            is_canonical = function()
                return true
            end,
        },
        transactions = publisher,
        abi = {},
        root = "root",
        factory = "factory",
        consensus = "consensus",
        player = {},
        signer = signer,
        label = "pending",
    })
    function client.observe()
        return observed
    end
    function client.jobs()
        return jobs
    end
    function client.prepare()
        return { signer = signer, to = "root", data = "0x" }
    end
    local function job(key)
        return {
            key = key,
            kind = key,
            first = 0,
            last = 10,
            context = { address = "root" },
            event = { log = { blockHash = "block4", logIndex = "0x0" } },
        }
    end
    jobs = { job("other"), job("live") }
    client:tick()
    assert(table.concat(calls, ",") == "live", "pending work oscillated between eligible jobs")
    jobs = { job("other") }
    client:tick()
    assert(calls[#calls] == "other")
    client:tick()
    assert(calls[#calls] == "cancel", "failed replacement stranded obsolete work")
    calls = {}
    jobs = { job("live") }
    jobs[1].last = 9
    client:tick()
    assert(table.concat(calls, ",") == "cancel", "expired pending work was not canceled")

    -- A waiting attempt can discover a new head. Do not apply cancellation
    -- decisions made before that observation to its replacement branch.
    calls = {}
    jobs = { job("other") }
    function client.prepare()
        observed = { head = 5, hash = "block5", tip = 9, tip_hash = "block9", ready = true, order = {} }
        return { signer = signer, to = "root", data = "0x" }
    end
    client.prepared, client.rejected = {}, {}
    function publisher.submit(_, _, intent)
        calls[#calls + 1] = intent and intent.key or "cancel"
        return { waiting = true }
    end
    jobs[1].last = 20
    client:tick()
    assert(table.concat(calls, ",") == "other", "head change reused obsolete cancellation decisions")
end

print("PRT bridge encoding, scheduling, input streaming, and process-boundary tests passed.")
