-- The parts of the PRT game that do not depend on what is being disputed: the claim trees
-- (Merkle trees over runs of repeated nodes, refined on demand), the match walk, the referee's
-- coroutine dispatcher, the referee server that carries the wire protocol, and the
-- narration. The game script supplies the machines, the claim builds, the tournament,
-- and the verification of the disputed transition.

local cartesi = require("cartesi")
local socket = require("socket")

local keccak = cartesi.keccak256

--------------------------------------------------------------------------------
-- Small utilities
--------------------------------------------------------------------------------

-- With PRT_GAME_TRACE set, every wire message is dumped to stderr, unbuffered so it survives
-- a redirect. The referee runs with it off so its narration stays clean, and an empty player
-- transcript confirms a clean run.
io.stderr:setvbuf("no")
local tracing = os.getenv("PRT_GAME_TRACE") ~= nil
local function trace_wire(direction, name, line)
    if tracing then
        io.stderr:write(string.format("%s %s: %s\n", direction, name or "?", line))
    end
end

-- A hash is shown by its first four bytes.
local function format_short_hash(hash)
    return cartesi.tohex(hash):sub(1, 10) .. "..."
end

--------------------------------------------------------------------------------
-- Narration
--
-- The referee narrates the tournament into tagged files, one per story tag (the claims, the
-- tournament, each match, the verdict), so the rendered walkthrough can print one story
-- whole and reduce another to its first and last few lines. Matches run concurrently, so
-- several files are open at once. Every line echoes to stdout, so a live run still reads as
-- one interleaved story.
--------------------------------------------------------------------------------

local narration_files = {}
local function narrate(tag, fmt, ...)
    local line = string.format(fmt, ...)
    local file = narration_files[tag]
    if not file then
        file = assert(io.open(tag, "w"))
        file:setvbuf("line")
        narration_files[tag] = file
    end
    file:write(line, "\n")
    io.stdout:write(line, "\n")
end

--------------------------------------------------------------------------------
-- Claim trees
--
-- A claim commits to 2^height leaves, the state hashes of a computation hash, but almost
-- all of them are repetitions: a machine that stopped advancing repeats its state hash to
-- the end of its span. The tree therefore stores runs, each a node hash and how many
-- consecutive times it appears. The stored nodes can sit above the leaves, at entry_height,
-- when the machine delivers them bundled. A query that descends below a stored entry is
-- answered by refine(tree, entry_index), which recovers the leaf runs under that one entry
-- (by re-running a machine through it) and caches them. Nothing else of the tree is ever
-- materialized.
--------------------------------------------------------------------------------

-- Appends a run, merging with the previous one when the hash repeats.
local function push_run(runs, hash, count)
    if count == 0 then
        return
    end
    local last = runs[#runs]
    if last and last.hash == hash then
        last.count = last.count + count
    else
        runs[#runs + 1] = { hash = hash, count = count }
    end
end

-- Extracts the sub-range [first, first+count) of a runs array.
local function slice_runs(runs, first, count)
    local slice = {}
    local skipped = 0
    for _, run in ipairs(runs) do
        local from = skipped
        skipped = skipped + run.count
        local lo = math.max(from, first)
        local hi = math.min(skipped, first + count)
        if lo < hi then
            push_run(slice, run.hash, hi - lo)
        end
    end
    return slice
end

-- Freezes a runs array, computing the cumulative counts binary search needs.
local function seal_runs(runs)
    local cum = {}
    local total = 0
    for i, run in ipairs(runs) do
        total = total + run.count
        cum[i] = total
    end
    runs.cum = cum
    runs.total = total
    return runs
end

-- The first run covering entry index (0-based). Counts compare as unsigned, since the
-- tallest trees hold more entries than a signed integer.
local function find_run(runs, index)
    local lo, hi = 1, #runs
    while lo < hi do
        local mid = (lo + hi) >> 1
        if math.ult(index, runs.cum[mid]) then
            hi = mid
        else
            lo = mid + 1
        end
    end
    return lo
end

-- The root of the complete subtree holding 2^k copies of hash, by repeated squaring, cached
-- per hash. This is what makes repetitions free: a run of any length costs one hash chain.
local function compute_repeated_root(tree, hash, k)
    local chain = tree.iterated[hash]
    if not chain then
        chain = { [0] = hash }
        tree.iterated[hash] = chain
    end
    for i = #chain + 1, k do
        chain[i] = keccak(chain[i - 1], chain[i - 1])
    end
    return chain[k]
end

-- The node at height h, index q, over a runs array whose entries sit at entry_height.
-- A range covered by a single run is an iterated hash, anything else splits in two.
-- docs:begin get_runs_node
local function get_runs_node(tree, runs, entry_height, h, q)
    local first = q << (h - entry_height)
    local count = 1 << (h - entry_height)
    local i = find_run(runs, first)
    if not math.ult(runs.cum[i] - 1, first + count - 1) then -- a single run covers the range
        return compute_repeated_root(tree, runs[i].hash, h - entry_height)
    end
    return keccak(
        get_runs_node(tree, runs, entry_height, h - 1, 2 * q),
        get_runs_node(tree, runs, entry_height, h - 1, 2 * q + 1)
    )
end
-- docs:end get_runs_node

local tree_meta = { __index = {} }

-- The node at height h, index q. At or above entry_height it resolves over the stored runs.
-- Below, it locates the one stored entry standing over the node and queries the leaf runs
-- recovered by refine, so only the entries a dispute actually visits are ever expanded.
-- docs:begin get_tree_node
function tree_meta.__index.get_node(tree, h, q)
    if h >= tree.entry_height then
        return get_runs_node(tree, tree.runs, tree.entry_height, h, q)
    end
    local entry = q >> (tree.entry_height - h)
    local leaf_runs = tree.refined[entry]
    if not leaf_runs then
        leaf_runs = seal_runs(tree:refine(entry))
        assert(leaf_runs.total == 1 << tree.entry_height, "refine did not produce a full entry")
        tree.refined[entry] = leaf_runs
    end
    return get_runs_node(tree, leaf_runs, 0, h, q - (entry << (tree.entry_height - h)))
end
-- docs:end get_tree_node

function tree_meta.__index.get_root(tree)
    return tree:get_node(tree.height, 0)
end

-- The two children of the node at height h, index q.
function tree_meta.__index.get_children(tree, h, q)
    return tree:get_node(h - 1, 2 * q), tree:get_node(h - 1, 2 * q + 1)
end

-- The proof of a leaf index, in the standard cartesi.hash-tree representation. Claim-tree
-- addresses are logical leaf indices, so their target size is zero and their root size is the
-- tree height.
function tree_meta.__index.prove(tree, index)
    local siblings = {}
    for level = 0, tree.height - 1 do
        siblings[level + 1] = tree:get_node(level, (index >> level) ~ 1)
    end
    return {
        target_address = index,
        log2_target_size = 0,
        target_hash = tree:get_node(0, index),
        log2_root_size = tree.height,
        root_hash = tree:get_root(),
        sibling_hashes = siblings,
    }
end

-- A claim tree of 2^height leaves, stored as runs of nodes at entry_height, with
-- refine(tree, entry_index) recovering the leaf runs under one entry on demand.
local function new_tree(height, entry_height, runs, refine)
    return setmetatable({
        height = height,
        entry_height = entry_height,
        runs = seal_runs(runs),
        refine = refine,
        refined = {},
        iterated = {},
    }, tree_meta)
end

--------------------------------------------------------------------------------
-- Match walk
--
-- A match walks two claim trees down to the leaf where they first diverge, the two claims
-- alternating, one move per round, exactly as in Dave's Match.sol. The referee holds one node
-- to open (`other_parent`) and the opponent's standing left and right children. The on-turn
-- claim opens its node, exposing the two children and, above the leaves, the two grandchildren
-- of the side the walk descends into. The walk follows the side where the claims first
-- disagree, converging on the leftmost divergent leaf, and the turn passes to the opponent each
-- round. Nothing here touches the wire: the functions are pure over the match state and the
-- move, so the walk can be checked on synthetic trees.
--------------------------------------------------------------------------------

-- Seeds a match over two claims of the given tree height. Claim one opens first, so the walk
-- starts with claim1's computation hash as the node to open and claim2's join-exposed children standing.
-- docs:begin new_match
local function new_match(claim1, claim2, height)
    return {
        claim1 = claim1,
        claim2 = claim2,
        turn_claim = claim1, -- the claim whose node is other_parent
        other_claim = claim2,
        other_parent = claim1.computation_hash,
        left_node = claim2.left,
        right_node = claim2.right,
        height = height,
        index = 0,
    }
end
-- docs:end new_match

-- Checks a move against the match state: the children must join into the node to open, and,
-- above the leaves, the grandchildren must join into the child the walk descends into.
-- docs:begin is_valid_move
local function is_valid_move(match, move)
    if keccak(move.l, move.r) ~= match.other_parent then
        return false
    end
    if match.height > 1 then
        return keccak(move.nl, move.nr) == ((move.l ~= match.left_node) and move.l or move.r)
    end
    return true
end
-- docs:end is_valid_move

-- Applies a valid move. Above the leaves, the walk descends one height: the on-turn claim's
-- chosen grandchildren become the standing left and right, the opponent's node on the chosen
-- side becomes the next to open, and the turn passes. At height 1 the exposed children are
-- leaves, and the walk is over: it returns the isolated dispute, the divergent leaf's index,
-- what each claim committed to there, and, when the
-- divergence is at a right leaf, the agreed state before it, the left leaf both sides exposed.
-- docs:begin advance_match
local function advance_match(match, move)
    local descend_left = move.l ~= match.left_node
    if match.height == 1 then
        local state_index, turn_state_hash, other_state_hash, agreed_state_hash
        if descend_left then
            state_index, turn_state_hash, other_state_hash = 2 * match.index, move.l, match.left_node
        else
            state_index, turn_state_hash, other_state_hash, agreed_state_hash =
                2 * match.index + 1, move.r, match.right_node, move.l
        end
        local claim1_next_state_hash = match.turn_claim == match.claim1 and turn_state_hash or other_state_hash
        local claim2_next_state_hash = match.turn_claim == match.claim1 and other_state_hash or turn_state_hash
        return {
            state_index = state_index,
            agreed_state_hash = agreed_state_hash,
            claim1_next_state_hash = claim1_next_state_hash,
            claim2_next_state_hash = claim2_next_state_hash,
        }
    end
    if descend_left then
        match.other_parent, match.index = match.left_node, 2 * match.index
    else
        match.other_parent, match.index = match.right_node, 2 * match.index + 1
    end
    match.left_node, match.right_node = move.nl, move.nr
    match.height = match.height - 1
    match.turn_claim, match.other_claim = match.other_claim, match.turn_claim
    return nil
end
-- docs:end advance_match

--------------------------------------------------------------------------------
-- Coroutine dispatcher
--
-- The referee mediates several matches at once, each written as ordinary sequential code
-- inside its own coroutine. A coroutine that must wait (for a socket or an answer) yields to
-- the dispatcher, which resumes whichever coroutine's event arrives first. There are no
-- deadlines: the referee waits on connections, never on the clock.
--------------------------------------------------------------------------------

local dispatcher_meta = { __index = {} }

local function new_dispatcher()
    return setmetatable({
        readable = { socks = {}, cortn = {} },
        writable = { socks = {}, cortn = {} },
        ready = {},
        ready_first = 1,
        ready_last = 0,
    }, dispatcher_meta)
end

-- Schedules a coroutine to be resumed with the given value.
function dispatcher_meta.__index.schedule(self, cortn, value)
    self.ready_last = self.ready_last + 1
    self.ready[self.ready_last] = { cortn, value }
end

function dispatcher_meta.__index.spawn(self, f)
    self:schedule(coroutine.create(f), "start")
end

local function wait_on(list, sock)
    assert(not list.cortn[sock], "one waiter per socket")
    list.socks[#list.socks + 1] = sock
    list.cortn[sock] = coroutine.running()
    return coroutine.yield()
end

function dispatcher_meta.__index.wake_when_readable(self, sock)
    return wait_on(self.readable, sock)
end

function dispatcher_meta.__index.wake_when_writable(self, sock)
    return wait_on(self.writable, sock)
end

-- Suspends the running coroutine until it is scheduled, returning the value it was scheduled
-- with.
function dispatcher_meta.__index.wake_when_scheduled()
    return coroutine.yield()
end

local function wake_ready(self, list, ready_socks)
    for _, sock in ipairs(ready_socks) do
        local cortn = list.cortn[sock]
        list.cortn[sock] = nil
        for i, s in ipairs(list.socks) do
            if s == sock then
                table.remove(list.socks, i)
                break
            end
        end
        self:schedule(cortn, "io")
    end
end

-- One dispatcher step: waits for the first socket event or scheduled coroutine, then resumes
-- everyone it concerns. A coroutine scheduled while the step runs waits for the next step, so
-- sockets are polled between any two resumptions of the same coroutine. Errors inside a
-- coroutine are fatal: the referee has no business surviving its own bugs.
function dispatcher_meta.__index.step(self)
    local timeout
    if self.ready_first <= self.ready_last then
        timeout = 0
    end
    assert(timeout or #self.readable.socks > 0 or #self.writable.socks > 0, "would block forever")
    local readable, writable = socket.select(self.readable.socks, self.writable.socks, timeout)
    wake_ready(self, self.readable, readable)
    wake_ready(self, self.writable, writable)
    local last = self.ready_last
    while self.ready_first <= last do
        local turn = self.ready[self.ready_first]
        self.ready[self.ready_first] = nil
        self.ready_first = self.ready_first + 1
        if coroutine.status(turn[1]) == "suspended" then
            local ok, err = coroutine.resume(turn[1], turn[2])
            if not ok then
                error(debug.traceback(turn[1], err))
            end
        end
    end
end

--------------------------------------------------------------------------------
-- Wire protocol
--
-- Each message is one line, the compact JSON of a Lua value by cartesi.tojson plus a
-- newline. The referee sends requests {operation, arguments}, encoding the arguments under
-- the operation's request schema. A player dispatches the operation against its own state and
-- answers {label, value}, encoded under the operation's response schema, so binary hashes,
-- proofs, and access logs survive both directions. Schema names are local metadata, not wire
-- fields.
-- The valid move for an operation is unique, fixed by the claim's committed tree, so a claim
-- cannot be misrepresented and it never matters who sends a move: the referee takes the first
-- move that proves itself and ignores the rest. The label rides along only for tracing.
--------------------------------------------------------------------------------

-- The schemas shared by every request. The game script adds its operation schemas.
local SCHEMA_DICT = {
    SealRequest = { items = {} },
    SealResponse = "Default",
}

-- Describes one request once, for both ends of the wire. Referee calls pass the request
-- followed by ordinary positional arguments; the request supplies the operation name and
-- the schemas used to encode its argument tuple and decode its response.
local function define_request(name, request_schema, response_schema)
    return { name = name, request_schema = request_schema, response_schema = response_schema }
end

local SEAL = define_request("seal", "SealRequest", "SealResponse")

-- The envelope schema for requests under a named argument schema, registered on first use.
local function ensure_request_envelope_schema(schema)
    if not schema then
        return nil
    end
    local name = schema .. "Envelope"
    if not SCHEMA_DICT[name] then
        SCHEMA_DICT[name] = { arguments = schema }
    end
    return name
end

-- The envelope schema for responses under a named value schema, registered on first use, so
-- both sides encode {label, value} with the value's binary fields transformed.
local function ensure_response_envelope_schema(schema)
    if not schema then
        return nil
    end
    local name = schema .. "Envelope"
    if not SCHEMA_DICT[name] then
        SCHEMA_DICT[name] = { value = schema }
    end
    return name
end

-- Sends one line over a connection owned by the dispatcher, yielding while the socket is
-- not ready.
local function send_line(dispatcher, connection, line)
    local first = 1
    while true do
        local reason = dispatcher:wake_when_writable(connection.sock)
        assert(reason == "io", "unexpected wake while sending")
        local sent, err, partial = connection.sock:send(line, first)
        if sent then
            return true
        elseif err == "timeout" then
            first = partial + 1
        else
            return nil, err
        end
    end
end

-- Receives one line over a connection owned by the dispatcher, yielding while bytes are
-- missing. Returns nil when the connection closes.
local function receive_line(dispatcher, connection)
    while true do
        local reason = dispatcher:wake_when_readable(connection.sock)
        assert(reason == "io", "unexpected wake while receiving")
        local line, err, partial = connection.sock:receive("*l", connection.partial)
        if line then
            connection.partial = nil
            return line
        elseif err == "timeout" then
            connection.partial = partial
        else
            return nil, err
        end
    end
end

--------------------------------------------------------------------------------
-- Players
--------------------------------------------------------------------------------

-- The player side is a plain blocking loop: announce itself, then read a request, decode its
-- arguments under the operation's request schema, dispatch the operation, and answer with its
-- value under the response schema. The label is only for tracing. Every request is routed to a
-- holder of the claim it is about, so a missing operation or result is a bug in the player, and
-- the process dies with it: the
-- referee sees the connection close, and the claim loses its holder. The loop also ends when
-- the game releases the player, or when the referee goes away.
-- docs:begin serve
local function serve(player, server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    player.connection = assert(socket.connect(host, tonumber(port)))
    local hello = player.hello or cartesi.tojson({ role = "player", label = player.label }, -1)
    assert(player.connection:send(hello .. "\n"))
    repeat
        local line = player.connection:receive("*l")
        if not line then
            break
        end
        trace_wire("from referee", player.label, line)
        local envelope = cartesi.fromjson(line)
        local request = assert(player.requests[envelope.operation], "unknown operation")
        local wire_request = cartesi.fromjson(line, ensure_request_envelope_schema(request.request_schema), SCHEMA_DICT)
        local handler = assert(player[wire_request.operation], "missing operation")
        local value = handler(player, table.unpack(wire_request.arguments or {}))
        assert(value ~= nil, "the operation produced no value")
        local response = { label = player.label, value = value }
        local encoded =
            cartesi.tojson(response, -1, ensure_response_envelope_schema(request.response_schema), SCHEMA_DICT)
        trace_wire("to referee", player.label, encoded)
        assert(player.connection:send(encoded .. "\n"))
    until player.done
    player.connection:close()
end
-- docs:end serve

-- The sealer is a player with one operation: closing the next phase. It announces itself as
-- the sealer on connecting, and the referee first asks it to close initial subscriptions, then
-- to close every tournament's claim collection by the same lifecycle at both levels.
local function new_sealer()
    local sealer = {
        label = "sealer",
        hello = cartesi.tojson({ role = "sealer" }, -1),
        requests = { seal = SEAL },
        seal = function()
            return true
        end,
    }
    return sealer
end

--------------------------------------------------------------------------------
-- Referee server
--
-- Every player connects to the referee server, which is the single event loop. Connections
-- arriving during the initial subscription phase subscribe to its initial hash. A tournament
-- then opens with a fixed audience, the connections asked for a claim, and its claim collection
-- closes once the sealer seals it and every connection in the audience has answered
-- or closed. A move request asks the holders of a claim, and takes the first reply that proves
-- itself. A reply that fails to prove itself, or does not even decode under the operation's
-- schema, is rejected, as the blockchain rejects a bad transaction, and counts as that
-- connection's answer. Only a line that cannot be decoded enough to identify a message, or a
-- closed socket, ends a connection. A claim whose every holder answered without proof, or closed, is
-- eliminated at once. Nothing depends on the clock, and nothing depends on the order replies
-- arrive in, so the outcome is a pure function of the claims.
--
-- Claim operations authenticate themselves by proof. Sealing does not: it is the referee's
-- trusted orchestration, standing in for the clock the contracts use, and the transport
-- enforces that trust. A connection announces its role once, on its first line, and a
-- second announcement closes it. The sealer is whichever connection first announced itself
-- as such, a seal request is bound to that connection, and its next reply seals the one
-- tournament currently assigned to it. The model therefore assumes a process announces its role
-- honestly. A sealer that goes away fails the referee outright, since no tournament could
-- ever close again.
--------------------------------------------------------------------------------

local server_meta = { __index = {} }
local accept_connections

local function new_server(address)
    local host, port = address:match("^(.-):(%d+)$")
    assert(host and port, "invalid server address")
    local server = setmetatable({
        dispatcher = new_dispatcher(),
        listener = assert(socket.bind(host, tonumber(port))),
        connections = {},
        subscriptions = {}, -- routing hash -> set of connections interested in defending it
        active = {}, -- set of requests whose coroutines are waiting
        open_phases = {}, -- subscription and tournament phases in creation order
        seal_queue = {}, -- phases waiting for the sealer, in creation order
        seal_active = nil, -- the one phase currently being sent to the sealer
        sealer = nil, -- the sealer's connection, once it announces itself
        done = false,
    }, server_meta)
    accept_connections(server)
    return server
end

-- Queues a line on a connection and wakes its writer.
local function enqueue(self, connection, line)
    if connection.dead then
        return
    end
    connection.outbox[#connection.outbox + 1] = line
    if connection.parked_writer then
        local writer = connection.parked_writer
        connection.parked_writer = nil
        self.dispatcher:schedule(writer, "work")
    end
end

-- Resolves the request globally and hands the result to its coroutine. Individual connections
-- may still be unanswered and owe replies; send_request accounts for each such reply before
-- assigning that connection new work.
local function resolve(self, entry, result)
    entry.resolved = true
    self.active[entry] = nil
    if entry.cortn then
        self.dispatcher:schedule(entry.cortn, result)
    end
end

-- Re-examines a request after a reply, a closed connection, or a seal. A move request
-- resolves as soon as it has taken a valid value, and otherwise once every connection asked
-- has answered or closed, with nothing. A collection stays active while a connection is
-- still to answer, and a tournament's claim collection also until the seal, then resolves with
-- the replies gathered.
local function settle(self, entry)
    if not self.active[entry] then
        return
    end
    if entry.kind == "accept_first" then
        if entry.value ~= nil or not next(entry.pending) then
            resolve(self, entry, { value = entry.value })
        end
    elseif not entry.open and not next(entry.pending) then
        resolve(self, entry, { replies = entry.replies })
    end
end

-- Closes and forgets a subscription or tournament phase once its trusted seal arrives.
local function close_phase(self, phase)
    phase.open = false
    for index, open_phase in ipairs(self.open_phases) do
        if open_phase == phase then
            table.remove(self.open_phases, index)
            settle(self, phase)
            return
        end
    end
    error("sealed phase was not open")
end

-- Drops a connection from every request waiting on it, settling those it was the last of.
local function forget_connection(self, connection)
    for entry in pairs(self.active) do
        if entry.pending[connection] then
            entry.pending[connection] = nil
            settle(self, entry)
        end
    end
end

-- Closes a connection (its socket closed, or it sent a line the referee cannot decode). A dead
-- connection is skipped by every notify and holder lookup thereafter.
local function close_connection(self, connection)
    if not connection.dead then
        connection.dead = true
        connection.sock:close()
        forget_connection(self, connection)
        assert(connection ~= self.sealer, "the sealer went away, no tournament can close again")
    end
end

-- Encodes a request and its positional Lua arguments under its request schema.
local function encode_request(request, arguments)
    local wire_request = { operation = request.name, arguments = arguments }
    return cartesi.tojson(wire_request, -1, ensure_request_envelope_schema(request.request_schema), SCHEMA_DICT) .. "\n"
end

-- Sends one request at a time over a connection. The referee preserves this invariant because
-- each process follows one claim lineage, each claim enters only one match in a round, and a
-- parent match is suspended during its uarch tournament. If another connection resolved the
-- previous request first, its reply is now stale; count it before replacing the current request.
-- TCP preserves reply order, so the reader can discard exactly that many replies before
-- accepting the reply to the new request. A player served by serve() answers every request or
-- closes; an arbitrary silent peer can stall this demonstration.
local function send_request(self, connection, entry, line)
    if connection.dead then
        return
    end
    if connection.current_request then
        assert(connection.current_request.resolved, "a connection was assigned concurrent requests")
        connection.stale_requests_pending = connection.stale_requests_pending + 1
    end
    connection.current_request = entry
    enqueue(self, connection, line)
end

local request_next_seal

-- Queues a phase for the trusted sealer. The sealer is deliberately serialized like a
-- player: one request is in flight, and its next reply necessarily belongs to that request.
local function request_seal(self, phase)
    if not self.sealer or phase.seal_requested then
        return
    end
    phase.seal_requested = true
    self.seal_queue[#self.seal_queue + 1] = phase
    request_next_seal(self)
end

request_next_seal = function(self)
    if self.seal_active or not self.sealer or #self.seal_queue == 0 then
        return
    end
    local phase = table.remove(self.seal_queue, 1)
    local entry = {
        kind = "seal",
        phase = phase,
        response_schema = "SealResponse",
        pending = { [self.sealer] = true },
    }
    self.seal_active = entry
    send_request(self, self.sealer, entry, encode_request(SEAL, {}))
end

-- Files the next reply from a connection on its current request. A value that does not decode
-- under the operation's response schema is an
-- invalid operation, not a malformed connection: it counts as the connection's answer, is
-- rejected, and leaves the connection open, exactly like a value the acceptor rejects, so
-- the order replies arrive in cannot decide which connections stay open. A move request
-- takes the first truthy result its acceptor returns. A collection keeps every reply that
-- decodes. A successful seal response from the sealer closes the one phase assigned to
-- it; an invalid response is a failure of the referee's own orchestration.
local function deliver(self, entry, connection, line)
    if not entry.pending[connection] then
        return
    end
    entry.pending[connection] = nil
    local ok, decoded =
        pcall(cartesi.fromjson, line, ensure_response_envelope_schema(entry.response_schema), SCHEMA_DICT)
    if entry.kind == "seal" then
        assert(ok and decoded.value == true, "the sealer did not close the phase asked")
        entry.resolved = true
        self.seal_active = nil
        close_phase(self, entry.phase)
        request_next_seal(self)
        return
    end
    if ok and entry.kind == "collect" then
        entry.replies[#entry.replies + 1] = { value = decoded.value, label = decoded.label, connection = connection }
    elseif ok and entry.value == nil then
        local succeeded, value = pcall(entry.accept, decoded.value)
        if succeeded and value then
            entry.value = value
        end
    end
    settle(self, entry)
end

-- A connection announced itself as the sealer. There is one sealer, the first to announce,
-- and it is never part of a tournament's audience. Every phase already open, still waiting
-- for its seal, is queued in creation order.
local function announce_sealer(self, connection)
    if self.sealer then
        close_connection(self, connection)
        return
    end
    connection.is_sealer = true
    self.sealer = connection
    for _, entry in ipairs(self.open_phases) do
        if entry.open then
            request_seal(self, entry)
        end
    end
end

-- A connection announced itself as a player. While the initial subscription phase is open,
-- connecting subscribes it to the initial hash that phase advertises.
local function announce_player(self, connection)
    connection.is_player = true
    for _, entry in ipairs(self.open_phases) do
        if entry.subscription_hash and entry.open then
            self:subscribe(entry.subscription_hash, connection)
        end
    end
end

-- The first line of a connection announces its role, once. A connection that announces again,
-- or sends anything else before announcing, is closed.
local function announce(self, connection, message)
    if connection.is_player or connection.is_sealer then
        close_connection(self, connection)
    elseif message.role == "sealer" then
        announce_sealer(self, connection)
    elseif message.role == "player" then
        announce_player(self, connection)
    else
        close_connection(self, connection)
    end
end

-- Adopts a new connection: spawns its writer, which drains the outbox, and its reader, which
-- assigns replies to requests in TCP order. Replies left behind when another player resolved
-- a request are discarded by count before the current reply is delivered. The first line a
-- connection sends announces what it is, a player or the sealer.
function server_meta.__index.adopt(self, sock)
    sock:settimeout(0)
    local connection = { sock = sock, outbox = {}, stale_requests_pending = 0 }
    self.connections[#self.connections + 1] = connection
    self.dispatcher:spawn(function()
        while true do
            local line = table.remove(connection.outbox, 1)
            if line then
                if not send_line(self.dispatcher, connection, line) then
                    close_connection(self, connection)
                    return
                end
            else
                connection.parked_writer = coroutine.running()
                coroutine.yield()
            end
        end
    end)
    self.dispatcher:spawn(function()
        while true do
            local line = receive_line(self.dispatcher, connection)
            if not line then
                close_connection(self, connection)
                return
            end
            trace_wire("from player", nil, line)
            local ok, message = pcall(cartesi.fromjson, line)
            if not ok or type(message) ~= "table" then
                close_connection(self, connection)
                return
            end
            local announced = connection.is_player or connection.is_sealer
            if connection.stale_requests_pending > 0 and announced then
                connection.stale_requests_pending = connection.stale_requests_pending - 1
            else
                if message.role or not announced then
                    announce(self, connection, message)
                else
                    local entry = connection.current_request
                    connection.current_request = nil
                    if entry and not entry.resolved then
                        deliver(self, entry, connection, line)
                    end
                end
            end
            if connection.dead then
                return
            end
        end
    end)
    return connection
end

-- Accepts connections, adopting each as it arrives, until the game ends. The referee is never
-- told how many players to expect: it takes every one that connects until the sealer closes
-- the initial subscription phase.
accept_connections = function(self)
    self.listener:settimeout(0)
    self.dispatcher:spawn(function()
        while not self.done do
            local reason = self.dispatcher:wake_when_readable(self.listener)
            assert(reason == "io", "unexpected wake while accepting")
            local sock = assert(self.listener:accept())
            self:adopt(sock)
        end
    end)
end

-- Subscribes a connection to requests routed by a state or computation hash.
function server_meta.__index.subscribe(self, root, connection)
    local set = self.subscriptions[root]
    if not set then
        set = {}
        self.subscriptions[root] = set
    end
    set[connection] = true
end

-- The live connections subscribed to any of the given routing hashes.
function server_meta.__index.get_subscribers(self, roots)
    local seen, list = {}, {}
    for _, root in ipairs(roots) do
        local set = self.subscriptions[root]
        if set then
            for connection in pairs(set) do
                if not connection.dead and not seen[connection] then
                    seen[connection] = true
                    list[#list + 1] = connection
                end
            end
        end
    end
    return list
end

-- Every live player connection.
function server_meta.__index.get_players(self)
    local list = {}
    for _, connection in ipairs(self.connections) do
        if not connection.dead and connection.is_player then
            list[#list + 1] = connection
        end
    end
    return list
end

-- Starts a request on the given connections. The set asked is frozen here, and a connection
-- already closed is not in it.
local function park(self, entry, conns, line)
    entry.cortn = coroutine.running()
    entry.pending = {}
    entry.line = line
    self.active[entry] = true
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
            send_request(self, connection, entry, line)
        end
    end
end

-- Suspends the running coroutine until its request resolves.
local function wait(self, entry)
    settle(self, entry)
    return coroutine.yield()
end

-- Asks the given connections for a move and returns the first truthy value produced by
-- `accept`, or nil once every connection asked has answered without one or closed.
-- A claim nobody answers for is thereby eliminated at once.
-- docs:begin accept_first
function server_meta.__index.accept_first(self, conns, accept, request, ...)
    local entry = { kind = "accept_first", response_schema = request.response_schema, accept = accept }
    park(self, entry, conns, encode_request(request, { ... }))
    return wait(self, entry).value
end
-- docs:end accept_first

-- Asks the given connections (every player, when nil) for a value, and returns the replies,
-- each with the label and connection that sent it, once every connection asked has replied or
-- closed.
function server_meta.__index.collect(self, conns, request, ...)
    local entry = { kind = "collect", response_schema = request.response_schema, replies = {}, open = false }
    park(self, entry, conns or self:get_players(), encode_request(request, { ... }))
    return wait(self, entry).replies
end

-- Accepts players subscribing to an initial hash until the sealer closes the phase. A player
-- connection itself expresses interest in the one computation served by this referee.
function server_meta.__index.accept_subscribers(self, initial_state_hash)
    local entry = {
        kind = "collect",
        replies = {},
        pending = {},
        open = true,
        subscription_hash = initial_state_hash,
        cortn = coroutine.running(),
    }
    self.active[entry] = true
    self.open_phases[#self.open_phases + 1] = entry
    for _, connection in ipairs(self:get_players()) do
        self:subscribe(initial_state_hash, connection)
    end
    request_seal(self, entry)
    wait(self, entry)
end

-- Collects claims from a fixed audience. This transport primitive hides how the demonstration
-- decides that claim collection is over.
-- docs:begin collect_claims
function server_meta.__index.collect_claims(self, conns, request, ...)
    local entry = {
        kind = "collect",
        response_schema = request.response_schema,
        replies = {},
        open = true,
    }
    self.open_phases[#self.open_phases + 1] = entry
    park(self, entry, conns, encode_request(request, { ... }))
    request_seal(self, entry)
    return wait(self, entry).replies
end
-- docs:end collect_claims

-- Runs the referee: spawns its main logic, then drives the event loop until it is done.
function server_meta.__index.run(self, main)
    self.dispatcher:spawn(function()
        main()
        self.done = true
    end)
    while not self.done do
        self.dispatcher:step()
    end
end

return {
    SCHEMA_DICT = SCHEMA_DICT,
    define_request = define_request,
    format_short_hash = format_short_hash,
    narrate = narrate,
    push_run = push_run,
    slice_runs = slice_runs,
    new_tree = new_tree,
    new_match = new_match,
    is_valid_move = is_valid_move,
    advance_match = advance_match,
    new_server = new_server,
    serve = serve,
    new_sealer = new_sealer,
}
