-- The parts of the PRT game that do not depend on what is being disputed: the claim trees
-- (Merkle trees over runs of repeated nodes, refined on demand), the referee's coroutine
-- dispatcher, the request board that carries the asynchronous wire protocol, and the tagged
-- narration. The game script supplies the machines, the commitment builds, the tournament,
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
local function short_hash(hash)
    return cartesi.tohex(hash):sub(1, 10) .. "..."
end

-- Requests are Lua snippets, so binary hashes cross the wire inside them in hexadecimal.
local hex, unhex = cartesi.tohex, cartesi.fromhex

--------------------------------------------------------------------------------
-- Narration
--
-- The referee narrates the tournament into tagged files, one per subject (the claims, the
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
local function iterated(tree, hash, k)
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
-- docs:begin runs_node
local function runs_node(tree, runs, entry_height, h, q)
    local first = q << (h - entry_height)
    local count = 1 << (h - entry_height)
    local i = find_run(runs, first)
    if not math.ult(runs.cum[i] - 1, first + count - 1) then -- a single run covers the range
        return iterated(tree, runs[i].hash, h - entry_height)
    end
    return keccak(
        runs_node(tree, runs, entry_height, h - 1, 2 * q),
        runs_node(tree, runs, entry_height, h - 1, 2 * q + 1)
    )
end
-- docs:end runs_node

local tree_meta = { __index = {} }

-- The node at height h, index q. At or above entry_height it resolves over the stored runs.
-- Below, it locates the one stored entry standing over the node and queries the leaf runs
-- recovered by refine, so only the entries a dispute actually visits are ever expanded.
-- docs:begin tree_node
function tree_meta.__index.node(tree, h, q)
    if h >= tree.entry_height then
        return runs_node(tree, tree.runs, tree.entry_height, h, q)
    end
    local entry = q >> (tree.entry_height - h)
    local leaf_runs = tree.refined[entry]
    if not leaf_runs then
        leaf_runs = seal_runs(tree:refine(entry))
        assert(leaf_runs.total == 1 << tree.entry_height, "refine did not produce a full entry")
        tree.refined[entry] = leaf_runs
    end
    return runs_node(tree, leaf_runs, 0, h, q - (entry << (tree.entry_height - h)))
end
-- docs:end tree_node

function tree_meta.__index.root(tree)
    return tree:node(tree.height, 0)
end

-- The two children of the node at height h, index q.
function tree_meta.__index.children(tree, h, q)
    return tree:node(h - 1, 2 * q), tree:node(h - 1, 2 * q + 1)
end

-- The proof of leaf index: its value and the sibling of each node on the path to the root.
function tree_meta.__index.prove(tree, index)
    local siblings = {}
    for level = 0, tree.height - 1 do
        siblings[level + 1] = tree:node(level, (index >> level) ~ 1)
    end
    return tree:node(0, index), siblings
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

-- The referee-side check: folds a leaf up its siblings to the root it claims membership of.
-- The bits of the leaf index say on which side each sibling stands.
-- docs:begin fold_proof
local function fold_proof(leaf, index, siblings)
    local hash = leaf
    for level = 1, #siblings do
        if index & (1 << (level - 1)) ~= 0 then
            hash = keccak(siblings[level], hash)
        else
            hash = keccak(hash, siblings[level])
        end
    end
    return hash
end
-- docs:end fold_proof

--------------------------------------------------------------------------------
-- Coroutine dispatcher
--
-- The referee mediates several matches at once, each written as ordinary sequential code
-- inside its own coroutine. A coroutine that must wait (for a socket, an answer, or a
-- deadline) yields to the dispatcher, which resumes whichever coroutine's event arrives
-- first. The players connect over plain blocking sockets and answer in whatever order they
-- please.
--------------------------------------------------------------------------------

local dispatcher_meta = { __index = {} }

local function new_dispatcher()
    return setmetatable({
        readable = { socks = {}, cortn = {} },
        writable = { socks = {}, cortn = {} },
        alarms = {},
        ready = {},
        ready_first = 1,
        ready_last = 0,
    }, dispatcher_meta)
end

-- Schedules a coroutine to be resumed with the given reason.
function dispatcher_meta.__index.schedule(self, cortn, reason)
    self.ready_last = self.ready_last + 1
    self.ready[self.ready_last] = { cortn, reason }
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

-- Suspends the running coroutine until it is scheduled, or until the deadline when one is
-- given. Returns the reason it was resumed with ("alarm" for the deadline).
function dispatcher_meta.__index.wake_when_scheduled(self, deadline)
    if deadline then
        self.alarms[#self.alarms + 1] = { deadline = deadline, cortn = coroutine.running() }
    end
    return coroutine.yield()
end

function dispatcher_meta.__index.cancel_alarms(self, cortn)
    for i = #self.alarms, 1, -1 do
        if self.alarms[i].cortn == cortn then
            table.remove(self.alarms, i)
        end
    end
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

-- One dispatcher step: waits for the first socket event, elapsed alarm, or scheduled
-- coroutine, then resumes everyone it concerns. A resumed coroutine may re-suspend on
-- something else before its later wakeups arrive, so stale wakeups are possible, and every
-- wait loop re-checks its condition. Errors inside a coroutine are fatal: the referee has
-- no business surviving its own bugs.
function dispatcher_meta.__index.step(self)
    local timeout
    if self.ready_first <= self.ready_last then
        timeout = 0
    else
        local now = socket.gettime()
        for _, alarm in ipairs(self.alarms) do
            local left = math.max(alarm.deadline - now, 0)
            if not timeout or left < timeout then
                timeout = left
            end
        end
    end
    assert(timeout or #self.readable.socks > 0 or #self.writable.socks > 0, "would block forever")
    local readable, writable = socket.select(self.readable.socks, self.writable.socks, timeout)
    wake_ready(self, self.readable, readable)
    wake_ready(self, self.writable, writable)
    local now = socket.gettime()
    for i = #self.alarms, 1, -1 do
        if self.alarms[i].deadline <= now then
            local alarm = table.remove(self.alarms, i)
            self:schedule(alarm.cortn, "alarm")
        end
    end
    while self.ready_first <= self.ready_last do
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
-- newline. The referee sends requests {subject, code, schema}, where subject names what the
-- move is about (a claim, or a match at a height) and code is a Lua snippet the player runs
-- against its own state. A player answers {subject, label, value}, the value encoded under
-- the schema the request named so binary hashes, proofs, and access logs survive the trip.
-- The valid move for a subject is unique, fixed by the claim's committed tree, so a claim
-- cannot be misrepresented and it never matters who sends a move: the referee takes any move
-- that proves itself and ignores the rest. The label rides along only for narration.
--------------------------------------------------------------------------------

-- The schemas shared by every request. The game script adds its own reply schemas.
local SCHEMA_DICT = {}

-- The envelope schema for replies under a named value schema, registered on first use, so
-- both sides encode {id, value} with the value's binary fields transformed.
local function reply_schema(schema)
    if not schema then
        return nil
    end
    local name = schema .. "Reply"
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

-- The player side is a plain blocking loop: read a request, run its snippet with the player
-- as its environment, and answer with the value the snippet produces, tagged by the
-- request's subject and stamped with the player's label (which the referee uses only to
-- narrate, never to decide). A player that cannot, or will not, answer a subject stays
-- silent, and the referee's per-subject timeout decides what the silence costs the claim.
-- docs:begin serve
local function serve(player, server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    player.connection = assert(socket.connect(host, tonumber(port)))
    repeat
        local line = assert(player.connection:receive("*l"))
        trace_wire("from referee", player.label, line)
        local request = cartesi.fromjson(line)
        local chunk = assert(load(request.code, "=referee", "t", player))
        local ok, value = pcall(chunk)
        if not ok then
            io.stderr:write(string.format("%s: request failed: %s\n", player.label, tostring(value)))
        elseif value ~= nil then
            local reply = cartesi.tojson(
                { subject = request.subject, label = player.label, value = value },
                -1,
                reply_schema(request.schema),
                SCHEMA_DICT
            )
            trace_wire("to referee", player.label, reply)
            assert(player.connection:send(reply .. "\n"))
        end
    until player.done
    player.connection:close()
end
-- docs:end serve

-- Tells a running referee that the last player has connected, so it closes the join phase. A
-- single line on the reserved "seal" subject over a throwaway connection, sent by the recipe
-- after ordering the players, so the referee need never be told how many to expect.
local function seal(server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    local connection = assert(socket.connect(host, tonumber(port)))
    assert(connection:send(cartesi.tojson({ subject = "seal" }, -1) .. "\n"))
    connection:close()
end

--------------------------------------------------------------------------------
-- Referee server
--
-- Every player connects to the referee server, which is the single event loop. It notifies
-- the subscribers of each awaiting match with the move that match needs, buffers every move a
-- player sends under the move's subject, and routes it to the coroutine parked on that
-- subject. A move no coroutine awaits is dropped, and a malformed one closes its sender's
-- connection.
--
-- The server runs in synchronous ticks so the narration is a pure function of the claims, not
-- of network timing. It snapshots the subjects currently parked, waits until each has a valid
-- move (or times out a silent one), then resumes the parked coroutines in a fixed priority
-- order, one step per match. A subject stamped with a lower priority is always narrated first,
-- so two runs of the same dispute read identically.
--------------------------------------------------------------------------------

-- A subject silent for this long, while the tournament makes no other progress, is timed out.
-- Generous enough that no honest move (a fork and a short run) is ever mistaken for silence.
local TICK_TIMEOUT = 30
-- The idle wait when nothing is parked yet, so the loop wakes to notice the first match.
local IDLE_WAIT = 1

local server_meta = { __index = {} }

local function new_server(dispatcher, listener)
    return setmetatable({
        dispatcher = dispatcher,
        listener = listener,
        connections = {},
        holders = {}, -- claim root hex -> set of connections that hold (can defend) it
        parked = {}, -- subject -> { cortn, validate, priority, schema, subject }
        collectors = {}, -- subject -> coroutine collecting join replies on it
        greetings = {}, -- subject -> request line an open join replays to each new connection
        inbox = {}, -- subject -> array of { line, connection } awaiting a consumer
        sealed = false, -- set once a seal connection closes the join phase
        done = false,
    }, server_meta)
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

-- Closes a connection (its sender posted a malformed move). A dead connection is skipped by
-- every notify and subscriber lookup thereafter.
local function close_connection(connection)
    if not connection.dead then
        connection.dead = true
        connection.sock:close()
    end
end

-- Wakes the tick loop, if it is waiting, so it re-checks its snapshot. Its pending timeout
-- alarm is cancelled, so waking early leaves nothing stale behind in the dispatcher.
local function wake_tick(self)
    if self.tick_waiter then
        local waiter = self.tick_waiter
        self.tick_waiter = nil
        self.dispatcher:cancel_alarms(waiter)
        self.dispatcher:schedule(waiter, "wake")
    end
end

-- Adopts a new player connection: spawns its writer, which drains the outbox, and its reader,
-- which files each incoming move under its subject and wakes whoever consumes that subject. A
-- move for a subject nobody awaits is dropped.
function server_meta.__index.adopt(self, sock)
    sock:settimeout(0)
    local connection = { sock = sock, outbox = {} }
    self.connections[#self.connections + 1] = connection
    -- Replay any open join request, so a player that connects after the broadcast still gets it.
    for _, line in pairs(self.greetings) do
        enqueue(self, connection, line)
    end
    self.dispatcher:spawn(function()
        while true do
            local line = table.remove(connection.outbox, 1)
            if line then
                if not send_line(self.dispatcher, connection, line) then
                    connection.dead = true
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
                connection.dead = true
                return
            end
            trace_wire("from player", nil, line)
            -- The subject is a plain field, decodable without the reply schema.
            local ok, message = pcall(cartesi.fromjson, line)
            local subject = ok and message.subject
            if subject == "seal" then
                self:seal(connection)
            elseif subject and (self.parked[subject] or self.collectors[subject]) then
                local queue = self.inbox[subject]
                if not queue then
                    queue = {}
                    self.inbox[subject] = queue
                end
                queue[#queue + 1] = { line = line, connection = connection }
                local collector = self.collectors[subject]
                if collector then
                    self.dispatcher:cancel_alarms(collector)
                    self.dispatcher:schedule(collector, "answer")
                end
                wake_tick(self)
            end
        end
    end)
    return connection
end

-- Accepts player connections, adopting each as it arrives, until the game ends. The referee
-- is never told how many players to expect: it takes every one that connects and stops
-- gathering claims when a seal connection closes the join phase.
function server_meta.__index.accept(self)
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

-- Closes the join phase. A throwaway seal connection sends this once the last player has
-- connected, so the referee stops waiting for more players without ever being told how many
-- to expect. The connection is marked so it is never counted as a player, and every open
-- collector is woken to re-check whether its phase is now complete.
function server_meta.__index.seal(self, connection)
    connection.is_seal = true
    self.sealed = true
    for _, collector in pairs(self.collectors) do
        self.dispatcher:cancel_alarms(collector)
        self.dispatcher:schedule(collector, "seal")
    end
end

-- The number of live player connections, the seal connection excepted. Once the join phase is
-- sealed, this is the count the referee waits to hear an opening claim from, and later the
-- count it waits to release.
function server_meta.__index.player_count(self)
    local count = 0
    for _, connection in ipairs(self.connections) do
        if not connection.dead and not connection.is_seal then
            count = count + 1
        end
    end
    return count
end

-- Records that a connection holds a claim, so it is notified of that claim's matches.
function server_meta.__index.add_holder(self, root_hex, connection)
    local set = self.holders[root_hex]
    if not set then
        set = {}
        self.holders[root_hex] = set
    end
    set[connection] = true
end

-- The live connections that hold any of the given claim roots (a match's subscribers).
function server_meta.__index.subscribers(self, root_hexes)
    local seen, list = {}, {}
    for _, root_hex in ipairs(root_hexes) do
        local set = self.holders[root_hex]
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

-- Encodes a request line: the subject the move is about, the snippet the player runs, and the
-- reply schema.
local function request_line(subject, schema, code, ...)
    return cartesi.tojson({ subject = subject, code = string.format(code, ...), schema = schema }, -1) .. "\n"
end

-- Notifies a set of connections (or every live one when `conns` is nil) with a request.
local function notify(self, conns, line)
    for _, connection in ipairs(conns or self.connections) do
        enqueue(self, connection, line)
    end
end

-- Collects the join moves on a subject and returns them (each a decoded value with the label
-- and connection that sent it). It registers as the subject's collector before notifying, so
-- no early reply is missed. Collection stops at the deadline, or `grace` seconds after `want`
-- first holds: the grace lets every player that will supply an identical claim be gathered, so
-- the labels a claim is credited with are the whole set, not whoever happened to answer first.
function server_meta.__index.collect(self, subject, conns, schema, deadline, grace, want, code, ...)
    self.collectors[subject] = coroutine.running()
    local line = request_line(subject, schema, code, ...)
    -- A join is open to players that connect after this broadcast, so it is replayed on adopt.
    self.greetings[subject] = line
    notify(self, conns, line)
    local replies, consumed, satisfied_at = {}, 0, nil
    while true do
        local queue = self.inbox[subject]
        while queue and consumed < #queue do
            consumed = consumed + 1
            local ok, decoded = pcall(cartesi.fromjson, queue[consumed].line, reply_schema(schema), SCHEMA_DICT)
            if ok then
                replies[#replies + 1] =
                    { value = decoded.value, label = decoded.label, connection = queue[consumed].connection }
            end
        end
        if not satisfied_at and want(replies) then
            satisfied_at = socket.gettime()
        end
        local wake = deadline
        if satisfied_at then
            wake = math.min(wake, satisfied_at + grace)
        end
        if socket.gettime() >= wake then
            break
        end
        self.dispatcher:wake_when_scheduled(wake)
    end
    self.collectors[subject] = nil
    self.greetings[subject] = nil
    self.inbox[subject] = nil
    return replies
end

-- Takes the valid moves buffered for a parked subject: decodes each under the subject's
-- schema, accepts the (unique) value of the first that its validator passes, gathers the
-- sorted labels of every sender that supplied it, and closes the connection of any sender
-- whose move is malformed. Returns the accepted value and labels, or nil if none is valid yet.
local function take_valid(self, entry)
    local queue = self.inbox[entry.subject]
    if not queue then
        return nil
    end
    local value, seen, labels = nil, {}, {}
    for _, item in ipairs(queue) do
        local ok, decoded = pcall(cartesi.fromjson, item.line, reply_schema(entry.schema), SCHEMA_DICT)
        local valid = false
        if ok then
            local validated, accepted = pcall(entry.validate, decoded.value)
            valid = validated and accepted
        end
        if valid then
            if value == nil then
                value = decoded.value
            end
            if not seen[decoded.label] then
                seen[decoded.label] = true
                labels[#labels + 1] = decoded.label
            end
        else
            close_connection(item.connection)
        end
    end
    if value == nil then
        return nil
    end
    table.sort(labels)
    return value, labels
end

-- Notifies a subject's subscribers with the move it needs, parks the running match coroutine
-- on that subject under the tick discipline, and returns the accepted move (value and the
-- sorted labels that supplied it) once the tick loop resumes it, or nil when the subject timed
-- out. `priority` fixes the subject's narration order; `validate` rejects malformed moves.
-- docs:begin await
function server_meta.__index.await(self, subject, conns, priority, schema, validate, code, ...)
    self.parked[subject] = {
        cortn = coroutine.running(),
        validate = validate,
        priority = priority,
        schema = schema,
        subject = subject,
    }
    notify(self, conns, request_line(subject, schema, code, ...))
    wake_tick(self)
    local result = coroutine.yield()
    self.parked[subject] = nil
    self.inbox[subject] = nil
    if result.timed_out then
        return nil
    end
    return result.value, result.labels
end
-- docs:end await

-- Parks the tick loop until it is woken (by a new park, an arriving move, or the deadline).
local function wait_tick(self, deadline)
    self.tick_waiter = coroutine.running()
    self.dispatcher:wake_when_scheduled(deadline)
    self.tick_waiter = nil
end

-- The tick loop. Each tick it snapshots the parked subjects in priority order, waits until
-- every one has a valid move or the timeout elapses, then resumes them in that order, one step
-- per match. A subject still silent at the timeout is resumed as timed out, so its match
-- eliminates the silent claim. New subjects the resumed coroutines park on wait for the next
-- tick, which keeps every match advancing in lockstep and the transcript deterministic.
-- docs:begin tick_loop
function server_meta.__index.tick_loop(self)
    while not self.done do
        local snapshot = {}
        for _, entry in pairs(self.parked) do
            snapshot[#snapshot + 1] = entry
        end
        if #snapshot == 0 then
            wait_tick(self, socket.gettime() + IDLE_WAIT)
        else
            table.sort(snapshot, function(a, b)
                return a.priority < b.priority
            end)
            local deadline = socket.gettime() + TICK_TIMEOUT
            local pending = #snapshot
            while pending > 0 and socket.gettime() < deadline do
                for _, entry in ipairs(snapshot) do
                    if not entry.resolved then
                        local value, labels = take_valid(self, entry)
                        if value ~= nil then
                            entry.resolved = { value = value, labels = labels }
                            pending = pending - 1
                        end
                    end
                end
                if pending > 0 then
                    wait_tick(self, deadline)
                end
            end
            for _, entry in ipairs(snapshot) do
                self.dispatcher:schedule(entry.cortn, entry.resolved or { timed_out = true })
            end
            -- Yield once so the resumed coroutines run and park on their next subjects before
            -- the next snapshot is taken.
            wait_tick(self, socket.gettime())
        end
    end
end
-- docs:end tick_loop

-- Runs the referee: spawns the tick loop and the referee's main logic, then drives the event
-- loop until the main logic sets it done.
function server_meta.__index.run(self, main)
    self.dispatcher:spawn(function()
        self:tick_loop()
    end)
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
    short_hash = short_hash,
    hex = hex,
    unhex = unhex,
    narrate = narrate,
    push_run = push_run,
    slice_runs = slice_runs,
    new_tree = new_tree,
    fold_proof = fold_proof,
    new_dispatcher = new_dispatcher,
    new_server = new_server,
    serve = serve,
    seal = seal,
}
