-- The parts of the PRT game that do not depend on what is being disputed: the claim trees
-- (Merkle trees over runs of repeated nodes, refined on demand), the match walk, the referee's
-- coroutine dispatcher, the referee server that carries the wire protocol, and the tagged
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

-- The proof of a leaf index, in the standard cartesi.hash-tree representation. Claim-tree
-- addresses are logical leaf indices, so their target size is zero and their root size is the
-- tree height.
function tree_meta.__index.prove(tree, index)
    local siblings = {}
    for level = 0, tree.height - 1 do
        siblings[level + 1] = tree:node(level, (index >> level) ~ 1)
    end
    return {
        target_address = index,
        log2_target_size = 0,
        target_hash = tree:node(0, index),
        log2_root_size = tree.height,
        root_hash = tree:root(),
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
-- starts with one's root as the node to open and two's join-exposed root children standing.
-- docs:begin new_match
local function new_match(one, two, height)
    return {
        one = one,
        two = two,
        turn = one, -- the claim whose node is other_parent
        other = two,
        other_parent = one.root,
        left_node = two.left,
        right_node = two.right,
        height = height,
        index = 0,
    }
end
-- docs:end new_match

-- Checks a move against the match state: the children must join into the node to open, and,
-- above the leaves, the grandchildren must join into the child the walk descends into.
-- docs:begin valid_move
local function valid_move(m, move)
    if keccak(move.l, move.r) ~= m.other_parent then
        return false
    end
    if m.height > 1 then
        return keccak(move.nl, move.nr) == ((move.l ~= m.left_node) and move.l or move.r)
    end
    return true
end
-- docs:end valid_move

-- Applies a valid move. Above the leaves, the walk descends one height: the on-turn claim's
-- chosen grandchildren become the standing left and right, the opponent's node on the chosen
-- side becomes the next to open, and the turn passes. At height 1 the exposed children are
-- leaves, and the walk is over: it returns the isolated dispute, the divergent leaf's index,
-- what each claim committed to there (d1 for claim one, d2 for claim two), and, when the
-- divergence is at a right leaf, the agreed state before it, the left leaf both sides exposed.
-- docs:begin advance_match
local function advance_match(m, move)
    local descend_left = move.l ~= m.left_node
    if m.height == 1 then
        local leaf_index, d_turn, d_other, agreed
        if descend_left then
            leaf_index, d_turn, d_other = 2 * m.index, move.l, m.left_node
        else
            leaf_index, d_turn, d_other, agreed = 2 * m.index + 1, move.r, m.right_node, move.l
        end
        local d1 = m.turn == m.one and d_turn or d_other
        local d2 = m.turn == m.one and d_other or d_turn
        return { leaf_index = leaf_index, agreed = agreed, d1 = d1, d2 = d2 }
    end
    if descend_left then
        m.other_parent, m.index = m.left_node, 2 * m.index
    else
        m.other_parent, m.index = m.right_node, 2 * m.index + 1
    end
    m.left_node, m.right_node = move.nl, move.nr
    m.height = m.height - 1
    m.turn, m.other = m.other, m.turn
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
-- newline. The referee sends requests {subject, code, schema}, where subject names what the
-- move is about (a claim, or a match at a height) and code is a Lua snippet the player runs
-- against its own state. A player answers {subject, label, value}, the value encoded under
-- the schema the request named so binary hashes, proofs, and access logs survive the trip.
-- The valid move for a subject is unique, fixed by the claim's committed tree, so a claim
-- cannot be misrepresented and it never matters who sends a move: the referee takes the first
-- move that proves itself and ignores the rest. The label rides along only for tracing.
--------------------------------------------------------------------------------

-- The schemas shared by every request. The game script adds its own reply schemas.
local SCHEMA_DICT = {}

-- The envelope schema for replies under a named value schema, registered on first use, so
-- both sides encode {subject, label, value} with the value's binary fields transformed.
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

-- The player side is a plain blocking loop: announce itself, then read a request, run its
-- snippet with the player as its environment, and answer with the value the snippet produces,
-- tagged by the request's subject and stamped with the player's label (which the referee
-- never uses to decide). Every request is routed to a holder of the claim it is about, so a snippet that
-- produces nothing, or fails, is a bug in the player, and the process dies with it: the
-- referee sees the connection close, and the claim loses its holder. The loop also ends when
-- the game releases the player, or when the referee goes away.
-- docs:begin serve
local function serve(player, server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    player.connection = assert(socket.connect(host, tonumber(port)))
    local hello = player.hello or cartesi.tojson({ subject = "player", label = player.label }, -1)
    assert(player.connection:send(hello .. "\n"))
    repeat
        local line = player.connection:receive("*l")
        if not line then
            break
        end
        trace_wire("from referee", player.label, line)
        local request = cartesi.fromjson(line)
        local chunk = assert(load(request.code, "=referee", "t", player))
        local value = chunk()
        assert(value ~= nil, "the request produced no value")
        local reply = { subject = request.subject, label = player.label, value = value }
        local encoded = cartesi.tojson(reply, -1, reply_schema(request.schema), SCHEMA_DICT)
        trace_wire("to referee", player.label, encoded)
        assert(player.connection:send(encoded .. "\n"))
    until player.done
    player.connection:close()
end
-- docs:end serve

-- The sealer is a player with one operation: sealing the tournament the referee names. It
-- announces itself as the sealer on connecting, and the referee sends it a seal request for every
-- tournament it opens, the root one and every nested one, so a tournament closes its
-- claim submissions by the same lifecycle at both levels.
local function new_sealer()
    local sealer = {
        label = "sealer",
        hello = cartesi.tojson({ subject = "sealer" }, -1),
        seal = function(_, id)
            return id
        end,
    }
    sealer.sealer = sealer
    return sealer
end

--------------------------------------------------------------------------------
-- Referee server
--
-- Every player connects to the referee server, which is the single event loop. A tournament
-- opens with an audience, the connections asked to submit a claim to it, and its submissions
-- close once the sealer seals it and every connection in the audience has submitted or
-- closed. A move request asks the holders of a claim, and takes the first reply that proves
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
-- as such, a seal request is bound to that connection, and a seal is taken only from it, for
-- the tournament it names. The model therefore assumes a process announces its role
-- honestly. A sealer that goes away fails the referee outright, since no tournament could
-- ever close again.
--------------------------------------------------------------------------------

local server_meta = { __index = {} }

local function new_server(dispatcher, listener)
    return setmetatable({
        dispatcher = dispatcher,
        listener = listener,
        connections = {},
        holders = {}, -- claim root hex -> set of connections that hold (can defend) it
        parked = {}, -- subject -> the request parked on it
        sealer = nil, -- the sealer's connection, once it announces itself
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

-- Resolves a parked request: forgets its subject and hands the result to its coroutine.
local function resolve(self, entry, result)
    self.parked[entry.subject] = nil
    if entry.cortn then
        self.dispatcher:schedule(entry.cortn, result)
    end
end

-- Re-examines a parked request after a reply, a closed connection, or a seal. A move request
-- resolves as soon as it has taken a valid value, and otherwise once every connection asked
-- has answered or closed, with nothing. A collection stays parked while a connection is
-- still to answer, and a tournament's submissions also until the seal, then resolves with
-- the replies gathered. Later replies to a resolved request find no subject and are ignored.
local function settle(self, entry)
    if self.parked[entry.subject] ~= entry then
        return
    end
    if entry.kind == "ask" then
        if entry.value ~= nil or not next(entry.pending) then
            resolve(self, entry, { value = entry.value })
        end
    elseif not entry.open and not next(entry.pending) then
        resolve(self, entry, { replies = entry.replies })
    end
end

-- Drops a connection from every request waiting on it, settling those it was the last of.
local function forget_connection(self, connection)
    for _, entry in pairs(self.parked) do
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

-- Encodes a request line: the subject the move is about, the snippet the player runs, and the
-- reply schema.
local function request_line(subject, schema, code, ...)
    return cartesi.tojson({ subject = subject, code = string.format(code, ...), schema = schema }, -1) .. "\n"
end

-- Asks the sealer to seal a tournament, once there is a sealer to ask. The request is bound
-- to the sealer's connection: only its reply can seal.
local function request_seal(self, tournament)
    if not self.sealer then
        return
    end
    local subject = "seal-" .. tournament.subject
    local entry = { kind = "seal", subject = subject, tournament = tournament, pending = { [self.sealer] = true } }
    self.parked[subject] = entry
    enqueue(self, self.sealer, request_line(subject, nil, 'return sealer:seal("%s")', tournament.subject))
end

-- Files a reply on the request parked on its subject. A reply from a connection the request
-- is not waiting on (a forged seal, a repeat, or a late one) is ignored. The envelope already
-- identified the request, so a value that does not decode under the request's schema is an
-- invalid operation, not a malformed connection: it counts as the connection's answer, is
-- rejected, and leaves the connection open, exactly like a value the acceptor rejects, so
-- the order replies arrive in cannot decide which connections stay open. A move request
-- takes the first truthy result its acceptor returns. A collection keeps every reply that
-- decodes. A seal, from the sealer and naming the tournament it was asked for, closes that
-- tournament's submissions, and a seal that does not decode or names another tournament is
-- a failure of the referee's own orchestration.
local function deliver(self, entry, connection, line)
    if not entry.pending[connection] then
        return
    end
    entry.pending[connection] = nil
    local ok, decoded = pcall(cartesi.fromjson, line, reply_schema(entry.schema), SCHEMA_DICT)
    if entry.kind == "seal" then
        assert(ok and decoded.value == entry.tournament.subject, "the sealer did not seal the tournament asked")
        self.parked[entry.subject] = nil
        entry.tournament.open = false
        settle(self, entry.tournament)
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
-- and it is never part of a tournament's audience. Every tournament already open, still
-- waiting for its seal, is handed to it at once.
local function announce_sealer(self, connection)
    if self.sealer then
        close_connection(self, connection)
        return
    end
    connection.is_sealer = true
    self.sealer = connection
    for _, entry in pairs(self.parked) do
        if entry.kind == "collect" and entry.open then
            request_seal(self, entry)
        end
    end
end

-- A connection announced itself as a player. It is asked to submit to the mcycle tournament,
-- when that is still open.
local function announce_player(self, connection)
    connection.is_player = true
    for _, entry in pairs(self.parked) do
        if entry.grows and entry.open then
            entry.pending[connection] = true
            enqueue(self, connection, entry.line)
        end
    end
end

-- The first line of a connection announces its role, once. A connection that announces again,
-- or sends anything else before announcing, is closed.
local function announce(self, connection, message)
    if connection.is_player or connection.is_sealer then
        close_connection(self, connection)
    elseif message.subject == "sealer" then
        announce_sealer(self, connection)
    elseif message.subject == "player" then
        announce_player(self, connection)
    else
        close_connection(self, connection)
    end
end

-- Adopts a new connection: spawns its writer, which drains the outbox, and its reader, which
-- routes each incoming line to the request parked on its subject. The first line a
-- connection sends announces what it is, a player or the sealer.
function server_meta.__index.adopt(self, sock)
    sock:settimeout(0)
    local connection = { sock = sock, outbox = {} }
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
            -- The subject is a plain field, decodable without the reply schema.
            local ok, message = pcall(cartesi.fromjson, line)
            if not ok or type(message) ~= "table" then
                close_connection(self, connection)
                return
            end
            local announced = connection.is_player or connection.is_sealer
            if message.subject == "sealer" or message.subject == "player" or not announced then
                announce(self, connection, message)
            else
                local entry = self.parked[message.subject]
                if entry then
                    deliver(self, entry, connection, line)
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
-- told how many players to expect: it takes every one that connects until the sealer seals
-- the mcycle tournament.
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

-- Records that a connection holds a claim, so it is asked about that claim's matches.
function server_meta.__index.add_holder(self, root_hex, connection)
    local set = self.holders[root_hex]
    if not set then
        set = {}
        self.holders[root_hex] = set
    end
    set[connection] = true
end

-- The live connections that hold any of the given claim roots.
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

-- Every live player connection.
function server_meta.__index.everyone(self)
    local list = {}
    for _, connection in ipairs(self.connections) do
        if not connection.dead and connection.is_player then
            list[#list + 1] = connection
        end
    end
    return list
end

-- Parks a request on its subject, asking the given connections. The set asked is frozen here,
-- and a connection already closed is not in it.
local function park(self, entry, conns, line)
    assert(not self.parked[entry.subject], "subject already parked")
    entry.cortn = coroutine.running()
    entry.pending = {}
    entry.line = line
    self.parked[entry.subject] = entry
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
            enqueue(self, connection, line)
        end
    end
end

-- Suspends the running coroutine until its parked request resolves.
local function wait(self, entry)
    settle(self, entry)
    return coroutine.yield()
end

-- Asks the given connections for the move a subject needs, and returns the first truthy value
-- produced by `accept`, or nil once every connection asked has answered without one or closed.
-- A claim nobody answers for is thereby eliminated at once.
-- docs:begin ask
function server_meta.__index.ask(self, subject, conns, schema, accept, code, ...)
    local entry = { kind = "ask", subject = subject, schema = schema, accept = accept }
    park(self, entry, conns, request_line(subject, schema, code, ...))
    return wait(self, entry).value
end
-- docs:end ask

-- Asks the given connections (every player, when nil) for a value, and returns the replies,
-- each with the label and connection that sent it, once every connection asked has replied or
-- closed.
function server_meta.__index.collect(self, subject, conns, schema, code, ...)
    local entry = { kind = "collect", subject = subject, schema = schema, replies = {}, open = false }
    park(self, entry, conns or self:everyone(), request_line(subject, schema, code, ...))
    return wait(self, entry).replies
end

-- Opens a tournament to the given audience (every player that has connected, and every one
-- that connects before the seal, when nil), asking each to submit a claim, and returns the
-- submissions once the sealer seals the tournament and every connection in the audience has
-- submitted or closed.
-- docs:begin open_tournament
function server_meta.__index.open_tournament(self, id, conns, schema, code, ...)
    local entry = { kind = "collect", subject = id, schema = schema, replies = {}, open = true, grows = not conns }
    park(self, entry, conns or self:everyone(), request_line(id, schema, code, ...))
    request_seal(self, entry)
    return wait(self, entry).replies
end
-- docs:end open_tournament

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
    short_hash = short_hash,
    hex = hex,
    unhex = unhex,
    narrate = narrate,
    push_run = push_run,
    slice_runs = slice_runs,
    new_tree = new_tree,
    new_match = new_match,
    valid_move = valid_move,
    advance_match = advance_match,
    new_dispatcher = new_dispatcher,
    new_server = new_server,
    serve = serve,
    new_sealer = new_sealer,
}
