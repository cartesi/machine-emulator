-- Coroutine transport shared by the demonstration games. Game schemas, reply validity,
-- sender permissions, and narration remain outside the socket dispatcher.
local cartesi = require("cartesi")
local socket = require("socket")
local new_clock = require("prt-clock")
local new_response_queue = require("prt-response-queue")
local EVERYONE = nil

local function trace_wire(protocol, direction, name, line)
    if protocol.tracing then
        io.stderr:write(string.format("%s %s: %s\n", direction, name or "?", line))
    end
end

local function define_event(name, event_schema, response_schema)
    return { name = name, event_schema = event_schema, response_schema = response_schema }
end

local function new_protocol(events, schemas, trace_env)
    schemas.ClosePhaseEvent = { items = {} }
    schemas.ClosePhaseResponse = "Default"
    schemas.FinishEvent = { items = {} }
    schemas.FinishResponse = "Default"
    schemas.AdvanceTimeEvent = { items = { "Default" } }
    schemas.Responses = { items = "Default" }
    events.close_phase = define_event("close_phase", "ClosePhaseEvent", "ClosePhaseResponse")
    events.finish = define_event("finish", "FinishEvent", "FinishResponse")
    events.advance_time = define_event("advance_time", "AdvanceTimeEvent", "Responses")
    return { events = events, schemas = schemas, tracing = trace_env and os.getenv(trace_env) ~= nil }
end

local dispatcher_meta = { __index = {} }

local function new_dispatcher()
    return setmetatable({
        readable = { socks = {}, cortn = {} },
        writable = { socks = {}, cortn = {} },
        ready = {},
        ready_first = 1,
        ready_last = 0,
        parents = setmetatable({}, { __mode = "k" }),
    }, dispatcher_meta)
end

-- Schedules a coroutine to be resumed with the given value.
function dispatcher_meta.__index.schedule(self, cortn, value)
    self.ready_last = self.ready_last + 1
    self.ready[self.ready_last] = { cortn, value }
end

function dispatcher_meta.__index.spawn(self, f)
    local cortn = coroutine.create(f)
    self.parents[cortn] = coroutine.running()
    self:schedule(cortn, "start")
    return cortn
end

-- Closing a coroutine and its descendants runs their scoped cleanup. Queued resumptions
-- are harmless because step skips dead coroutines.
function dispatcher_meta.__index.close(self, main)
    local coroutines = { main }
    for cortn, parent in pairs(self.parents) do
        while parent do
            if parent == main then
                coroutines[#coroutines + 1] = cortn
                break
            end
            parent = self.parents[parent]
        end
    end
    for _, cortn in ipairs(coroutines) do
        assert(coroutine.close(cortn))
    end
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

-- The envelope schema for events under a named argument schema, registered on first use.
local function ensure_event_envelope_schema(protocol, schema)
    if not schema then
        return nil
    end
    local name = schema .. "Envelope"
    if not protocol.schemas[name] then
        protocol.schemas[name] = { arguments = schema }
    end
    return name
end

-- The envelope schema for responses under a named value schema, registered on first use, so
-- both sides encode {label, value} with the value's binary fields transformed.
local function ensure_response_envelope_schema(protocol, schema)
    if not schema then
        return nil
    end
    local name = schema .. "Envelope"
    if not protocol.schemas[name] then
        protocol.schemas[name] = { value = schema }
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

local client_queues = setmetatable({}, { __mode = "k" })
local client_requests = setmetatable({}, { __mode = "k" })

-- Schedules the current handler's response, retaining its routing and encoding inside
-- the transport. The player supplies only the block and the response-producing callback.
local function schedule_response(client, block, respond)
    local request = assert(client_requests[client], "no request being handled for this player")
    assert(request.id, "request does not support a delayed response")
    assert(type(respond) == "function", "schedule expects a response callback")
    client_queues[client]:schedule(request.id, block, function()
        -- Encode each response with its own event schema before batching.
        return cartesi.fromjson(cartesi.tojson(respond(), -1, request.response_schema, request.protocol.schemas))
    end)
    return request.owner and { scheduled_at = block } or true
end

-- Dispatches one wire event. Finish is transport cleanup rather than a client handler, so it
-- is handled here and kept out of the client-loop snippet.
local function answer_event(client, line, protocol)
    local envelope = cartesi.fromjson(line)
    local event = assert(protocol.events[envelope.operation], "unknown event")
    local wire_event =
        cartesi.fromjson(line, ensure_event_envelope_schema(protocol, event.event_schema), protocol.schemas)
    local queue = client_queues[client]
    if not queue then
        queue = new_response_queue()
        client_queues[client] = queue
    end
    local value
    if event == protocol.events.finish then
        value = true
    elseif event == protocol.events.advance_time then
        value = queue:advance(wire_event.arguments[1])
    else
        local handler = assert(client.event_handler[wire_event.operation], "missing event handler")
        client_requests[client] = {
            id = wire_event.id,
            response_schema = event.response_schema,
            protocol = protocol,
            owner = wire_event.owner,
        }
        local ok
        ok, value = pcall(handler, client, table.unpack(wire_event.arguments or {}))
        client_requests[client] = nil
        if not ok then
            error(value, 0)
        end
    end
    assert(value ~= nil, "the event handler produced no value")
    if wire_event.owner and not (type(value) == "table" and value.scheduled_at) then
        value = { answer = cartesi.fromjson(cartesi.tojson(value, -1, event.response_schema, protocol.schemas)) }
    end
    local response = { label = client.label, value = value, id = wire_event.id }
    local response_schema = wire_event.id and "Default" or event.response_schema
    local encoded =
        cartesi.tojson(response, -1, ensure_response_envelope_schema(protocol, response_schema), protocol.schemas)
    return encoded, event == protocol.events.finish or client.done
end

-- The player side is a plain blocking loop: announce itself, then read an event, decode its
-- arguments under the event's schema, dispatch its handler, and answer under the response
-- schema. The label names the player in the story. Computation requests go to interested holders.
-- schedule and time requests also deliver unrelated elimination work. A missing
-- handler or result is a client bug. The referee sees EOF and loses that holder. The loop also ends when
-- the referee goes away.
-- docs:begin run_client
local function run_client(client, server_address, protocol)
    local host, port = server_address:match("^(.-):(%d+)$")
    client.connection = assert(socket.connect(host, tonumber(port)))
    local hello = client.hello or cartesi.tojson({ role = "player", label = client.label }, -1)
    assert(client.connection:send(hello .. "\n"))
    while true do
        local line = client.connection:receive("*l")
        if not line then
            break
        end
        trace_wire(protocol, "from referee", client.label, line)
        local encoded, done = answer_event(client, line, protocol)
        trace_wire(protocol, "to referee", client.label, encoded)
        assert(client.connection:send(encoded .. "\n"))
        if done then
            break
        end
    end
    client.connection:close()
end
-- docs:end run_client

-- The phase closer closes initial subscriptions, or stops the server on a later connection.
-- Both commands are acknowledged through close_phase. Claim collection uses logical time.
local function new_phase_closer(command)
    assert(command == nil or command == "stop", "unknown phase closer command")
    local phase_closer = {
        label = "phase_closer",
        hello = cartesi.tojson({ role = "phase_closer", command = command }, -1),
        event_handler = {
            close_phase = function(self)
                self.done = true
                return true
            end,
        },
    }
    return phase_closer
end

--------------------------------------------------------------------------------
-- Referee server
--
-- Players answer one queued request at a time. Ordinary responses share a logical
-- block barrier. Schedule controls drain before the next time request.
-- The referee owns every window and validator. Only an accepted response
-- resolves a first-valid future, even when all its holders skip or disconnect.
-- Collections return all replies received before their wait's deadline.
-- Initial subscriptions still need an external close because connections arrive
-- over wall-clock time. Tournament claim collection closes at a supplied logical block.
-- The phase closer is trusted orchestration. Its announced role is not authenticated.
--------------------------------------------------------------------------------

local server_meta = { __index = {} }
local accept_connections

-- Omitting the address builds a socket-free model for scheduler tests.
local function new_server(address, protocol)
    local host, port = (address or ""):match("^(.-):(%d+)$")
    assert(not address or (host and port), "invalid server address")
    local server = setmetatable({
        dispatcher = new_dispatcher(),
        protocol = assert(protocol),
        listener = address and assert(socket.bind(host, tonumber(port))),
        connections = {},
        subscriptions = {}, -- subscription hash -> set of interested connections
        active = {}, -- set of pending requests, block waits, and closure groups
        clock = new_clock(),
        ordinary = {}, -- requests for the next ordinary block
        controls = {}, -- schedule requests awaiting their replies
        scheduled_responses = {}, -- scheduled response ID -> future
        event_order = 0,
        coroutine_order = setmetatable({}, { __mode = "k" }),
        next_coroutine_order = 0,
        open_phases = {}, -- the initial subscription phase, until its external close
        phase_closer = nil, -- the phase closer's connection, once it announces itself
        done = false,
    }, server_meta)
    if server.listener then
        accept_connections(server)
    end
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

local queue_control

-- Releases a completed request or block wait.
local function complete_event(self, entry)
    entry.resolved = true
    self.active[entry] = nil
    if entry.cortn then
        self.dispatcher:schedule(entry.cortn, entry)
        entry.cortn = nil
    end
end

-- Completes initial subscriptions once the trusted close arrives.
local function close_phase(self, phase)
    phase.open = false
    self.subscriptions_closed = true
    for index, open_phase in ipairs(self.open_phases) do
        if open_phase == phase then
            table.remove(self.open_phases, index)
            complete_event(self, phase)
            return
        end
    end
    error("closed phase was not open")
end

-- Drops a connection from every event waiting on it, settling those it was the last of.
local function forget_connection(self, connection)
    for entry in pairs(self.active) do
        if entry.pending[connection] then
            entry.pending[connection] = nil
        end
    end
    for _, entry in ipairs(self.controls) do
        entry.pending[connection] = nil
    end
    for _, entry in ipairs(self.batch or {}) do
        entry.pending[connection] = nil
    end
end

-- Closes a connection (its socket closed, or it sent a line the referee cannot decode). A dead
-- connection is skipped by every notify and holder lookup thereafter.
local function close_connection(self, connection)
    if not connection.dead then
        connection.dead = true
        connection.sock:close()
        forget_connection(self, connection)
        if self.admission then
            self.dispatcher:schedule(self.admission, "closed")
            self.admission = nil
        end
        assert(
            connection ~= self.phase_closer or self.subscriptions_closed or self.stopping,
            "the phase closer went away"
        )
    end
end

-- Encodes an event and its Lua argument tuple under its event schema.
local function encode_event(protocol, event, arguments, id, owner)
    local wire_event = { operation = event.name, arguments = arguments }
    wire_event.id, wire_event.owner = id, owner
    return cartesi.tojson(wire_event, -1, ensure_event_envelope_schema(protocol, event.event_schema), protocol.schemas)
        .. "\n"
end

-- One request is in flight per connection. Byte writes and protocol requests
-- have separate queues. The next request waits for the current reply or EOF.
local function send_next_event(self, connection)
    if connection.dead or connection.current_event then
        return
    end
    local queued = table.remove(connection.events, 1)
    if queued then
        connection.current_event = queued.entry
        enqueue(self, connection, queued.line)
    end
end

local function send_event(self, connection, entry, line)
    if not connection.dead then
        connection.events[#connection.events + 1] = { entry = entry, line = line }
        send_next_event(self, connection)
    end
end

-- Only initial subscriptions need a wall-clock orchestration request.
local function queue_phase_close(self, phase)
    local protocol = self.protocol
    if not self.phase_closer or phase.close_requested then
        return
    end
    phase.close_requested = true
    local entry = {
        kind = "close_phase",
        phase = phase,
        response_schema = "ClosePhaseResponse",
        pending = { [self.phase_closer] = true },
    }
    send_event(self, self.phase_closer, entry, encode_event(protocol, protocol.events.close_phase, {}))
end

-- Decoding finishes this audience member's request. Protocol acceptance waits
-- for the block barrier, so an early socket reply cannot resume a match.
local function deliver(self, entry, connection, line)
    local protocol = self.protocol
    if not entry.pending[connection] then
        return
    end
    entry.pending[connection] = nil
    local ok, decoded = pcall(
        cartesi.fromjson,
        line,
        ensure_response_envelope_schema(protocol, entry.response_schema),
        protocol.schemas
    )
    if entry.kind == "close_phase" or entry.kind == "stop" then
        assert(ok and decoded.value == true, "the phase closer did not close the phase asked")
        entry.resolved = true
        if entry.kind == "stop" then
            self.stopping = true
        else
            close_phase(self, entry.phase)
        end
        return
    end
    if ok and not decoded.skip then
        entry.replies[#entry.replies + 1] = {
            value = decoded.value,
            label = decoded.label,
            connection = connection,
            order = connection.order,
            received_at = self:get_time(),
            id = decoded.id,
        }
    end
end

-- Only one connection closes initial subscriptions. A separate invocation can stop the server.
-- Neither connection belongs to a tournament's audience.
local function announce_phase_closer(self, connection, command)
    local protocol = self.protocol
    if command == "stop" then
        connection.is_phase_closer = true
        local entry = {
            kind = "stop",
            response_schema = "ClosePhaseResponse",
            pending = { [connection] = true },
        }
        send_event(self, connection, entry, encode_event(protocol, protocol.events.close_phase, {}))
        return
    elseif command ~= nil then
        close_connection(self, connection)
        return
    end
    if self.phase_closer then
        close_connection(self, connection)
        return
    end
    connection.is_phase_closer = true
    self.phase_closer = connection
    for _, entry in ipairs(self.open_phases) do
        if entry.open then
            queue_phase_close(self, entry)
        end
    end
end

-- A connection announced itself as a player. While the initial subscription phase is open,
-- connecting subscribes it to the initial hash that phase advertises.
local function announce_player(self, connection)
    connection.is_player = true
    if self.admission then
        self.dispatcher:schedule(self.admission, "player")
        self.admission = nil
    elseif self.admitted then
        close_connection(self, connection)
        return
    end
    for _, entry in ipairs(self.open_phases) do
        if entry.subscription_hash and entry.open then
            self:subscribe_connection(entry.subscription_hash, connection)
        end
    end
end

-- The first line of a connection announces its role, once. A connection that announces again,
-- or sends anything else before announcing, is closed.
local function announce(self, connection, message)
    if connection.is_player or connection.is_phase_closer then
        close_connection(self, connection)
    elseif message.role == "phase_closer" and not self.admission and not self.admitted then
        announce_phase_closer(self, connection, message.command)
    elseif message.role == "player" then
        announce_player(self, connection)
    else
        close_connection(self, connection)
    end
end

-- Adopts a connection with a writer for bytes and a reader for its current
-- request. The first line announces the player or initial phase-closer role.
function server_meta.__index.adopt(self, sock)
    local protocol = self.protocol
    sock:settimeout(0)
    local connection = { sock = sock, outbox = {}, events = {}, order = #self.connections + 1 }
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
            trace_wire(protocol, "from player", nil, line)
            local ok, message = pcall(cartesi.fromjson, line)
            if not ok or type(message) ~= "table" then
                close_connection(self, connection)
                return
            end
            local announced = connection.is_player or connection.is_phase_closer
            if message.role or not announced then
                announce(self, connection, message)
            else
                local entry = connection.current_event
                connection.current_event = nil
                if entry then
                    deliver(self, entry, connection, line)
                end
                send_next_event(self, connection)
            end
            if connection.dead then
                return
            end
        end
    end)
    return connection
end

-- Accepts connections, adopting each as it arrives, until the game ends. The referee is never
-- told how many players to expect: it takes every one that connects until the phase closer closes
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

-- Subscribes a connection under the given hash.
function server_meta.__index.subscribe_connection(self, hash, connection)
    local set = self.subscriptions[hash]
    if not set then
        set = {}
        self.subscriptions[hash] = set
    end
    set[connection] = true
end

-- The live connections for one subscription, a list of subscriptions, or EVERYONE.
function server_meta.__index.get_subscribers(self, subscriptions)
    if subscriptions == EVERYONE then
        return self:get_players()
    end
    if type(subscriptions) ~= "table" then
        subscriptions = { subscriptions }
    end
    local seen, list = {}, {}
    for _, hash in ipairs(subscriptions) do
        local set = self.subscriptions[hash]
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

-- VG admits exactly two stable connections. Labels and claim hashes do not confer ownership.
function server_meta.__index.accept_players(self, count)
    assert(not self.admitted, "players already admitted")
    local players, index = {}, 1
    while #players < count do
        local connection = self.connections[index]
        if connection and (connection.is_player or connection.dead) then
            if connection.is_player and not connection.dead then
                players[#players + 1] = connection
            end
            index = index + 1
        else
            self.admission = coroutine.running()
            coroutine.yield()
        end
    end
    self.admitted = players
    for extra = index, #self.connections do
        close_connection(self, self.connections[extra])
    end
    return players
end

-- Registers a fixed audience and stable order without suspending the caller.
local function register_event(self, entry, conns)
    local cortn = coroutine.running()
    if not self.coroutine_order[cortn] then
        self.next_coroutine_order = self.next_coroutine_order + 1
        self.coroutine_order[cortn] = self.next_coroutine_order
    end
    self.event_order = self.event_order + 1
    entry.order = self.event_order
    entry.match_order = self.coroutine_order[cortn]
    entry.block = self:request_block()
    entry.pending, entry.replies = {}, {}
    self.active[entry] = true
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
        end
    end
end

function server_meta.__index.get_time(self)
    return self.clock.block
end

function server_meta.__index.request_block(self)
    return self.clock:request_block()
end

queue_control = function(self, conns, event, arguments, id, future)
    local entry = { pending = {}, replies = {}, response_schema = id and "Default" or event.response_schema }
    self.controls[#self.controls + 1] = entry
    entry.future = future
    local line = encode_event(self.protocol, event, arguments, id, future and true)
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
            send_event(self, connection, entry, line)
        end
    end
end

-- Replies to one request are taken in the join order of their senders, so the accepted reply,
-- the order of a collection, and any story line naming a sender never depend on arrival order.
local function reply_less(a, b)
    return a.order < b.order
end

local future_meta = { __index = {} }

-- Closing a future forgets its scheduled response, so a later arrival is stale and ignored, or
-- closes its unfinished closures.
function future_meta.__index:close()
    if self.closed then
        return
    end
    self.closed = true
    local server = self.server
    server.active[self] = nil
    if self.id then
        server.scheduled_responses[self.id] = nil
    end
    if self.tasks then
        for _, cortn in ipairs(self.tasks) do
            server.dispatcher:close(cortn)
        end
    end
    if self.cortn then
        server.dispatcher:schedule(self.cortn, self)
        self.cortn = nil
    end
end
future_meta.__close = future_meta.__index.close

-- A deadline bounds this wait only. All-response requests return a snapshot of replies
-- received before it; first-valid requests return nil if no result was accepted before it.
-- The future can still be waited on or closed.
function future_meta.__index:wait(deadline)
    assert(not self.closed, "future is closed")
    assert(not deadline or math.type(deadline) == "integer", "deadline must be a block number")
    assert(not self.cortn, "future already has a waiter")
    if not self.resolved and (not deadline or self.server:get_time() < deadline) then
        self.cortn, self.deadline = coroutine.running(), deadline
        coroutine.yield()
        self.deadline = nil
    end
    if not self.closed and self.resolved and (not deadline or self.accepted_at < deadline) then
        return self.value
    end
    if not self.closed and self.kind == "request_all" then
        local responses = {}
        for _, reply in ipairs(self.accepted_replies or self.replies) do
            if not deadline or reply.received_at < deadline then
                responses[#responses + 1] = reply
            end
        end
        table.sort(responses, reply_less)
        return responses
    end
end

-- Starts the closures concurrently, in list order. The future resolves to true when all
-- finish, including immediately for an empty list. Errors still fail the referee.
function server_meta.__index.run_all(self, functions)
    for _, f in ipairs(functions) do
        assert(type(f) == "function", "run_all expects closures")
    end
    local future = setmetatable({ kind = "run_all", server = self, tasks = {} }, future_meta)
    register_event(self, future, {})
    local remaining = #functions
    if remaining == 0 then
        future.value, future.accepted_at = true, self:get_time()
        complete_event(self, future)
    end
    for _, f in ipairs(functions) do
        future.tasks[#future.tasks + 1] = self.dispatcher:spawn(function()
            f()
            remaining = remaining - 1
            if remaining == 0 then
                future.value, future.accepted_at = true, self:get_time()
                complete_event(self, future)
            end
        end)
    end
    return future
end

-- Requests the first valid response without waiting, resolving subscriptions to a fixed audience.
-- Accepts one subscription, a list of subscriptions, or EVERYONE.
-- Its future owns only this event's responses.
-- An explicit response block sends the request as a control and registers a delayed
-- response ID. It supplies a clock boundary, not a substitute for the referee's validator.
function server_meta.__index.request_first_valid(
    self,
    subscriptions,
    event,
    event_arguments,
    accept_response,
    response_block
)
    assert(
        not response_block or (math.type(response_block) == "integer" and response_block > self:get_time()),
        "response block must be a later block"
    )
    local conns = self:get_subscribers(subscriptions)
    local future = setmetatable({
        kind = "request_first_valid",
        server = self,
        event = event,
        response_schema = event.response_schema,
        accept_response = accept_response,
    }, future_meta)
    register_event(self, future, conns)
    if response_block then
        future.id, future.eligible = future.order, response_block
        self.scheduled_responses[future.id] = future
        queue_control(self, conns, event, event_arguments, future.id)
    else
        future.line = encode_event(self.protocol, event, event_arguments)
        self.ordinary[#self.ordinary + 1] = future
    end
    return future
end

-- A VG move belongs to one admitted connection. Its ID also protects later
-- controls from stale replies on that same connection. Correctness is the game's concern.
function server_meta.__index.request_owner(self, owner, event, arguments, accept_response)
    local future = setmetatable({
        kind = "request_first_valid",
        server = self,
        owner = owner,
        event = event,
        response_schema = event.response_schema,
        accept_response = accept_response,
    }, future_meta)
    register_event(self, future, {})
    future.id = future.order
    self.scheduled_responses[future.id] = future
    queue_control(self, { owner }, event, arguments, future.id, future)
    return future
end

-- Requests every response to an ordinary event without waiting. The future resolves after
-- the block's audience finishes; a timed wait returns the responses received before its deadline.
-- An optional validator returns the accepted value. Errors, nil, and false reject a reply,
-- but its sender still counts as answered for the block barrier.
function server_meta.__index.request_all(self, subscriptions, event, event_arguments, accept_response)
    local future = setmetatable({
        kind = "request_all",
        server = self,
        response_schema = event.response_schema,
        line = encode_event(self.protocol, event, event_arguments),
        accept_response = accept_response,
        accepted_replies = accept_response and {},
    }, future_meta)
    register_event(self, future, self:get_subscribers(subscriptions))
    self.ordinary[#self.ordinary + 1] = future
    return future
end

-- Waits for a logical block's time barrier, or returns immediately if it has already been reached.
function server_meta.__index.wait_until(self, block)
    assert(math.type(block) == "integer" and block >= 0, "block must be a nonnegative block number")
    if self:get_time() >= block then
        return
    end
    local future <close> = setmetatable({ kind = "block", server = self, target_block = block }, future_meta)
    register_event(self, future, {})
    future:wait()
end

-- Accepts players subscribing to an initial hash until the phase closer closes the phase. A player
-- connection itself expresses interest in the one computation served by this referee.
function server_meta.__index.accept_subscribers(self, initial_state_hash)
    local entry = {
        kind = "request_all",
        replies = {},
        pending = {},
        open = true,
        subscription_hash = initial_state_hash,
        cortn = coroutine.running(),
    }
    self.active[entry] = true
    self.open_phases[#self.open_phases + 1] = entry
    for _, connection in ipairs(self:get_players()) do
        self:subscribe_connection(initial_state_hash, connection)
    end
    queue_phase_close(self, entry)
    coroutine.yield()
end

local function entry_less(a, b)
    return a.match_order < b.match_order or (a.match_order == b.match_order and a.order < b.order)
end

-- A response ID selects its original event schema and referee validator. A response whose
-- future has closed is stale and ignored.
local function accept_scheduled_response(self, response)
    local protocol = self.protocol
    local future = self.scheduled_responses[response.id]
    if
        not future
        or future.resolved
        or future.closed
        or future.value ~= nil
        or (future.owner and response.connection ~= future.owner)
    then
        return
    end
    local ok, decoded =
        pcall(cartesi.fromjson, cartesi.tojson(response.value, -1), future.event.response_schema, protocol.schemas)
    if not ok then
        return
    end
    local accepted, value = pcall(future.accept_response, decoded, response.label)
    if accepted and value then
        future.value, future.accepted_at = value, self:get_time()
    end
end

local function release_results(self)
    local completed = {}
    for entry in pairs(self.active) do
        if entry.kind == "block" and self:get_time() >= entry.target_block then
            entry.value, entry.accepted_at = true, self:get_time()
        elseif entry.kind == "request_all" and not entry.subscription_hash and entry.answered then
            entry.value, entry.accepted_at = entry.accepted_replies or entry.replies, self:get_time()
        end
        if entry.value ~= nil or (entry.cortn and entry.deadline and self:get_time() >= entry.deadline) then
            completed[#completed + 1] = entry
        end
    end
    table.sort(completed, entry_less)
    for _, entry in ipairs(completed) do
        if entry.value == nil then
            self.dispatcher:schedule(entry.cortn, entry)
            entry.cortn, entry.deadline = nil, nil
        else
            complete_event(self, entry)
        end
    end
end

-- Runs only between dispatcher turns, after all ready continuations have yielded.
-- A phase's whole audience must finish before its callbacks run or time advances.
function server_meta.__index.step_time(self)
    local protocol = self.protocol
    if not self.clock:barrier_ready(self.controls) then
        return
    end
    local had_owner_reply = false
    for _, control in ipairs(self.controls) do
        local future = control.future
        if future and not future.closed then
            for _, reply in ipairs(control.replies) do
                if reply.connection == future.owner and reply.id == future.id and type(reply.value) == "table" then
                    local block = reply.value.scheduled_at
                    if math.type(block) == "integer" and block > self:get_time() then
                        future.eligible = block
                    elseif reply.value.answer ~= nil then
                        accept_scheduled_response(self, {
                            id = future.id,
                            value = reply.value.answer,
                            connection = reply.connection,
                            label = reply.label,
                        })
                        had_owner_reply = true
                    end
                end
            end
        end
    end
    self.controls = {}
    if had_owner_reply then
        release_results(self)
        return true
    end
    if self.batch then
        if not self.clock:barrier_ready(self.batch) then
            return
        end
        if self.batch_kind == "time" then
            local responses = {}
            for _, entry in ipairs(self.batch) do
                for _, reply in ipairs(entry.replies) do
                    if type(reply.value) == "table" then
                        for _, response in ipairs(reply.value) do
                            if type(response) == "table" and math.type(response.id) == "integer" then
                                responses[#responses + 1] = {
                                    id = response.id,
                                    value = response.value,
                                    label = reply.label,
                                    order = reply.order,
                                    connection = reply.connection,
                                }
                            end
                        end
                    end
                end
            end
            table.sort(responses, function(a, b)
                local af, bf = self.scheduled_responses[a.id], self.scheduled_responses[b.id]
                local ae, be = af and af.eligible or 0, bf and bf.eligible or 0
                if ae ~= be then
                    return ae < be
                elseif a.id ~= b.id then
                    return a.id < b.id
                end
                return reply_less(a, b)
            end)
            for _, response in ipairs(responses) do
                accept_scheduled_response(self, response)
            end
        else
            table.sort(self.batch, entry_less)
            for _, entry in ipairs(self.batch) do
                entry.answered = true
                if entry.kind == "request_first_valid" and not entry.closed then
                    table.sort(entry.replies, reply_less)
                    for _, reply in ipairs(entry.replies) do
                        if entry.value == nil then
                            local ok, value = pcall(entry.accept_response, reply.value, reply.label)
                            if ok and value then
                                entry.value, entry.accepted_at = value, self:get_time()
                            end
                        end
                    end
                elseif entry.kind == "request_all" and entry.accept_response and not entry.closed then
                    table.sort(entry.replies, reply_less)
                    for _, reply in ipairs(entry.replies) do
                        local ok, value = pcall(entry.accept_response, reply.value, reply.label)
                        if ok and value then
                            entry.accepted_replies[#entry.accepted_replies + 1] = {
                                value = value,
                                label = reply.label,
                                connection = reply.connection,
                                order = reply.order,
                                received_at = reply.received_at,
                            }
                        end
                    end
                end
            end
        end
        self.batch = nil
        release_results(self)
        return true
    end
    if self.clock.before_ordinary then
        self.clock:begin_ordinary()
        self.batch, self.ordinary = self.ordinary, {}
        self.batch_kind = "ordinary"
        for _, entry in ipairs(self.batch) do
            assert(entry.block == self:get_time(), "ordinary request missed its block")
            if entry.closed then
                entry.pending = {}
            else
                for connection in pairs(entry.pending) do
                    send_event(self, connection, entry, entry.line)
                end
            end
        end
        return true
    end
    local boundaries = {}
    for _, entry in ipairs(self.ordinary) do
        boundaries[#boundaries + 1] = entry.block
    end
    for entry in pairs(self.active) do
        if entry.target_block then
            boundaries[#boundaries + 1] = entry.target_block
        end
        if entry.deadline then
            boundaries[#boundaries + 1] = entry.deadline
        end
    end
    for _, future in pairs(self.scheduled_responses) do
        if not future.resolved and future.eligible then
            boundaries[#boundaries + 1] = future.eligible
        end
    end
    local block = self.clock:next_block(boundaries)
    if block then
        self.clock:advance(block)
        local entry = { pending = {}, replies = {}, response_schema = "Responses" }
        self.batch, self.batch_kind = { entry }, "time"
        local line = encode_event(protocol, protocol.events.advance_time, { block })
        for _, connection in ipairs(self:get_players()) do
            entry.pending[connection] = true
            send_event(self, connection, entry, line)
        end
        return true
    end
end

-- Stops game coroutines without resuming their waits. Closing them runs their <close> locals,
-- including closing their futures. Transport coroutines remain alive to deliver finish.
local function close_referee(self, main)
    self.dispatcher:close(main)
    -- Initial subscriptions have no future owner. Also release any unowned request.
    for entry in pairs(self.active) do
        if entry.close then
            entry:close()
        else
            self.active[entry] = nil
        end
    end
end

-- Runs the referee, then sends finish and closes the connections. A phase-closer stop takes
-- the same cleanup path, closing the game coroutines while their proof waits are suspended.
function server_meta.__index.run(self, main)
    local protocol = self.protocol
    local referee_done, finishing = false, false
    local referee = coroutine.create(function()
        main()
        assert(not next(self.active), "referee finished with pending requests")
        referee_done = true
    end)
    self.dispatcher:schedule(referee, "start")
    while not self.done do
        if not finishing and (referee_done or self.stopping) then
            finishing = true
            if self.stopping then
                close_referee(self, referee)
            end
            self.dispatcher:spawn(function()
                local finished <close> = self:request_all(EVERYONE, protocol.events.finish, {})
                finished:wait()
                self.done = true
            end)
        end
        local progressed
        if self.dispatcher.ready_first > self.dispatcher.ready_last then
            progressed = self:step_time()
        end
        if not progressed then
            self.dispatcher:step()
        end
    end
    if self.listener then
        self.listener:close()
    end
    for _, connection in ipairs(self.connections) do
        connection.sock:close()
    end
end

-- Runs the listening side of the protocol. The referee itself contains only the game logic;
-- this function owns its listener, connection multiplexer, and coroutine dispatcher.
local function run_server(referee, server_address, protocol)
    local referee_server = new_server(server_address, protocol)
    referee_server:run(function()
        referee:run(referee_server)
    end)
end

return {
    new_protocol = new_protocol,
    define_event = define_event,
    new_server = new_server,
    answer_event = answer_event,
    schedule_response = schedule_response,
    run_server = run_server,
    run_client = run_client,
    new_phase_closer = new_phase_closer,
}
