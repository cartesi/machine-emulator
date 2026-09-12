-- The parts of the PRT game shared by referee and players: geometry, event schemas, claim
-- trees (frontier forests of bundle roots, opened on demand), the referee's coroutine
-- dispatcher and server, and narration. The game script supplies the match walk,
-- machines, claim builds, tournament, and verification of the disputed transition.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local hash_tree = require("cartesi.hash-tree")
local socket = require("socket")
local new_clock = require("prt-clock")
local new_response_queue = require("prt-response-queue")

-- A nil subscription audience broadcasts to every live player; an empty list reaches nobody.
local EVERYONE = nil

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
-- A claim commits to 2^height leaves. The forest stores bundle roots at their logical
-- heights. Opening a bundle reconstructs its individual state hashes and expands its
-- opaque leaf after verifying the root. Implicit repetitions share the expanded subtree.
--------------------------------------------------------------------------------

local tree_meta = { __index = {} }

-- Reconstruct an unopened bundle and install its authenticated subtree in the forest.
-- A readable state leaf means the bundle was already opened, possibly through padding.
-- docs:begin open_bundle
function tree_meta.__index.open_bundle(tree, bundle_index)
    local position = bundle_index << tree.bundle_height
    if pcall(hash_tree.frontier_forest_get_node, tree.forest, position, 0) then
        return
    end
    local bundle_forest = tree:refine(bundle_index)
    assert(bundle_forest.height == tree.bundle_height, "the opened bundle has the wrong height")
    hash_tree.frontier_forest_expand_leaf(tree.forest, position, bundle_forest)
end
-- docs:end open_bundle

-- Queries never execute a machine. Reading below an unopened bundle fails.
-- docs:begin get_tree_node
function tree_meta.__index.get_node(tree, position, height)
    return hash_tree.frontier_forest_get_node(tree.forest, position, height)
end
-- docs:end get_tree_node

function tree_meta.__index.get_root(tree)
    return hash_tree.frontier_forest_get_root_hash(tree.forest)
end

-- The two children of the node at position and height.
function tree_meta.__index.get_children(tree, position, height)
    local child_height = height - 1
    return tree:get_node(position, child_height), tree:get_node(position + (1 << child_height), child_height)
end

-- The proof of a state leaf, following a single path through the expanded forest.
function tree_meta.__index.prove(tree, index)
    return {
        target_address = index,
        log2_target_size = 0,
        target_hash = tree:get_node(index, 0),
        log2_root_size = tree.height,
        root_hash = tree:get_root(),
        sibling_hashes = hash_tree.frontier_forest_get_siblings(tree.forest, index, 0),
    }
end

-- A claim tree of 2^height leaves, with refine reconstructing one bundle on demand.
local function new_tree(height, bundle_height, forest, refine)
    assert(forest.height == height, "the forest does not match the claim height")
    return setmetatable({
        height = height,
        bundle_height = bundle_height,
        forest = forest,
        refine = refine,
    }, tree_meta)
end

-- The other turn in a two-claim match.
local function get_other_turn(turn)
    return 3 - turn
end

--------------------------------------------------------------------------------
-- Story
--
-- The referee reports semantic events; this table owns their formatting and every
-- presentation-only calculation, keeping narration out of the tournament algorithm.
--------------------------------------------------------------------------------

-- docs:begin story
local story = {}
local NOTICE = "Notice(bytes payload)"
local tournament_streams = setmetatable({}, { __mode = "k" })
local match_streams = setmetatable({}, { __mode = "k" })
local match_counts = setmetatable({}, { __mode = "k" })

local function get_tournament_stream(tournament)
    return tournament.level == "mcycle" and "tournament"
        or assert(tournament_streams[tournament], "uarch tournament has no narration stream")
end

local function get_match_stream(match)
    return assert(match_streams[match], "match has no narration stream")
end

local function get_match_label(match)
    return (get_match_stream(match):sub(#"match_" + 1):gsub("_", "."))
end

function story.report_claims(tournament)
    local stream = tournament.level == "mcycle" and "claims" or get_tournament_stream(tournament)
    for _, claim in ipairs(tournament.claims) do
        if tournament.level == "mcycle" then
            narrate("claim_hashes", "%s", cartesi.tohex(claim.computation_hash))
        end
        narrate(
            stream,
            "Claim %s, with final state %s, joined.",
            format_short_hash(claim.computation_hash),
            format_short_hash(claim.final_state_hash)
        )
    end
end

function story.report_state_transition(
    tournament,
    match,
    state_transition_offset,
    obtained_state_hash,
    next_state_hashes
)
    local form = "an ordinary uarch step"
    if
        state_transition_offset == 0
        and tournament.period_index == 0
        and tournament.dapp_contract.inputs[tournament.input_index + 1]
    then
        form = "the inclusion of input " .. tournament.input_index .. " and the first uarch step"
    elseif state_transition_offset & cartesi.UARCH_CYCLE_MAX == cartesi.UARCH_CYCLE_MAX then
        form = "a uarch step and the uarch reset closing an instruction"
    end
    narrate(get_match_stream(match), "The disputed transition is %s.", form)
    if not obtained_state_hash then
        narrate(get_match_stream(match), "No log settled the transition. Both claims are eliminated.")
        return
    end
    narrate(
        get_match_stream(match),
        "The disputed transition provably leads to %s.",
        format_short_hash(obtained_state_hash)
    )
    local winning_claim_index
    for claim_index = 1, 2 do
        if obtained_state_hash == next_state_hashes[claim_index] then
            winning_claim_index = claim_index
            break
        end
    end
    if not winning_claim_index then
        narrate(get_match_stream(match), "Neither claim committed to it. Both are eliminated.")
        return
    end
    local losing_claim_index = get_other_turn(winning_claim_index)
    local loser = match.claims[losing_claim_index]
    narrate(
        get_match_stream(match),
        "Claim %s committed to %s and is eliminated.",
        format_short_hash(loser.computation_hash),
        format_short_hash(next_state_hashes[losing_claim_index])
    )
end

function story.report_uarch_tournament(uarch_tournament, mcycle_match, agreed_state_hash)
    tournament_streams[uarch_tournament] = get_match_stream(mcycle_match)
    narrate(
        get_tournament_stream(uarch_tournament),
        "A uarch tournament opens over input %d, period %d, starting from %s.",
        uarch_tournament.input_index,
        uarch_tournament.period_index,
        format_short_hash(agreed_state_hash)
    )
end

function story.report_uarch_result(mcycle_match, winner, next_state_hashes)
    if not winner then
        narrate(get_match_stream(mcycle_match), "The uarch tournament had no winner. Both claims are eliminated.")
        return
    end
    local winning_claim_index
    for claim_index = 1, 2 do
        if winner.final_state_hash == next_state_hashes[claim_index] then
            winning_claim_index = claim_index
            break
        end
    end
    assert(winning_claim_index, "uarch winner did not settle either mcycle claim")
    local loser = mcycle_match.claims[get_other_turn(winning_claim_index)]
    narrate(
        get_match_stream(mcycle_match),
        "The uarch winner confirms %s. Claim %s is eliminated.",
        format_short_hash(winner.final_state_hash),
        format_short_hash(loser.computation_hash)
    )
end

function story.report_divergence(match, divergence)
    narrate(
        get_match_stream(match),
        "The claims diverge at state %d: %s against %s, from the agreed state %s.",
        divergence.state_index,
        format_short_hash(divergence.next_state_hashes[1]),
        format_short_hash(divergence.next_state_hashes[2]),
        format_short_hash(divergence.agreed_state_hash)
    )
end

function story.report_timeout_win(match)
    local turn_claim = match.claims[match.turn]
    local other_claim = match.claims[get_other_turn(match.turn)]
    narrate(
        get_match_stream(match),
        "Nobody opened claim %s. Claim %s claims a timeout win.",
        format_short_hash(turn_claim.computation_hash),
        format_short_hash(other_claim.computation_hash)
    )
end

function story.report_match_eliminated(match)
    narrate(get_match_stream(match), "An elimination response removes both inactive claims.")
end

function story.report_match_progress(match)
    narrate(
        get_match_stream(match),
        "Height %d: the claims first disagree within leaves [0x%x, 0x%x].",
        match.height,
        match.position,
        match.position + (1 << match.height) - 1
    )
end

function story.report_match(tournament, round, match)
    local count = (match_counts[tournament] or 0) + 1
    match_counts[tournament] = count
    local prefix = tournament.level == "mcycle" and "match" or get_tournament_stream(tournament)
    match_streams[match] = string.format("%s_%d", prefix, count)
    narrate(
        get_tournament_stream(tournament),
        "Round %d, match %s, at the %s level: claim %s against claim %s.",
        round,
        get_match_label(match),
        tournament.level,
        format_short_hash(match.claims[1].computation_hash),
        format_short_hash(match.claims[2].computation_hash)
    )
end

function story.report_round(tournament, round, matches, unmatched_claim)
    for _, match in ipairs(matches) do
        local winning_claim = match.claims[match.winner]
        if winning_claim then
            narrate(
                get_tournament_stream(tournament),
                "Match %s: claim %s wins.",
                get_match_label(match),
                format_short_hash(winning_claim.computation_hash)
            )
        else
            narrate(get_tournament_stream(tournament), "Match %s: no claim survives.", get_match_label(match))
        end
    end
    if unmatched_claim then
        narrate(
            get_tournament_stream(tournament),
            "Claim %s advances unmatched to round %d.",
            format_short_hash(unmatched_claim.computation_hash),
            round + 1
        )
    end
end

function story.report_winner(winner)
    if not winner then
        return
    end
    narrate("verdict", "Tournament winner is claim %s.", format_short_hash(winner.computation_hash))
    narrate("verdict", "Winner computation hash: %s", cartesi.tohex(winner.computation_hash))
    narrate("verdict", "Winner final state hash: %s", cartesi.tohex(winner.final_state_hash))
end

function story.report_output(output)
    local payload = evmu.decode_calldata(NOTICE, output.output, "raw").payload
    narrate("verdict", "Result proved against the final state:\n%s", payload)
end
-- docs:end story

--------------------------------------------------------------------------------
-- Coroutine dispatcher
--
-- The referee mediates several matches at once, each written as ordinary sequential code
-- inside its own coroutine. A coroutine that must wait (for a socket or an answer) yields to
-- the dispatcher. Socket readiness drives transport. Block barriers separately
-- release protocol continuations in creation order.
--------------------------------------------------------------------------------

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

--------------------------------------------------------------------------------
-- Wire protocol
--
-- Each message is one line, the compact JSON of a Lua value by cartesi.tojson plus a
-- newline. The referee emits events as {operation, arguments}, encoding the event data under
-- its schema. A player dispatches the corresponding handler against its own state and
-- answers {label, value}, encoded under the event's response schema, so binary hashes,
-- proofs, and access logs survive both directions. Schema names are local metadata, not wire
-- fields.
-- Computation responses authenticate their values against the committed claim.
-- Time requests return scheduled responses, each checked by its referee validator.
-- The label rides along only for tracing.
--------------------------------------------------------------------------------

-- The schemas used by the PRT events and private transport lifecycle.
local SCHEMA_DICT = {
    ClosePhaseEvent = { items = {} },
    ClosePhaseResponse = "Default",
    FinishEvent = { items = {} },
    FinishResponse = "Default",
    Claim = {
        computation_hash_left = "Base64",
        computation_hash_right = "Base64",
        final_state_hash_proof = "Proof",
    },
    CommitMcycleClaimEvent = { items = {} },
    CommitMcycleClaimResponse = "Claim",
    RevealBisectionEvent = { items = { "Base64", "Default", "Default", "Base64" } },
    RevealBisectionResponse = {
        turn_left_node = "Base64",
        turn_right_node = "Base64",
        turn_next_left_node = "Base64",
        turn_next_right_node = "Base64",
    },
    SealDivergenceEvent = { items = { "Base64", "Default", "Base64" } },
    SealDivergenceResponse = {
        turn_left_node = "Base64",
        turn_right_node = "Base64",
        agreed_state_hash_proof = "Proof",
    },
    NextStateHashes = { items = { "Base64", "Base64" } },
    CommitUarchClaimEvent = { items = { "Default", "Default", "NextStateHashes" } },
    CommitUarchClaimResponse = "Claim",
    ProveStateTransitionEvent = { items = { "Default", "Default", "Default" } },
    ProveStateTransitionResponse = {
        send_cmio_log = "AccessLog",
        step_log = "AccessLog",
        reset_uarch_log = "AccessLog",
    },
    ProveOutputsMerkleRootEvent = { items = {} },
    ProveOutputsMerkleRootResponse = {
        iflags_y_data = "Base64",
        iflags_y_proof = "Proof",
        htif_tohost_data = "Base64",
        htif_tohost_proof = "Proof",
        tx_buffer_data = "Base64",
        tx_buffer_proof = "Proof",
    },
    ProveOutputEvent = { items = {} },
    ProveOutputResponse = {
        output_index = "Default",
        output = "Base64",
        output_proof = "Proof",
    },
    ClaimChildren = { computation_hash_left = "Base64", computation_hash_right = "Base64" },
    GetClaimChildrenEvent = { items = { "Base64" } },
    ScheduleClaimChildrenEvent = { items = { "Default", "Base64" } },
    ScheduleEliminationEvent = { items = { "Default" } },
    Responses = { items = "Default" },
    CancelResponseEvent = { items = { "Default" } },
    AdvanceTimeEvent = { items = { "Default" } },
}

-- Describes one event once, for both ends of the wire.
local function define_event(name, event_schema, response_schema)
    return { name = name, event_schema = event_schema, response_schema = response_schema }
end

-- Scheduling events acknowledge a callback now and return its typed response later.
local function define_schedule_event(name, event_schema, response_schema)
    local event = define_event(name, event_schema, "Default")
    event.scheduled_schema = response_schema
    return event
end

local EVENTS = {
    close_phase = define_event("close_phase", "ClosePhaseEvent", "ClosePhaseResponse"),
    finish = define_event("finish", "FinishEvent", "FinishResponse"),
    commit_mcycle_claim = define_event("commit_mcycle_claim", "CommitMcycleClaimEvent", "CommitMcycleClaimResponse"),
    reveal_bisection = define_event("reveal_bisection", "RevealBisectionEvent", "RevealBisectionResponse"),
    seal_divergence = define_event("seal_divergence", "SealDivergenceEvent", "SealDivergenceResponse"),
    commit_uarch_claim = define_event("commit_uarch_claim", "CommitUarchClaimEvent", "CommitUarchClaimResponse"),
    prove_state_transition = define_event(
        "prove_state_transition",
        "ProveStateTransitionEvent",
        "ProveStateTransitionResponse"
    ),
    prove_outputs_merkle_root = define_event(
        "prove_outputs_merkle_root",
        "ProveOutputsMerkleRootEvent",
        "ProveOutputsMerkleRootResponse"
    ),
    prove_output = define_event("prove_output", "ProveOutputEvent", "ProveOutputResponse"),
    get_claim_children = define_event("get_claim_children", "GetClaimChildrenEvent", "ClaimChildren"),
    schedule_match_timeout_win = define_schedule_event(
        "schedule_match_timeout_win",
        "ScheduleClaimChildrenEvent",
        "ClaimChildren"
    ),
    schedule_match_elimination = define_schedule_event(
        "schedule_match_elimination",
        "ScheduleEliminationEvent",
        "Default"
    ),
    cancel_response = define_event("cancel_response", "CancelResponseEvent", "Default"),
    advance_time = define_event("advance_time", "AdvanceTimeEvent", "Responses"),
}

-- The envelope schema for events under a named argument schema, registered on first use.
local function ensure_event_envelope_schema(schema)
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

-- Dispatches one wire event. Finish is transport cleanup rather than a client handler, so it
-- is handled here and kept out of the client-loop snippet.
local client_queues = setmetatable({}, { __mode = "k" })
local function answer_event(client, line)
    local envelope = cartesi.fromjson(line)
    local event = assert(EVENTS[envelope.operation], "unknown event")
    local wire_event = cartesi.fromjson(line, ensure_event_envelope_schema(event.event_schema), SCHEMA_DICT)
    local queue = client_queues[client]
    if not queue then
        queue = new_response_queue()
        client_queues[client] = queue
    end
    local value
    if event == EVENTS.finish then
        value = true
    elseif event == EVENTS.advance_time then
        value = queue:advance(wire_event.arguments[1])
    elseif event == EVENTS.cancel_response then
        queue:cancel(wire_event.arguments[1])
        value = true
    else
        local handler = assert(client[wire_event.operation], "missing event handler")
        value = handler(client, table.unpack(wire_event.arguments or {}))
        if event.scheduled_schema then
            local respond = value
            assert(type(respond) == "function", "scheduling handler must return a response callback")
            queue:schedule(wire_event.id, wire_event.arguments[1], function()
                -- Encode each response with its own event schema before batching.
                return cartesi.fromjson(cartesi.tojson(respond(), -1, event.scheduled_schema, SCHEMA_DICT))
            end)
            value = true
        end
    end
    assert(value ~= nil, "the event handler produced no value")
    local response = { label = client.label, value = value }
    local encoded = cartesi.tojson(response, -1, ensure_response_envelope_schema(event.response_schema), SCHEMA_DICT)
    return encoded, event == EVENTS.finish or client.done
end

-- The player side is a plain blocking loop: announce itself, then read an event, decode its
-- arguments under the event's schema, dispatch its handler, and answer under the response
-- schema. The label is only for tracing. Computation requests go to interested holders.
-- schedule, cancel, and time requests also deliver unrelated elimination work. A missing
-- handler or result is a client bug. The referee sees EOF and loses that holder. The loop also ends when
-- the referee goes away.
-- docs:begin run_client
local function run_client(client, server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    client.connection = assert(socket.connect(host, tonumber(port)))
    local hello = client.hello or cartesi.tojson({ role = "player", label = client.label }, -1)
    assert(client.connection:send(hello .. "\n"))
    while true do
        local line = client.connection:receive("*l")
        if not line then
            break
        end
        trace_wire("from referee", client.label, line)
        local encoded, done = answer_event(client, line)
        trace_wire("to referee", client.label, encoded)
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
        close_phase = function(self)
            self.done = true
            return true
        end,
    }
    return phase_closer
end

--------------------------------------------------------------------------------
-- Referee server
--
-- Players answer one queued request at a time. Ordinary responses share a logical
-- block barrier. Schedule/cancel controls drain before the next time request.
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
local function new_server(address)
    local host, port = (address or ""):match("^(.-):(%d+)$")
    assert(not address or (host and port), "invalid server address")
    local server = setmetatable({
        dispatcher = new_dispatcher(),
        listener = address and assert(socket.bind(host, tonumber(port))),
        connections = {},
        subscriptions = {}, -- subscription hash -> set of interested connections
        active = {}, -- set of pending requests, block waits, and closure groups
        clock = new_clock(),
        ordinary = {}, -- requests for the next ordinary block
        controls = {}, -- schedule/cancel requests awaiting their replies
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
        assert(
            connection ~= self.phase_closer or self.subscriptions_closed or self.stopping,
            "the phase closer went away"
        )
    end
end

-- Encodes an event and its Lua argument tuple under its event schema.
local function encode_event(event, arguments, id)
    local wire_event = { operation = event.name, arguments = arguments }
    wire_event.id = id
    return cartesi.tojson(wire_event, -1, ensure_event_envelope_schema(event.event_schema), SCHEMA_DICT) .. "\n"
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
    send_event(self, self.phase_closer, entry, encode_event(EVENTS.close_phase, {}))
end

-- Decoding finishes this audience member's request. Protocol acceptance waits
-- for the block barrier, so an early socket reply cannot resume a match.
local function deliver(self, entry, connection, line)
    if not entry.pending[connection] then
        return
    end
    entry.pending[connection] = nil
    local ok, decoded =
        pcall(cartesi.fromjson, line, ensure_response_envelope_schema(entry.response_schema), SCHEMA_DICT)
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
            received_at = self:get_time(),
        }
    end
end

-- Only one connection closes initial subscriptions. A separate invocation can stop the server.
-- Neither connection belongs to a tournament's audience.
local function announce_phase_closer(self, connection, command)
    if command == "stop" then
        connection.is_phase_closer = true
        local entry = {
            kind = "stop",
            response_schema = "ClosePhaseResponse",
            pending = { [connection] = true },
        }
        send_event(self, connection, entry, encode_event(EVENTS.close_phase, {}))
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
    elseif message.role == "phase_closer" then
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
    sock:settimeout(0)
    local connection = { sock = sock, outbox = {}, events = {} }
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

queue_control = function(self, conns, event, arguments, id)
    local entry = { pending = {}, replies = {}, response_schema = event.response_schema }
    self.controls[#self.controls + 1] = entry
    local line = encode_event(event, arguments, id)
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
            send_event(self, connection, entry, line)
        end
    end
end

local future_meta = { __index = {} }

-- Closing a future cancels its callback on every holder or closes its unfinished closures.
function future_meta.__index:close()
    if self.closed then
        return
    end
    self.closed = true
    local server = self.server
    server.active[self] = nil
    if self.id then
        server.scheduled_responses[self.id] = nil
        queue_control(server, self.conns, EVENTS.cancel_response, { self.id })
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
function server_meta.__index.request_first_valid(self, subscriptions, event, event_arguments, accept_response)
    local conns = self:get_subscribers(subscriptions)
    local future = setmetatable({
        kind = "request_first_valid",
        server = self,
        event = event,
        conns = conns,
        response_schema = event.response_schema,
        accept_response = accept_response,
    }, future_meta)
    register_event(self, future, conns)
    if event.scheduled_schema then
        local block = event_arguments[1]
        assert(math.type(block) == "integer" and block > self:get_time(), "callback must belong to a later block")
        future.id, future.eligible = future.order, block
        self.scheduled_responses[future.id] = future
        queue_control(self, conns, event, event_arguments, future.id)
    else
        future.line = encode_event(event, event_arguments)
        self.ordinary[#self.ordinary + 1] = future
    end
    return future
end

-- Requests every response to an ordinary event without waiting. The future resolves after
-- the block's audience finishes; a timed wait returns the responses received before its deadline.
-- An optional validator returns the accepted value. Errors, nil, and false reject a reply,
-- but its sender still counts as answered for the block barrier.
function server_meta.__index.request_all(self, subscriptions, event, event_arguments, accept_response)
    assert(not event.scheduled_schema, "scheduled events require request_first_valid")
    local future = setmetatable({
        kind = "request_all",
        server = self,
        response_schema = event.response_schema,
        line = encode_event(event, event_arguments),
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

-- A response ID selects its original event schema and referee validator.
local function accept_scheduled_response(self, response)
    local future = self.scheduled_responses[response.id]
    if not future or future.resolved or future.closed or future.value ~= nil then
        return
    end
    local ok, decoded =
        pcall(cartesi.fromjson, cartesi.tojson(response.value, -1), future.event.scheduled_schema, SCHEMA_DICT)
    if not ok then
        return
    end
    local accepted, value = pcall(future.accept_response, decoded)
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
    if not self.clock:barrier_ready(self.controls) then
        return
    end
    self.controls = {}
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
                                responses[#responses + 1] = response
                            end
                        end
                    end
                end
            end
            table.sort(responses, function(a, b)
                local af, bf = self.scheduled_responses[a.id], self.scheduled_responses[b.id]
                local ae, be = af and af.eligible or 0, bf and bf.eligible or 0
                return ae < be or (ae == be and a.id < b.id)
            end)
            for _, response in ipairs(responses) do
                accept_scheduled_response(self, response)
            end
        else
            table.sort(self.batch, entry_less)
            for _, entry in ipairs(self.batch) do
                entry.answered = true
                if entry.kind == "request_first_valid" and not entry.closed then
                    for _, reply in ipairs(entry.replies) do
                        if entry.value == nil then
                            local ok, value = pcall(entry.accept_response, reply.value)
                            if ok and value then
                                entry.value, entry.accepted_at = value, self:get_time()
                            end
                        end
                    end
                elseif entry.kind == "request_all" and entry.accept_response and not entry.closed then
                    for _, reply in ipairs(entry.replies) do
                        local ok, value = pcall(entry.accept_response, reply.value)
                        if ok and value then
                            entry.accepted_replies[#entry.accepted_replies + 1] = {
                                value = value,
                                label = reply.label,
                                connection = reply.connection,
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
        if not future.resolved then
            boundaries[#boundaries + 1] = future.eligible
        end
    end
    local block = self.clock:next_block(boundaries)
    if block then
        self.clock:advance(block)
        local entry = { pending = {}, replies = {}, response_schema = "Responses" }
        self.batch, self.batch_kind = { entry }, "time"
        local line = encode_event(EVENTS.advance_time, { block })
        for _, connection in ipairs(self:get_players()) do
            entry.pending[connection] = true
            send_event(self, connection, entry, line)
        end
        return true
    end
end

-- Stops game coroutines without resuming their waits. Closing them runs their <close> locals,
-- including future cancellation. Transport coroutines remain alive to deliver finish.
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
                local finished <close> = self:request_all(EVERYONE, EVENTS.finish, {})
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
local function run_server(referee, server_address)
    local referee_server = new_server(server_address)
    referee_server:run(function()
        referee:run(referee_server)
    end)
end

return {
    EVERYONE = EVERYONE,
    SCHEMA_DICT = SCHEMA_DICT,
    define_event = define_event,
    EVENTS = EVENTS,
    story = story,
    format_short_hash = format_short_hash,
    narrate = narrate,
    new_tree = new_tree,
    get_other_turn = get_other_turn,
    new_server = new_server, -- prt-test.lua exercises the transport primitives directly
    answer_event = answer_event,
    run_server = run_server,
    run_client = run_client,
    new_phase_closer = new_phase_closer,
}
