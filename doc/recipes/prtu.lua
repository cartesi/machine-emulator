-- The parts of the PRT game shared by referee and players: geometry, event schemas, claim
-- trees (frontier forests of bundle roots, opened on demand), the referee's coroutine
-- dispatcher and server, and narration. The game script supplies the match walk,
-- machines, claim builds, tournament, and verification of the disputed transition.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local hash_tree = require("cartesi.hash-tree")
local socket = require("socket")
local new_clock = require("prt-clock")
local new_actions = require("prt-actions")

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
-- A claim commits to 2^height leaves, the state hashes of a computation hash, delivered
-- bundled: the machine reports one bundle root per 2^bundle_height leaves, so the claim
-- stores an outer frontier forest that much shallower, holding bundle roots at its level
-- zero. A query that descends below a bundle opens it: refine(tree, bundle_index) builds
-- the complete forest of the leaves under that one bundle by re-running a machine through
-- its window, exactly as a machine produces the disputed transition's logs. The opened
-- forest is checked against the committed bundle root and cached, and nothing else of the
-- tree is ever materialized.
--------------------------------------------------------------------------------

local tree_meta = { __index = {} }

-- Opens one bundle: asks refine for the complete forest of the leaves under it, verifies
-- that forest against the committed bundle root, and caches it. Only the bundles a dispute
-- actually visits are ever opened, and each costs one machine re-run.
-- docs:begin open_bundle
function tree_meta.__index.open_bundle(tree, bundle_index)
    local bundle_forest = tree.opened[bundle_index]
    if not bundle_forest then
        bundle_forest = tree:refine(bundle_index)
        assert(
            hash_tree.frontier_forest_get_root_hash(bundle_forest)
                == hash_tree.frontier_forest_get_node(tree.outer, bundle_index, 0),
            "the opened bundle does not match its committed root"
        )
        tree.opened[bundle_index] = bundle_forest
    end
    return bundle_forest
end
-- docs:end open_bundle

-- The node at height whose first covered leaf is position. At or above bundle_height it is
-- a node of the outer forest. Below, its bundle must have been opened explicitly before the
-- query, so an innocent-looking tree read never hides a machine re-run.
-- docs:begin get_tree_node
function tree_meta.__index.get_node(tree, position, height)
    if height >= tree.bundle_height then
        return hash_tree.frontier_forest_get_node(
            tree.outer,
            position >> tree.bundle_height,
            height - tree.bundle_height
        )
    end
    local bundle_index = position >> tree.bundle_height
    local bundle_forest = assert(tree.opened[bundle_index], "claim bundle has not been opened")
    return hash_tree.frontier_forest_get_node(bundle_forest, position & ((1 << tree.bundle_height) - 1), height)
end
-- docs:end get_tree_node

function tree_meta.__index.get_root(tree)
    return hash_tree.frontier_forest_get_root_hash(tree.outer)
end

-- The two children of the node at position and height.
function tree_meta.__index.get_children(tree, position, height)
    local child_height = height - 1
    return tree:get_node(position, child_height), tree:get_node(position + (1 << child_height), child_height)
end

-- The proof of a leaf index, in the standard cartesi.hash-tree representation. The bundle
-- forest appends its siblings first, then the outer forest appends the bundle siblings into
-- the same array. Claim-tree addresses are logical leaf indices, so their target size is
-- zero and their root size is the tree height.
function tree_meta.__index.prove(tree, index)
    local siblings = {}
    if tree.bundle_height > 0 then
        local bundle_index = index >> tree.bundle_height
        local bundle_forest = assert(tree.opened[bundle_index], "claim bundle has not been opened")
        hash_tree.frontier_forest_get_siblings(bundle_forest, index & ((1 << tree.bundle_height) - 1), 0, siblings)
    end
    hash_tree.frontier_forest_get_siblings(tree.outer, index >> tree.bundle_height, 0, siblings)
    return {
        target_address = index,
        log2_target_size = 0,
        target_hash = tree:get_node(index, 0),
        log2_root_size = tree.height,
        root_hash = tree:get_root(),
        sibling_hashes = siblings,
    }
end

-- A claim tree of 2^height leaves over an outer forest of bundle roots, with
-- refine(tree, bundle_index) opening the complete forest under one bundle on demand.
local function new_tree(height, bundle_height, outer, refine)
    assert(outer.height == height - bundle_height, "the outer forest does not match the claim height")
    return setmetatable({
        height = height,
        bundle_height = bundle_height,
        outer = outer,
        refine = refine,
        opened = {},
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

function story.report_uarch_result_consumed(mcycle_match, winner)
    narrate(
        get_match_stream(mcycle_match),
        "The uarch winner %s was not propagated before its deadline. An eliminate call removes both parent claims.",
        format_short_hash(winner.final_state_hash)
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
    narrate(get_match_stream(match), "An eliminate call removes both inactive claims.")
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

function story.report_result(result)
    if not result then
        return
    end
    local payload = evmu.decode_calldata(NOTICE, result.output, "raw").payload
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
    PropagateChildEvent = { items = "Base64" },
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
    propagate_child = define_event("propagate_child", "PropagateChildEvent", "ClaimChildren"),
    schedule_child_propagation = define_schedule_event(
        "schedule_child_propagation",
        "GetClaimChildrenEvent",
        "ClaimChildren"
    ),
    schedule_timeout_win = define_schedule_event("schedule_timeout_win", "GetClaimChildrenEvent", "ClaimChildren"),
    schedule_match_elimination = define_schedule_event("schedule_match_elimination", "FinishEvent", "Default"),
    schedule_child_elimination = define_schedule_event("schedule_child_elimination", "FinishEvent", "Default"),
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
        queue = new_actions()
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
            queue:schedule(wire_event.id, wire_event.eligible, wire_event.expires, function()
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

-- The phase closer is a separate transport role with one handler: closing the next phase.
-- It closes initial subscriptions and may then disconnect. Claim collection uses logical time.
local function new_phase_closer()
    local phase_closer = {
        label = "phase_closer",
        hello = cartesi.tojson({ role = "phase_closer" }, -1),
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
-- completes an obligation, even when all its holders skip or disconnect.
-- Initial subscriptions still need an external close because connections arrive
-- over wall-clock time. Tournament joining closes at a supplied logical boundary.
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
        subscriptions = {}, -- routing hash -> set of connections interested in defending it
        active = {}, -- set of events whose coroutines are waiting
        clock = new_clock(),
        ordinary = {}, -- requests for the next ordinary block
        controls = {}, -- schedule/cancel requests awaiting their replies
        routes = {}, -- scheduled response ID -> validator and pending emit
        scheduled = {}, -- coroutine -> responses belonging to its next emit
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

-- Completing a request cancels every scheduled response competing to satisfy it.
local function complete_event(self, entry)
    entry.resolved = true
    self.active[entry] = nil
    for _, route in ipairs(entry.scheduled or {}) do
        self.routes[route.id] = nil
        queue_control(self, route.conns, EVENTS.cancel_response, { route.id })
    end
    if entry.cortn then
        self.dispatcher:schedule(entry.cortn, entry)
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
        assert(connection ~= self.phase_closer or self.subscriptions_closed, "the phase closer went away")
    end
end

-- Encodes an event and its Lua argument tuple under its event schema.
local function encode_event(event, arguments, scheduled)
    local wire_event = { operation = event.name, arguments = arguments }
    if scheduled then
        wire_event.id, wire_event.eligible, wire_event.expires = scheduled.id, scheduled.eligible, scheduled.expires
    end
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
    if entry.kind == "close_phase" then
        assert(ok and decoded.value == true, "the phase closer did not close the phase asked")
        entry.resolved = true
        close_phase(self, entry.phase)
        return
    end
    if ok and not decoded.skip then
        entry.replies[#entry.replies + 1] = { value = decoded.value, label = decoded.label, connection = connection }
    end
end

-- A connection announced itself as the phase closer. There is one, the first to announce,
-- and it is never part of a tournament's audience. It closes initial subscriptions only.
local function announce_phase_closer(self, connection)
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
        announce_phase_closer(self, connection)
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

-- Subscribes a connection to events routed by a state or computation hash.
function server_meta.__index.subscribe_connection(self, root, connection)
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

-- Registers a fixed audience. Dispatch is deferred until its ordinary block.
local function park(self, entry, conns, line)
    entry.cortn = coroutine.running()
    if not self.coroutine_order[entry.cortn] then
        self.next_coroutine_order = self.next_coroutine_order + 1
        self.coroutine_order[entry.cortn] = self.next_coroutine_order
    end
    self.event_order = self.event_order + 1
    entry.order = self.event_order
    entry.match_order = self.coroutine_order[entry.cortn]
    entry.block = self:request_block()
    entry.pending, entry.replies = {}, {}
    entry.line = line
    self.active[entry] = true
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
        end
    end
    self.ordinary[#self.ordinary + 1] = entry
end

function server_meta.__index.get_time(self)
    return self.clock.block
end

function server_meta.__index.request_block(self)
    return self.clock:request_block()
end

queue_control = function(self, conns, event, arguments, scheduled)
    local entry = { pending = {}, replies = {}, response_schema = event.response_schema }
    self.controls[#self.controls + 1] = entry
    local line = encode_event(event, arguments, scheduled)
    for _, connection in ipairs(conns) do
        if not connection.dead then
            entry.pending[connection] = true
            send_event(self, connection, entry, line)
        end
    end
end

-- Scheduled responses compete with the next ordinary request from this coroutine.
function server_meta.__index.schedule(self, conns, event, arguments, block, accept_response, expires)
    assert(event.scheduled_schema, "expected a scheduling event")
    assert(block > self:request_block(), "scheduled response must belong to a later block")
    local cortn = coroutine.running()
    local scheduled = self.scheduled[cortn] or {}
    self.scheduled[cortn] = scheduled
    self.event_order = self.event_order + 1
    local route = {
        id = self.event_order,
        event = event,
        conns = conns,
        eligible = block,
        expires = expires,
        accept_response = accept_response,
    }
    self.routes[route.id] = route
    scheduled[#scheduled + 1] = route
    queue_control(self, conns, event, arguments, route)
    return route.id
end

function server_meta.__index.emit(self, conns, event, event_arguments, accept_response)
    local cortn = coroutine.running()
    local entry = {
        kind = "emit",
        response_schema = event.response_schema,
        accept_response = accept_response,
        scheduled = self.scheduled[cortn],
    }
    self.scheduled[cortn] = nil
    for _, route in ipairs(entry.scheduled or {}) do
        route.entry = entry
    end
    park(self, entry, conns, encode_event(event, event_arguments))
    return (coroutine.yield()).value
end

-- Optional outputs and other collections still complete after their audience.
function server_meta.__index.collect(self, conns, event, event_arguments)
    local entry = { kind = "collect", response_schema = event.response_schema }
    park(self, entry, conns or self:get_players(), encode_event(event, event_arguments))
    return (coroutine.yield()).replies
end

-- Accepts players subscribing to an initial hash until the phase closer closes the phase. A player
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
        self:subscribe_connection(initial_state_hash, connection)
    end
    queue_phase_close(self, entry)
    coroutine.yield()
end

-- Claim gathering uses the referee-supplied closure, for root and child alike.
-- docs:begin collect_claims
function server_meta.__index.collect_claims(self, conns, event, event_arguments, close_block)
    assert(close_block > self:request_block(), "joining must close after its opening block")
    local entry = { kind = "collect", response_schema = event.response_schema, close_block = close_block }
    park(self, entry, conns, encode_event(event, event_arguments))
    return (coroutine.yield()).replies
end
-- docs:end collect_claims

local function entry_less(a, b)
    return a.match_order < b.match_order or (a.match_order == b.match_order and a.order < b.order)
end

-- A response ID selects its original event schema and referee validator.
local function route_response(self, response)
    local route = self.routes[response.id]
    if not route or not route.entry or route.entry.resolved or route.entry.value ~= nil then
        return
    end
    local ok, decoded =
        pcall(cartesi.fromjson, cartesi.tojson(response.value, -1), route.event.scheduled_schema, SCHEMA_DICT)
    if not ok then
        return
    end
    local accepted, value = pcall(route.accept_response, decoded)
    if accepted and value then
        route.entry.value = value
    end
end

local function release_results(self)
    local completed = {}
    for entry in pairs(self.active) do
        if not entry.subscription_hash and entry.answered then
            if entry.kind == "emit" then
                if entry.value ~= nil or not entry.scheduled then
                    completed[#completed + 1] = entry
                end
            elseif not entry.close_block or self:get_time() >= entry.close_block then
                completed[#completed + 1] = entry
            end
        end
    end
    table.sort(completed, entry_less)
    for _, entry in ipairs(completed) do
        complete_event(self, entry)
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
                local ar, br = self.routes[a.id], self.routes[b.id]
                local ae, be = ar and ar.eligible or 0, br and br.eligible or 0
                return ae < be or (ae == be and a.id < b.id)
            end)
            for _, response in ipairs(responses) do
                route_response(self, response)
            end
        else
            table.sort(self.batch, entry_less)
            for _, entry in ipairs(self.batch) do
                entry.answered = true
                if entry.kind == "emit" then
                    for _, reply in ipairs(entry.replies) do
                        if entry.value == nil then
                            local ok, value = pcall(entry.accept_response, reply.value)
                            if ok and value then
                                entry.value = value
                            end
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
            for connection in pairs(entry.pending) do
                send_event(self, connection, entry, entry.line)
            end
        end
        return true
    end
    local boundaries = {}
    for _, entry in ipairs(self.ordinary) do
        boundaries[#boundaries + 1] = entry.block
    end
    for entry in pairs(self.active) do
        if entry.close_block then
            boundaries[#boundaries + 1] = entry.close_block
        end
    end
    for _, route in pairs(self.routes) do
        if route.entry then
            boundaries[#boundaries + 1] = route.eligible
            if route.expires then
                boundaries[#boundaries + 1] = route.expires
            end
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

-- Runs the referee: spawns its main logic, releases every remaining player when it is done,
-- then closes the listener and connections. Socket closing remains the fallback for peers that
-- are not sent the finish event, including the phase closer.
function server_meta.__index.run(self, main)
    self.dispatcher:spawn(function()
        main()
        self:collect(nil, EVENTS.finish, {})
        self.done = true
    end)
    while not self.done do
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
