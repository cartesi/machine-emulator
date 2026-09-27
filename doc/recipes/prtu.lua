-- The parts of the PRT game shared by referee and players: geometry, event schemas,
-- transport bindings and narration. The game script supplies
-- the match walk, machines, claim builds, tournament, and verification of the disputed transition.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")

-- A nil subscription audience broadcasts to every live player; an empty list reaches nobody.
local EVERYONE = nil

--------------------------------------------------------------------------------
-- Small utilities
--------------------------------------------------------------------------------

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

-- The other turn in a two-claim match.
local function get_other_turn_index(turn_index)
    return 3 - turn_index
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

function story.report_claims(tournament, responses, order)
    local labels = {}
    for _, sender in ipairs(order) do
        local hash = responses[sender].claim.computation_hash
        labels[hash] = labels[hash] or {}
        table.insert(labels[hash], sender.label)
    end
    local stream = tournament.level == "mcycle" and "claims" or get_tournament_stream(tournament)
    for _, claim in ipairs(tournament.claims) do
        narrate(
            stream,
            "Claim %s, with final state %s, joined (posted by %s).",
            format_short_hash(claim.computation_hash),
            format_short_hash(claim.final_state_hash),
            table.concat(labels[claim.computation_hash], ", ")
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
        and tournament.input_period_offset == 0
        and tournament.dapp_contract.inputs[tournament.epoch_input_offset + 1]
    then
        form = "the inclusion of input " .. tournament.epoch_input_offset .. " and the first uarch step"
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
    local losing_claim_index = get_other_turn_index(winning_claim_index)
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
        uarch_tournament.epoch_input_offset,
        uarch_tournament.input_period_offset,
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
    local loser = mcycle_match.claims[get_other_turn_index(winning_claim_index)]
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
        divergence.leaf_index,
        format_short_hash(divergence.next_state_hashes[1]),
        format_short_hash(divergence.next_state_hashes[2]),
        format_short_hash(divergence.agreed_state_hash)
    )
end

function story.report_timeout_win(match)
    local turn_claim = match.claims[match.turn_index]
    local other_claim = match.claims[get_other_turn_index(match.turn_index)]
    narrate(
        get_match_stream(match),
        "Nobody opened claim %s. Claim %s claims a timeout win.",
        format_short_hash(turn_claim.computation_hash),
        format_short_hash(other_claim.computation_hash)
    )
end

function story.report_match_eliminated(match, label)
    narrate(get_match_stream(match), "An elimination response from %s removes both inactive claims.", label)
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

local transport = require("game-transport")

local SCHEMA_DICT = {
    ClosePhaseEvent = { items = {} },
    ClosePhaseResponse = "Default",
    FinishEvent = { items = {} },
    InputAddedEvent = { items = { "Default", "Default" } },
    EpochSealedEvent = { items = { "Default" } },
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
    ScheduleClaimChildrenEvent = { items = { "Default", "Base64" } },
    ScheduleEliminationEvent = { items = { "Default" } },
    Responses = { items = "Default" },
    AdvanceTimeEvent = { items = { "Default" } },
}

-- Describes one event once, for both ends of the wire. An omitted response schema
-- declares a notification with no return value; the transport acknowledges it.
local function define_event(name, event_schema, response_schema)
    return { name = name, event_schema = event_schema, response_schema = response_schema }
end

local EVENTS = {
    close_phase = define_event("close_phase", "ClosePhaseEvent", "ClosePhaseResponse"),
    finish = define_event("finish", "FinishEvent"),
    input_added = define_event("input_added", "InputAddedEvent"),
    epoch_sealed = define_event("epoch_sealed", "EpochSealedEvent"),
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
    schedule_match_timeout_win = define_event(
        "schedule_match_timeout_win",
        "ScheduleClaimChildrenEvent",
        "ClaimChildren"
    ),
    schedule_match_elimination = define_event("schedule_match_elimination", "ScheduleEliminationEvent", "Default"),
    advance_time = define_event("advance_time", "AdvanceTimeEvent", "Responses"),
}

local protocol = transport.new_protocol(EVENTS, SCHEMA_DICT, "PRT_GAME_TRACE")
local function new_server(address)
    return transport.new_server(address, protocol)
end
local function answer_event(client, line)
    return transport.answer_event(client, line, protocol)
end
local function run_client(client, address)
    return transport.run_client(client, address, protocol)
end
local function run_server(referee, address)
    return transport.run_server(referee, address, protocol)
end
return {
    EVERYONE = EVERYONE,
    protocol = protocol,
    SCHEMA_DICT = SCHEMA_DICT,
    define_event = define_event,
    EVENTS = EVENTS,
    story = story,
    format_short_hash = format_short_hash,
    narrate = narrate,
    get_other_turn_index = get_other_turn_index,
    new_server = new_server,
    answer_event = answer_event,
    schedule_response = transport.schedule_response,
    run_server = run_server,
    run_client = run_client,
    new_phase_closer = transport.new_phase_closer,
}
