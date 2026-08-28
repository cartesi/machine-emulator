-- Domain narration for the PRT recipe. The referee reports semantic events; this module owns
-- their formatting and every calculation needed only to explain them.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local geometry = require("prt-geometry")
local prtu = require("prtu")

local format_short_hash, narrate = prtu.format_short_hash, prtu.narrate
local NOTICE = "Notice(bytes payload)"
local UARCH_CYCLES_PER_MCYCLE = geometry.UARCH_CYCLES_PER_MCYCLE

local story = {}
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

function story.report_claims(tournament, claims)
    local stream = tournament.level == "mcycle" and "claims" or get_tournament_stream(tournament)
    for _, claim in ipairs(claims) do
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
    claim0_next_state_hash,
    claim1_next_state_hash
)
    local form = "an ordinary uarch step"
    if
        state_transition_offset == 0
        and tournament.period_index == 0
        and tournament.dapp_contract.inputs[tournament.input_index + 1]
    then
        form = "the inclusion of input " .. tournament.input_index .. " and the first uarch step"
    elseif state_transition_offset & (UARCH_CYCLES_PER_MCYCLE - 1) == UARCH_CYCLES_PER_MCYCLE - 1 then
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
    local loser, lost_state_hash
    if obtained_state_hash == claim0_next_state_hash then
        loser = match.claims[1]
        lost_state_hash = claim1_next_state_hash
    elseif obtained_state_hash == claim1_next_state_hash then
        loser = match.claims[0]
        lost_state_hash = claim0_next_state_hash
    end
    if not loser then
        narrate(get_match_stream(match), "Neither claim committed to it. Both are eliminated.")
        return
    end
    narrate(
        get_match_stream(match),
        "Claim %s committed to %s and is eliminated.",
        format_short_hash(loser.computation_hash),
        format_short_hash(lost_state_hash)
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

function story.report_uarch_result(mcycle_match, winner, claim0_next_state_hash, claim1_next_state_hash)
    if not winner then
        narrate(get_match_stream(mcycle_match), "The uarch tournament had no winner. Both claims are eliminated.")
        return
    end
    local loser
    if winner.final_state_hash == claim0_next_state_hash then
        loser = mcycle_match.claims[1]
    elseif winner.final_state_hash == claim1_next_state_hash then
        loser = mcycle_match.claims[0]
    else
        error("uarch winner did not settle either mcycle claim")
    end
    narrate(
        get_match_stream(mcycle_match),
        "The uarch winner confirms %s. Claim %s is eliminated.",
        format_short_hash(winner.final_state_hash),
        format_short_hash(loser.computation_hash)
    )
end

function story.report_divergence(match, divergence, agreed_state_hash)
    if not agreed_state_hash then
        narrate(get_match_stream(match), "Nobody proved the agreed state. Both claims are eliminated.")
        return
    end
    narrate(
        get_match_stream(match),
        "The claims diverge at state %d: %s against %s, from the agreed state %s.",
        divergence.state_index,
        format_short_hash(divergence.claim0_next_state_hash),
        format_short_hash(divergence.claim1_next_state_hash),
        format_short_hash(agreed_state_hash)
    )
end

function story.report_default_win(match)
    local turn_claim = match.claims[match.turn]
    local other_claim = match.claims[match.turn ~ 1]
    narrate(
        get_match_stream(match),
        "Nobody opened claim %s. Claim %s wins by default.",
        format_short_hash(turn_claim.computation_hash),
        format_short_hash(other_claim.computation_hash)
    )
end

function story.report_match_progress(match)
    narrate(
        get_match_stream(match),
        "Height %d: the claims first disagree within leaves [0x%x, 0x%x].",
        match.height,
        match.index << match.height,
        ((match.index + 1) << match.height) - 1
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
        format_short_hash(match.claims[0].computation_hash),
        format_short_hash(match.claims[1].computation_hash)
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
    narrate("verdict", "Tournament winner is claim %s.", format_short_hash(winner.computation_hash))
    narrate("verdict", "Winner computation hash: %s", cartesi.tohex(winner.computation_hash))
    narrate("verdict", "Winner final state hash: %s", cartesi.tohex(winner.final_state_hash))
end

function story.report_result(result)
    local payload = evmu.decode_calldata(NOTICE, result.output, "raw").payload
    narrate("verdict", "Result proved against the final state:\n%s", payload)
end

return story
