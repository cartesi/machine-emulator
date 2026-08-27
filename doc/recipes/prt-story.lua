-- Domain narration for the PRT recipe. The referee reports semantic events; this module owns
-- their formatting and every calculation needed only to explain them.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local geometry = require("prt-geometry")
local prtu = require("prtu")

local short_hash, narrate = prtu.short_hash, prtu.narrate
local NOTICE = "Notice(bytes payload)"
local UARCH_CYCLES_PER_MCYCLE = geometry.UARCH_CYCLES_PER_MCYCLE

local story = {}
local tournament_streams = setmetatable({}, { __mode = "k" })
local match_streams = setmetatable({}, { __mode = "k" })
local match_counts = setmetatable({}, { __mode = "k" })

local function tournament_stream(tournament)
    return tournament.level == "mcycle" and "tournament"
        or assert(tournament_streams[tournament], "uarch tournament has no narration stream")
end

local function match_stream(match)
    return assert(match_streams[match], "match has no narration stream")
end

local function match_label(match)
    return (match_stream(match):sub(#"match_" + 1):gsub("_", "."))
end

function story.claims_joined(tournament, claims)
    local stream = tournament.level == "mcycle" and "claims" or tournament_stream(tournament)
    for _, claim in ipairs(claims) do
        narrate(
            stream,
            "Claim %s, with final state %s, joined.",
            short_hash(claim.computation_hash),
            short_hash(claim.final_state)
        )
    end
end

function story.transition_opened(tournament, match, transition_index)
    local disputed_period = tournament.disputed_period
    local form = "an ordinary uarch step"
    if
        transition_index == 0
        and disputed_period.period_index == 0
        and tournament.dapp_contract.inputs[disputed_period.input_index + 1]
    then
        form = "the inclusion of input " .. disputed_period.input_index .. " and the first uarch step"
    elseif transition_index & (UARCH_CYCLES_PER_MCYCLE - 1) == UARCH_CYCLES_PER_MCYCLE - 1 then
        form = "a uarch step and the uarch reset closing an instruction"
    end
    narrate(match_stream(match), "The disputed transition is %s.", form)
end

function story.transition_settled(match, next_hash, winner, claim1_next_hash, claim2_next_hash)
    if not next_hash then
        narrate(match_stream(match), "No log settled the transition. Both claims are eliminated.")
        return
    end
    narrate(match_stream(match), "The disputed transition provably leads to %s.", short_hash(next_hash))
    if not winner then
        narrate(match_stream(match), "Neither claim committed to it. Both are eliminated.")
        return
    end
    local loser = winner == match.claim1 and match.claim2 or match.claim1
    local lost = winner == match.claim1 and claim2_next_hash or claim1_next_hash
    narrate(
        match_stream(match),
        "Claim %s committed to %s and is eliminated.",
        short_hash(loser.computation_hash),
        short_hash(lost)
    )
end

function story.uarch_tournament_opened(tournament, match, disputed_period, agreed_hash)
    tournament_streams[tournament] = match_stream(match)
    narrate(
        tournament_stream(tournament),
        "A uarch tournament opens over input %d, period %d, starting from %s.",
        disputed_period.input_index,
        disputed_period.period_index,
        short_hash(agreed_hash)
    )
end

function story.uarch_tournament_settled(match, winner, survivor)
    if not winner then
        narrate(match_stream(match), "The uarch tournament had no winner. Both claims are eliminated.")
        return
    end
    local loser = survivor == match.claim1 and match.claim2 or match.claim1
    narrate(
        match_stream(match),
        "The uarch winner confirms %s. Claim %s is eliminated.",
        short_hash(winner.final_state),
        short_hash(loser.computation_hash)
    )
end

function story.dispute_isolated(match, dispute, agreed_hash)
    if not agreed_hash then
        narrate(match_stream(match), "Nobody proved the agreed state. Both claims are eliminated.")
        return
    end
    narrate(
        match_stream(match),
        "The claims diverge at state %d: %s against %s, from the agreed state %s.",
        dispute.state_index,
        short_hash(dispute.claim1_next_hash),
        short_hash(dispute.claim2_next_hash),
        short_hash(agreed_hash)
    )
end

function story.default_win(match)
    narrate(
        match_stream(match),
        "Nobody opened claim %s. Claim %s wins by default.",
        short_hash(match.turn_claim.computation_hash),
        short_hash(match.other_claim.computation_hash)
    )
end

function story.match_advanced(match)
    narrate(
        match_stream(match),
        "Height %d: the claims first disagree within leaves [0x%x, 0x%x].",
        match.height,
        match.index << match.height,
        ((match.index + 1) << match.height) - 1
    )
end

function story.match_opened(tournament, round, match)
    local count = (match_counts[tournament] or 0) + 1
    match_counts[tournament] = count
    local prefix = tournament.level == "mcycle" and "match" or tournament_stream(tournament)
    match_streams[match] = string.format("%s_%d", prefix, count)
    narrate(
        tournament_stream(tournament),
        "Round %d, match %s, at the %s level: claim %s against claim %s.",
        round,
        match_label(match),
        tournament.level,
        short_hash(match.claim1.computation_hash),
        short_hash(match.claim2.computation_hash)
    )
end

function story.round_settled(tournament, claims, round, matches, results)
    for slot, match in ipairs(matches) do
        if results[slot] then
            narrate(
                tournament_stream(tournament),
                "Match %s: claim %s wins.",
                match_label(match),
                short_hash(results[slot].computation_hash)
            )
        else
            narrate(tournament_stream(tournament), "Match %s: no claim survives.", match_label(match))
        end
    end
    if #claims % 2 == 1 then
        narrate(
            tournament_stream(tournament),
            "Claim %s takes a bye to round %d.",
            short_hash(claims[#claims].computation_hash),
            round + 1
        )
    end
end

function story.tournament_winner(winner)
    narrate("verdict", "Tournament winner is claim %s.", short_hash(winner.computation_hash))
    narrate("verdict", "Winner computation hash: %s", cartesi.tohex(winner.computation_hash))
    narrate("verdict", "Winner final state hash: %s", cartesi.tohex(winner.final_state))
end

function story.result_posted(result)
    local payload = evmu.decode_calldata(NOTICE, result.output, "raw").payload
    narrate("verdict", "Result proved against the final state:\n%s", payload)
end

return story
