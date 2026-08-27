-- Domain narration for the PRT recipe. The referee reports semantic events; this module owns
-- their formatting and every calculation needed only to explain them.

local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local prtu = require("prtu")

local short_hash, narrate = prtu.short_hash, prtu.narrate
local NOTICE = "Notice(bytes payload)"

local M = {}

function M.new(uarch_cycles_per_mcycle)
    local story = {}

    function story.claims_joined(tag, claims)
        for _, claim in ipairs(claims) do
            narrate(
                tag,
                "Claim %s, with final state %s, joined.",
                short_hash(claim.root),
                short_hash(claim.final_state)
            )
        end
    end

    function story.transition_opened(tournament, m, transition_index)
        local disputed_period = tournament.disputed_period
        local form = "an ordinary uarch step"
        if
            transition_index == 0
            and disputed_period.period_index == 0
            and tournament.dapp_contract.inputs[disputed_period.input_index + 1]
        then
            form = "the inclusion of input " .. disputed_period.input_index .. " and the first uarch step"
        elseif transition_index & (uarch_cycles_per_mcycle - 1) == uarch_cycles_per_mcycle - 1 then
            form = "a uarch step and the uarch reset closing an instruction"
        end
        narrate(m.tag, "The disputed transition is %s.", form)
    end

    function story.transition_settled(m, hash, winner, d1, d2)
        if not hash then
            narrate(m.tag, "No log settled the transition. Both claims are eliminated.")
            return
        end
        narrate(m.tag, "The disputed transition provably leads to %s.", short_hash(hash))
        if not winner then
            narrate(m.tag, "Neither claim committed to it. Both are eliminated.")
            return
        end
        local loser = winner == m.one and m.two or m.one
        local lost = winner == m.one and d2 or d1
        narrate(m.tag, "Claim %s committed to %s and is eliminated.", short_hash(loser.root), short_hash(lost))
    end

    function story.uarch_tournament_opened(m, disputed_period, agree_hash)
        narrate(
            m.tag,
            "A uarch tournament opens over input %d, period %d, starting from %s.",
            disputed_period.input_index,
            disputed_period.period_index,
            short_hash(agree_hash)
        )
    end

    function story.uarch_tournament_settled(m, winner, survivor)
        if not winner then
            narrate(m.tag, "The uarch tournament had no winner. Both claims are eliminated.")
            return
        end
        local loser = survivor == m.one and m.two or m.one
        narrate(
            m.tag,
            "The uarch winner confirms %s. Claim %s is eliminated.",
            short_hash(winner.final_state),
            short_hash(loser.root)
        )
    end

    function story.dispute_isolated(m, dispute, agree_hash)
        if not agree_hash then
            narrate(m.tag, "Nobody proved the agreed state. Both claims are eliminated.")
            return
        end
        narrate(
            m.tag,
            "The claims diverge at leaf %d: %s against %s, from the agreed state %s.",
            dispute.leaf_index,
            short_hash(dispute.d1),
            short_hash(dispute.d2),
            short_hash(agree_hash)
        )
    end

    function story.default_win(m)
        narrate(
            m.tag,
            "Nobody opened claim %s. Claim %s wins by default.",
            short_hash(m.turn.root),
            short_hash(m.other.root)
        )
    end

    function story.match_advanced(m)
        narrate(
            m.tag,
            "Height %d: the claims first disagree within leaves [0x%x, 0x%x].",
            m.height,
            m.index << m.height,
            ((m.index + 1) << m.height) - 1
        )
    end

    function story.match_opened(tournament, round, m)
        narrate(
            tournament.tag,
            "Round %d, match %s, at the %s level: claim %s against claim %s.",
            round,
            m.id,
            tournament.level,
            short_hash(m.one.root),
            short_hash(m.two.root)
        )
    end

    function story.round_settled(tournament, claims, round, matches, results)
        for slot, m in ipairs(matches) do
            if results[slot] then
                narrate(tournament.tag, "Match %s: claim %s wins.", m.id, short_hash(results[slot].root))
            else
                narrate(tournament.tag, "Match %s: no claim survives.", m.id)
            end
        end
        if #claims % 2 == 1 then
            narrate(tournament.tag, "Claim %s takes a bye to round %d.", short_hash(claims[#claims].root), round + 1)
        end
    end

    function story.tournament_winner(winner)
        narrate("verdict", "Tournament winner is claim %s.", short_hash(winner.root))
        narrate("verdict", "Winner claim root: %s", cartesi.tohex(winner.root))
        narrate("verdict", "Winner final state hash: %s", cartesi.tohex(winner.final_state))
    end

    function story.result_posted(result)
        local payload = evmu.decode_calldata(NOTICE, result.output, "raw").payload
        narrate("verdict", "Result proved against the final state:\n%s", payload)
    end

    return story
end

return M
