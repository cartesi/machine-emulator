local cartesi = require("cartesi")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local run_with_server = require("game-test-server")
local hash = cartesi.keccak256("clock fixture")

-- The immediate player never pays for the other player's delay. The delayed
-- player carries its spent allowance into every subsequent requested move.
-- Like PRT, the deadline is start + allowance. The response budget discounts the
-- charge for an accepted answer, never extends its deadline. Expiry forfeits the
-- remaining allowance. Delays 2, 2, 0, 2 leave 3, 2, 2, then expire at the deadline.
for delayed_index = 1, 2 do
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        local players = {}
        for index = 1, 2 do
            local client = { label = "same label", block = 0, delay = 0, event_handler = {} }
            function client.event_handler:commit_final_hash()
                self.requested_at = self.block
                if self.delay == 0 then
                    return hash
                end
                return vgu.schedule_response(self, self.block + self.delay, function()
                    return hash
                end)
            end
            run_client(nil, function(wire, line)
                if wire.operation == "advance_time" then
                    client.block = wire.arguments[1]
                end
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
            players[index] = { client = client, connection = server:get_players()[index], allowance = 4 }
        end
        local delayed, immediate = players[delayed_index], players[3 - delayed_index]
        for round, delay in ipairs({ 2, 2, 0, 2 }) do
            delayed.client.delay = delay
            local replies = vg.request_hashes(server, players, vgu.EVENTS.commit_final_hash, {})
            assert(delayed.client.requested_at == immediate.client.requested_at, "hash requests were serialized")
            assert(
                replies[3 - delayed_index] == hash and immediate.allowance == 4,
                "opponent delay charged immediate player"
            )
            assert(delayed.allowance == ({ 3, 2, 2, 0 })[round])
            assert((replies[delayed_index] ~= nil) == (round < 4), "deadline is not exclusive")
        end
    end)
end

for _, behavior in ipairs({ "skip", "quit", "malformed" }) do
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        for index = 1, 2 do
            run_client(nil, function(wire)
                if wire.operation == "commit_final_hash" then
                    if behavior == "quit" then
                        return { skip = true, id = wire.id, done = true }, true
                    end
                    if behavior == "skip" then
                        return { skip = true, id = wire.id }
                    end
                    return { value = { answer = "malformed" }, id = wire.id }
                end
                return { value = wire.operation == "advance_time" and {} or true }
            end, true)
            wait_connections(index)
        end
        local referee = vg.new_referee(hash, {})
        referee:run(server)
        assert(not referee.winner and not referee.final_hash)
        assert(referee.players[1].allowance == 0 and referee.players[2].allowance == 0)
    end)
end

-- Both players receive every midpoint request, including the last midpoint of
-- each coordinate. One or both may forfeit; the final proof belongs to player 1.
local function empty_response()
    return {}
end
local empty_handlers = {
    __index = function()
        return empty_response
    end,
}
for _, failed_round in ipairs({ 1, 16, 17, 64, 65, 84, 85, 86 }) do
    for failed_player = 0, (failed_round <= 84 and 2 or 0) do
        run_with_server(vgu.protocol, function(server, run_client, wait_connections)
            local rounds, proofs = { 0, 0 }, 0
            local claims = { hash, cartesi.keccak256("other claim") }
            for index = 1, 2 do
                local client = { event_handler = setmetatable({}, empty_handlers) }
                function client.event_handler.commit_final_hash()
                    return claims[index]
                end
                function client.event_handler:commit_bisection(interval)
                    rounds[index] = rounds[index] + 1
                    local round = rounds[index]
                    assert(round <= 84, "bisection continued past the leaf")
                    local level = round <= 16 and "input" or round <= 64 and "mcycle" or "uarch_cycle"
                    local remaining = (round <= 16 and 16 or round <= 64 and 64 or 84) - round + 1
                    assert(interval.level == level and interval.lo == 0 and interval.hi == (1 << remaining))
                    assert(interval.input == (round > 16 and 0 or nil))
                    assert(interval.mcycle_offset == (round > 64 and 0 or nil))
                    if round == failed_round and (failed_player == 0 or failed_player == index) then
                        return vgu.schedule_response(self, math.maxinteger, empty_response)
                    end
                    return claims[index]
                end
                function client.event_handler:commit_log(input, mcycle_offset, uarch_cycle)
                    proofs = proofs + 1
                    assert(rounds[1] == 84 and rounds[2] == 84 and index == 1)
                    assert(input == 0 and mcycle_offset == 0 and uarch_cycle == 0, "wrong transition coordinates")
                    if failed_round == 85 then
                        return vgu.schedule_response(self, math.maxinteger, empty_response)
                    end
                    return {} -- Rejected; no valid proof arrives before the deadline.
                end
                run_client(nil, function(_, line)
                    return vgu.answer_event(client, line)
                end, true)
                wait_connections(index)
            end
            local referee = vg.new_referee(hash, {})
            referee:run(server)
            local last = math.min(failed_round, 84)
            assert(rounds[1] == last and rounds[2] == last, "requested another midpoint after settlement")
            assert(proofs == (failed_round > 84 and 1 or 0))
            if failed_player == 0 and failed_round <= 84 then
                assert(not referee.winner and not referee.final_hash)
                assert(referee.players[1].allowance == 0 and referee.players[2].allowance == 0)
            else
                local loser = failed_round > 84 and 1 or failed_player
                local winner = 3 - loser
                assert(referee.winner.index == winner and referee.final_hash == claims[winner])
                assert(referee.players[winner].allowance == 4, "charged the immediate player")
                assert(referee.players[loser].allowance == 0)
            end
        end)
    end
end
vgu.close_narration()
print("vg-clock-test: ok")
