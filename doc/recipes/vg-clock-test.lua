local cartesi = require("cartesi")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local run_with_server = require("vg-test-server")
local hash = cartesi.keccak256("clock fixture")

-- The immediate player never pays for the other player's delay. The delayed
-- player carries its spent allowance into every subsequent requested move.
-- Like PRT, the deadline is start + allowance. The response budget discounts the
-- charge for an accepted answer, never extends its deadline. Expiry eliminates the
-- player. Delays 2, 2, 0, 2 leave 3, 2, 2, then expire at the deadline.
for delayed_index = 1, 2 do
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        local players = {}
        for index = 1, 2 do
            local client = { label = "same label", block = 0, delay = 0, event_handler = {} }
            function client.event_handler:commit_final_hash()
                self.requested_at = self.block
                self.requests = (self.requests or 0) + 1
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
            players[server:get_players()[index]] = { client = client, allowance = 4 }
        end
        local addresses = vg.addresses(players)
        local delayed_sender, immediate_sender = addresses[delayed_index], addresses[3 - delayed_index]
        local delayed, immediate = players[delayed_sender], players[immediate_sender]
        for round, delay in ipairs({ 2, 2, 0, 2 }) do
            delayed.client.delay = delay
            local replies = vg.request_hashes(server, players, vgu.EVENTS.commit_final_hash, {})
            assert(delayed.client.requested_at == immediate.client.requested_at, "hash requests were serialized")
            assert(
                replies[immediate_sender] == hash and immediate.allowance == 4,
                "opponent delay charged immediate player"
            )
            if round < 4 then
                assert(delayed.allowance == ({ 3, 2, 2 })[round])
            else
                assert(
                    players[delayed_sender] == nil and players[immediate_sender] == immediate,
                    "expired player was not removed"
                )
            end
            assert((replies[delayed_sender] ~= nil) == (round < 4), "deadline is not exclusive")
        end
        local replies = vg.request_hashes(server, players, vgu.EVENTS.commit_final_hash, {})
        assert(replies[immediate_sender] == hash and not replies[delayed_sender])
        assert(delayed.client.requests == 4 and immediate.client.requests == 5)
    end)
end

for _, behavior in ipairs({ "skip", "quit", "malformed" }) do
    local referee = vg.new_referee(hash, {})
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
        referee:run(server)
    end)
    assert(not referee.winner and not referee.final_hash)
    assert(not next(referee.players))
end

-- Both players receive every midpoint request, including the last midpoint of
-- each coordinate. Both survivors must then offer their transition proofs.
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
        local rounds, proofs = { 0, 0 }, 0
        local claims = { hash, cartesi.keccak256("other claim") }
        local referee = vg.new_referee(hash, {})
        local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections)
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
                    assert(interval.level == level and interval.lo == 0 and interval.hi == (1 << remaining) - 1)
                    assert(interval.input == (round > 16 and 0 or nil))
                    assert(interval.mcycle_offset == (round > 64 and 0 or nil))
                    if round == failed_round and (failed_player == 0 or failed_player == index) then
                        return vgu.schedule_response(self, math.maxinteger, empty_response)
                    end
                    return claims[index]
                end
                function client.event_handler:commit_log(input, mcycle_offset, uarch_cycle)
                    proofs = proofs + 1
                    assert(rounds[1] == 84 and rounds[2] == 84)
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
            referee:run(server)
        end)
        local last = math.min(failed_round, 84)
        assert(rounds[1] == last and rounds[2] == last, "requested another midpoint after settlement")
        assert(proofs == (failed_round > 84 and 2 or 0))
        if failed_player == 0 then
            assert(not referee.winner and not referee.final_hash)
            assert(not next(referee.players))
        else
            local loser = failed_player
            local winner = 3 - loser
            assert(referee.winner.index == winner and referee.final_hash == claims[winner])
            assert(#vg.addresses(referee.players) == 1)
            assert(referee.players[server.connections[winner]] == referee.winner)
            assert(referee.winner.allowance == 4, "charged the immediate player")
        end
    end
end
vgu.close_narration()
print("vg-clock-test: ok")
