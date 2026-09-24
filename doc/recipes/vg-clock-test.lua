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
run_with_server(vgu.protocol, function(server, run_client, wait_connections)
    local players = {}
    for index = 1, 2 do
        local client = { label = "same label", block = 0, delay = 0, event_handler = {} }
        function client.event_handler.commit_final_hash(self)
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
    for round, delay in ipairs({ 2, 2, 0, 2 }) do
        players[1].client.delay = delay
        local replies = vg.request_pair(server, players, vgu.EVENTS.commit_final_hash, {})
        assert(replies[2] == hash and players[2].allowance == 4, "opponent delay charged immediate player")
        assert(players[1].allowance == ({ 3, 2, 2, 0 })[round])
        assert((replies[1] ~= nil) == (round < 4), "deadline is not exclusive")
    end
end)

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
vgu.close_narration()
print("vg-clock-test: ok")
