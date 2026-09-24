local cartesi = require("cartesi")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local get_other_turn_index = vgu.get_other_turn_index
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
        function client.event_handler:commit_final_hash()
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
        local replies = {}
        for index, player in ipairs(players) do
            replies[index] = vg.request_move(server, player, vgu.EVENTS.commit_final_hash, {}, function(value)
                return value == hash and value
            end)
        end
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

-- Once both claims exist, the first missed turn settles the game even if both
-- players stop answering. Alternation continues across coordinate boundaries;
-- the last response replaces the next midpoint with a transition proof.
local function empty_response()
    return {}
end
local empty_handlers = {
    __index = function()
        return empty_response
    end,
}
for _, failed_turn in ipairs({ 1, 2, 16, 17, 18, 64, 65, 66, 84, 85, 86 }) do
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        local turns, interval = 0, { level = "input", lo = 0, hi = 1 << 16 }
        local claims = { hash, cartesi.keccak256("other claim") }
        for index = 1, 2 do
            local client = { event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_final_hash()
                return claims[index]
            end
            local function answer(_, branch, received_interval, midpoint_hash, terminal)
                turns = turns + 1
                assert(index == 1 + turns % 2, "turns did not alternate")
                local level = turns <= 17 and "input" or turns <= 65 and "mcycle" or "uarch_cycle"
                assert(received_interval.level == level, "wrong bisection handoff")
                for key, value in pairs(interval) do
                    assert(received_interval[key] == value, "wrong bisection coordinate")
                end
                assert(branch == (turns <= 2 and "start" or "disagree"))
                assert(
                    (turns == 1 and midpoint_hash == nil)
                        or (turns > 1 and midpoint_hash == claims[get_other_turn_index(index)])
                )
                assert(terminal == (turns == 85), "wrong terminal request")
                if turns > 1 then
                    interval = vg.advance_interval(interval, false)
                end
                if turns >= failed_turn then
                    return vgu.schedule_response(client, math.maxinteger, empty_response)
                end
                if terminal then
                    assert(interval.level == "uarch_cycle" and interval.hi - interval.lo == 1)
                    return { agree = false, log = {} } -- Rejected; no valid proof arrives before the deadline.
                end
                return { agree = false, midpoint_hash = claims[index] }
            end
            function client.event_handler:commit_bisection(branch, received_interval, midpoint_hash)
                return answer(self, branch, received_interval, midpoint_hash, false)
            end
            function client.event_handler:commit_log(branch, received_interval, midpoint_hash)
                return answer(self, branch, received_interval, midpoint_hash, true)
            end
            run_client(nil, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        local referee = vg.new_referee(hash, {})
        referee:run(server)
        local last = math.min(failed_turn, 85)
        local loser = 1 + last % 2
        local winner = get_other_turn_index(loser)
        assert(turns == last, "requested another turn after settlement")
        assert(referee.winner.index == winner and referee.final_hash == claims[winner])
        assert(referee.players[winner].allowance == 4, "charged the inactive player")
        assert(referee.players[loser].allowance == 0)
    end)
end
vgu.close_narration()
print("vg-clock-test: ok")
