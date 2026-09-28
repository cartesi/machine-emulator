local cartesi = require("cartesi")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local run_with_server = require("vg-test-server")
local hash = cartesi.keccak256("clock fixture")

local function empty_response()
    return {}
end
local empty_handlers = {
    __index = function()
        return empty_response
    end,
}

-- The immediate player never pays for the other player's delay. The delayed
-- player carries its spent allowance into every subsequent requested move.
-- Like PRT, the deadline is start + allowance. The response budget discounts the
-- charge for an accepted answer, never extends its deadline. Expiry eliminates the
-- player. Delays 2, 2, 0, 2 leave 3, 2, 2, then expire at the deadline.
for delayed_index = 1, 2 do
    local clients = {}
    local claims = { hash, cartesi.keccak256("other claim") }
    local dapp_contract = vg.make_dapp_contract(hash, {})
    local results
    local delayed, immediate
    run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        results = observed
        for index = 1, 2 do
            local sender
            local client = {
                label = "player " .. index,
                block = 0,
                requested_at = {},
                allowances = {},
                disputes = 0,
                event_handler = setmetatable({}, empty_handlers),
            }
            local function offer(self)
                local round = #self.requested_at + 1
                assert(round <= 4, "requested another hash after elimination")
                assert(round == 1 or self.disputes == 1, "midpoint requested before dispute started")
                self.requested_at[round] = self.block
                self.allowances[round] = round == 1 and dapp_contract.max_allowance or results.players[sender].allowance
                local delay = index == delayed_index and ({ 2, 2, 0, 2 })[round] or 0
                if delay == 0 then
                    return claims[index]
                end
                return vgu.schedule_response(self, self.block + delay, function()
                    return claims[index]
                end)
            end
            client.event_handler.commit_claim, client.event_handler.reveal_bisection = offer, offer
            function client.event_handler:dispute_started()
                assert(#self.requested_at == 1 and self.disputes == 0)
                assert(results.players[sender].allowance == (index == delayed_index and 3 or 4))
                self.disputes = self.disputes + 1
            end
            run_client({ role = "player", label = client.label }, function(wire, line)
                if wire.operation == "advance_time" then
                    client.block = wire.arguments[1]
                end
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
            sender = server:get_players()[index]
            clients[index] = client
        end
        local senders = server:get_players()
        delayed, immediate = senders[delayed_index], senders[3 - delayed_index]
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
    end)
    for round = 1, 4 do
        assert(clients[1].requested_at[round] == clients[2].requested_at[round], "hash requests were serialized")
        assert(clients[delayed_index].allowances[round] == ({ 4, 3, 2, 2 })[round])
        assert(clients[3 - delayed_index].allowances[round] == 4, "opponent delay charged immediate player")
    end
    assert(#clients[1].requested_at == 4 and #clients[2].requested_at == 4)
    assert(not results.players[delayed] and results.players[immediate] == results.winner, "deadline is not exclusive")
    assert(results.final_hash == claims[3 - delayed_index] and results.winner.allowance == 4)
    assert(results.winner.label == clients[3 - delayed_index].label, "VG lost the admitted player's label")
end

-- Repeated claims and labels still belong to separate connections. One
-- proponent's accepted midpoint cannot save another who fails to defend it.
do
    local dapp_contract = vg.make_dapp_contract(hash, {})
    local results
    local requested = {}
    local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        results = observed
        for index = 1, 3 do
            local client = { label = "same label", event_handler = setmetatable({}, empty_handlers) }
            function client.event_handler.commit_claim()
                return index <= 2 and hash or cartesi.keccak256("other claim")
            end
            function client.event_handler.reveal_bisection()
                assert(#vg.addresses(results.players) == 3, "equal claims were merged")
                requested[index] = true
                return index == 2 and hash or "malformed"
            end
            run_client({ role = "player", label = client.label }, function(_, line)
                return vgu.answer_event(client, line)
            end, true)
            wait_connections(index)
        end
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
    end)
    assert(requested[1] and requested[2] and requested[3], "a proponent was not asked to defend its claim")
    assert(#vg.addresses(results.players) == 1 and results.players[server.connections[2]] == results.winner)
    assert(results.final_hash == hash)
end

for _, behavior in ipairs({ "skip", "quit", "malformed" }) do
    local dapp_contract = vg.make_dapp_contract(hash, {})
    local results
    run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
        results = observed
        for index = 1, 2 do
            run_client({ role = "player", label = behavior .. " " .. index }, function(wire)
                if wire.operation == "commit_claim" then
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
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        vg.new_referee(dapp_contract):run(server)
    end)
    assert(not results.winner and not results.final_hash)
    assert(not next(results.players))
end

-- Both players receive every midpoint request, including the last midpoint of
-- each coordinate. Both survivors must then offer their transition proofs.
-- Proof-time failures also exercise the last transition and alternating halves.
for _, failed_round in ipairs({ 1, 16, 17, 64, 65, 84, 85, 86 }) do
    for failed_player = 0, (failed_round <= 84 and 2 or 0) do
        local rounds, proofs = { 0, 0 }, 0
        local target = {
            epoch_input_offset = failed_round == 85 and (1 << 16) - 1 or failed_round == 86 and 0xa55a or 0,
            input_mcycle_offset = failed_round == 85 and (1 << 48) - 1 or failed_round == 86 and 0xa55aa55aa55a or 0,
            uarch_cycle = failed_round == 85 and (1 << 20) - 1 or failed_round == 86 and 0xa55aa or 0,
        }
        local claims = { hash, cartesi.keccak256("other claim") }
        local dapp_contract = vg.make_dapp_contract(hash, {})
        local results
        local server = run_with_server(vgu.protocol, function(server, run_client, wait_connections, observed)
            results = observed
            for index = 1, 2 do
                local client = { label = "player " .. index, event_handler = setmetatable({}, empty_handlers) }
                function client.event_handler.commit_claim()
                    return claims[index]
                end
                function client.event_handler:reveal_bisection(agreed_position, tentative_position)
                    rounds[index] = rounds[index] + 1
                    local round = rounds[index]
                    assert(round <= 84, "bisection continued past the leaf")
                    local coordinate = round <= 16 and "epoch_input_offset"
                        or round <= 64 and "input_mcycle_offset"
                        or "uarch_cycle"
                    local remaining = (round <= 16 and 16 or round <= 64 and 64 or 84) - round + 1
                    local lo = (target[coordinate] >> remaining) << remaining
                    local mid = lo + (1 << (remaining - 1))
                    local expected = {
                        epoch_input_offset = round <= 16 and lo or target.epoch_input_offset,
                        input_mcycle_offset = round <= 16 and 0 or round <= 64 and lo or target.input_mcycle_offset,
                        uarch_cycle = round <= 64 and 0 or lo,
                    }
                    for field, offset in pairs(expected) do
                        assert(agreed_position[field] == offset, "wrong agreed position")
                        assert(tentative_position[field] == (field == coordinate and mid or offset), "wrong midpoint")
                    end
                    if round == failed_round and (failed_player == 0 or failed_player == index) then
                        return vgu.schedule_response(self, math.maxinteger, empty_response)
                    end
                    return target[coordinate] >= mid and hash or claims[index]
                end
                function client.event_handler:prove_state_transition(
                    epoch_input_offset,
                    input_mcycle_offset,
                    uarch_cycle
                )
                    proofs = proofs + 1
                    assert(rounds[1] == 84 and rounds[2] == 84)
                    assert(
                        epoch_input_offset == target.epoch_input_offset
                            and input_mcycle_offset == target.input_mcycle_offset
                            and uarch_cycle == target.uarch_cycle,
                        "wrong transition coordinates"
                    )
                    if failed_round == 85 then
                        return vgu.schedule_response(self, math.maxinteger, empty_response)
                    end
                    return {} -- Rejected; no valid proof arrives before the deadline.
                end
                run_client({ role = "player", label = client.label }, function(_, line)
                    return vgu.answer_event(client, line)
                end, true)
                wait_connections(index)
            end
            run_client({ role = "phase_closer" }, function()
                return { value = true }
            end)
            vg.new_referee(dapp_contract):run(server)
        end)
        local last = math.min(failed_round, 84)
        assert(rounds[1] == last and rounds[2] == last, "requested another midpoint after settlement")
        assert(proofs == (failed_round > 84 and 2 or 0))
        if failed_player == 0 then
            assert(not results.winner and not results.final_hash)
            assert(not next(results.players))
        else
            local loser = failed_player
            local winner = 3 - loser
            assert(results.final_hash == claims[winner])
            assert(#vg.addresses(results.players) == 1)
            assert(results.players[server.connections[winner]] == results.winner)
            assert(results.winner.allowance == 4, "charged the immediate player")
        end
    end
end
vgu.close_narration()
print("vg-clock-test: ok")
