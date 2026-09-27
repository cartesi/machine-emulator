-- A counterfactual at the reply-delivery boundary. The outsider joins after
-- admission closes. Inject replies in both runs to isolate move ownership.
-- Only the second run attributes the outsider's moves to player 2 and suppresses
-- player 2's own midpoint replies. Both runs preserve the original claims, the
-- referee, and all transition proof checks.
local cartesi = require("cartesi")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local roles = require("vg-dishonest")
local run_with_server = require("vg-test-server")

local function run(initial_hash, paths, delegate)
    local honest <close> = vg.new_player(initial_hash)
    local opponent <close> = roles.new_forger(initial_hash, 2, "forged-input-2.bin")
    local fabulist <close> = roles.new_forger(initial_hash, 2, "forged-input-2.bin")
    local referee = vg.new_referee(initial_hash, paths)
    local outsider
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        local pending
        run_client(nil, function(_, line)
            return vgu.answer_event(opponent, line)
        end, true)
        wait_connections(1)
        run_client(nil, function(wire, line)
            if
                wire.operation == "initial_state"
                or wire.operation == "input_added"
                or wire.operation == "epoch_sealed"
                or wire.operation == "dispute_started"
            then
                vgu.answer_event(fabulist, line)
            end
            local response = vgu.answer_event(honest, line)
            if delegate and wire.operation == "reveal_bisection" then
                return { id = wire.id, skip = true }
            end
            return response
        end, true)
        wait_connections(2)
        local owner = server.connections[2]
        local function inject(value)
            assert(pending)
            local control = pending.control
            table.insert(control.replies, 1, {
                connection = delegate and owner or outsider,
                label = honest.label,
                order = delegate and owner.order or outsider.order,
                id = pending.future.id,
                value = { answer = value },
            })
        end
        local request_all = server.request_all
        function server:request_all(connections, event, arguments, accept)
            if event == vgu.EVENTS.initial_state then
                run_client(nil, function(wire)
                    assert(wire.operation ~= "commit_claim", "late player was asked for a claim")
                    return { value = true }
                end)
                wait_connections(4)
                outsider = self.connections[4]
            end
            local future = request_all(self, connections, event, arguments, accept)
            if event == vgu.EVENTS.reveal_bisection and future.pending[owner] then
                pending = { future = future, control = self.controls[#self.controls] }
                -- The outsider answers the honest player's midpoint requests
                -- using the forger's history.
                local response = fabulist.event_handler[event.name](fabulist, table.unpack(arguments))
                inject(cartesi.fromjson(cartesi.tojson(response, -1, event.response_schema, vgu.protocol.schemas)))
            end
            return future
        end
        run_client({ role = "phase_closer" }, function()
            return { value = true }
        end)
        referee:run(server)
        assert(not owner.dead, "the honest player disconnected during the counterfactual")
    end)
    assert(not referee.players[outsider], "the outsider was admitted as a claimant")
    vgu.close_narration()
    -- Keep each run's narration apart, so the counterfactual can be quoted from generated output.
    for _, name in ipairs({ "claims", "bisect_input", "bisect_mcycle", "bisect_uarch_cycle", "verdict" }) do
        assert(os.rename(name, string.format("fabulist-%s-%s", delegate and "delegated" or "protected", name)))
    end
    local claims = { opponent.final_hash, honest.final_hash }
    assert(#vg.addresses(referee.players) == 1 and referee.players[next(referee.players)] == referee.winner)
    assert(referee.winner.index == (delegate and 1 or 2))
    assert(referee.final_hash == claims[referee.winner.index])
    return claims
end

-- Leaves fabulist-protected-* and fabulist-delegated-* narration files and a labeled summary.
return function(initial_hash, paths)
    local protected_claims = run(initial_hash, paths, false)
    local delegated_claims = run(initial_hash, paths, true)
    for index = 1, 2 do
        assert(protected_claims[index] == delegated_claims[index], "original claim changed")
    end
    local transcript <close> = assert(io.open("fabulist-transcript", "w"))
    transcript:write(
        string.format(
            "Honest original claim: %s\nDishonest original claim: %s\n"
                .. "Ownership enforced: outsider replies rejected, honest claim wins.\n"
                .. "Broken assumption: an outsider may defend player 2's claim.\n"
                .. "The fabulist submits matching midpoint hashes on behalf of the honest player.\n"
                .. "The forger proves a transition within that agreed history; its dishonest original claim wins.\n"
                .. "Both runs retain the same original claims and transition verifier.\n",
            cartesi.tohex(protected_claims[2]),
            cartesi.tohex(protected_claims[1])
        )
    )
    print("vg-fabulist-test: both outcomes ok")
end
