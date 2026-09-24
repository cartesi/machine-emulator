-- A counterfactual at the reply-delivery boundary. Production admission already
-- excludes outsiders. Inject replies here in both runs to isolate move ownership.
-- Only the second run delegates player 1's pending moves to the outsider. It
-- preserves both original claims, the referee, and all transition proof checks.
local cartesi = require("cartesi")
local vg = require("rolling-verification-game")
local vgu = require("vgu")
local roles = require("vg-dishonest")
local run_with_server = require("game-test-server")

local function run(initial_hash, paths, delegate)
    local honest <close> = vg.new_player(initial_hash)
    local opponent <close> = roles.new_forger(initial_hash, 2, "forged-input-2.bin")
    local referee = vg.new_referee(initial_hash, paths)
    run_with_server(vgu.protocol, function(server, run_client, wait_connections)
        local pending, outsider
        run_client(nil, function(_, line)
            return vgu.answer_event(honest, line)
        end, true)
        wait_connections(1)
        local owner = server.connections[1]
        local function inject(value)
            assert(pending)
            local control = pending.control
            table.insert(control.replies, 1, {
                connection = outsider,
                label = honest.label,
                order = outsider.order,
                id = pending.future.id,
                value = { answer = value },
            })
        end
        run_client(nil, function(wire, line)
            local reply, done = vgu.answer_event(opponent, line)
            if wire.operation == "commit_bisection" then
                -- The fabulist agrees with the forger at every midpoint, conceding
                -- the honest player's real defense without altering its claim.
                inject(cartesi.fromjson(reply).value.answer)
            end
            return reply, done
        end, true)
        wait_connections(2)
        run_client(nil, function()
            return { value = true }
        end)
        wait_connections(3)
        outsider = server.connections[3]
        local request_owner = server.request_owner
        function server.request_owner(self, connection, event, arguments, accept)
            local future = request_owner(self, connection, event, arguments, accept)
            if connection == owner and (event == vgu.EVENTS.commit_bisection or event == vgu.EVENTS.commit_log) then
                pending = { future = future, control = self.controls[#self.controls] }
                if delegate then
                    future.owner = outsider
                end
                if event == vgu.EVENTS.commit_log then
                    inject({})
                end
            end
            return future
        end
        referee:run(server)
        assert(outsider.dead, "the outsider was admitted as a third claimant")
    end)
    vgu.close_narration()
    -- Keep each run's narration apart, so the counterfactual can be quoted from generated output.
    for _, name in ipairs({ "claims", "bisect_input", "bisect_mcycle", "bisect_uarch_cycle", "verdict" }) do
        assert(os.rename(name, string.format("fabulist-%s-%s", delegate and "delegated" or "protected", name)))
    end
    assert(referee.players[1].final_hash == honest.final_hash)
    assert(referee.players[2].final_hash == opponent.final_hash)
    assert(referee.winner.index == (delegate and 2 or 1))
    return referee
end

-- Leaves fabulist-protected-* and fabulist-delegated-* narration files and a labeled summary.
return function(initial_hash, paths)
    local protected = run(initial_hash, paths, false)
    local delegated = run(initial_hash, paths, true)
    for index = 1, 2 do
        assert(protected.players[index].final_hash == delegated.players[index].final_hash, "original claim changed")
    end
    assert(protected.transition.valid and not delegated.transition.valid)
    local transcript <close> = assert(io.open("fabulist-transcript", "w"))
    transcript:write(
        string.format(
            "Honest original claim: %s\nDishonest original claim: %s\n"
                .. "Ownership enforced: outsider replies rejected, player 1's proof verifies, honest claim wins.\n"
                .. "Broken assumption: an outsider may defend player 1's claim.\n"
                .. "The fabulist agrees with the forger's midpoints and submits a failing terminal proof.\n"
                .. "Proof verification rejects it, player 2's dishonest original claim wins.\n"
                .. "Both runs retain the same original claims and transition verifier.\n",
            cartesi.tohex(protected.players[1].final_hash),
            cartesi.tohex(protected.players[2].final_hash)
        )
    )
    print("vg-fabulist-test: both outcomes ok")
end
