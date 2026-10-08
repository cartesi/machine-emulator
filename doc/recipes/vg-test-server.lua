-- Stop the example through the runner protocol once its supplied output offers
-- leave an indefinite proof wait suspended. Assertions belong after this call,
-- since stopping closes the referee coroutine rather than returning from its wait.
local cartesi = require("cartesi")
local vgu = require("vgu")
local run_with_server = require("game-test-server")

-- Observe the same results consumed by the referee without exposing its local tournament state.
local function observe_result(future, results, field)
    local wait = future.wait_at_most
    function future:wait_at_most(deadline)
        local value, order = wait(self, deadline)
        results[field] = value
        return value, order
    end
end

return function(protocol, scenario)
    local results = { players = {} }
    local narration <close> = setmetatable({ report_winner = vgu.story.report_winner }, {
        __close = function(saved)
            vgu.story.report_winner = saved.report_winner
        end,
    })
    function vgu.story.report_winner(winner)
        results.winner = winner
        results.final_state_hash = winner and winner.final_state_hash
        narration.report_winner(winner)
    end
    local stopped_server
    run_with_server(protocol, function(server, run_client, wait_connections)
        stopped_server = server
        local request_all = server.request_all
        function server:request_all(audience, event, arguments, accept)
            local future = request_all(self, audience, event, arguments, accept)
            if
                event == vgu.EVENTS.commit_claim
                or event == vgu.EVENTS.reveal_bisection
                or event == vgu.EVENTS.prove_state_transition
            then
                observe_result(future, results, "players")
            end
            return future
        end
        local request_first_valid = server.request_first_valid
        function server:request_first_valid(audience, event, arguments, accept)
            local future = request_first_valid(self, audience, event, arguments, accept)
            if event == vgu.EVENTS.prove_outputs_merkle_root then
                observe_result(future, results, "outputs_root")
            elseif event == vgu.EVENTS.prove_output then
                observe_result(future, results, "output")
            end
            return future
        end
        local step_time, stop_requested = server.step_time, false
        function server:step_time()
            local progressed = step_time(self)
            if not progressed and not stop_requested and not self.batch and #self.controls == 0 then
                for future in pairs(self.active) do
                    if
                        future.event == vgu.EVENTS.prove_outputs_merkle_root
                        or future.event == vgu.EVENTS.prove_output
                    then
                        assert(future.cortn and not future.deadline, "output wait is not indefinite")
                        stop_requested = true
                        local closer = vgu.new_phase_closer("stop")
                        run_client(cartesi.fromjson(closer.hello), function(_, line)
                            return vgu.answer_event(closer, line)
                        end, true)
                        return true
                    end
                end
            end
            return progressed
        end
        scenario(server, run_client, wait_connections, results)
    end)
    assert(not next(stopped_server.active), "stopping retained a proof request")
    return stopped_server
end
