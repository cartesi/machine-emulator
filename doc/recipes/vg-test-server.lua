-- Stop the example through the runner protocol once its supplied output offers
-- leave an indefinite proof wait suspended. Assertions belong after this call,
-- since stopping closes the referee coroutine rather than returning from its wait.
local cartesi = require("cartesi")
local vgu = require("vgu")
local run_with_server = require("game-test-server")

return function(protocol, scenario)
    local stopped_server
    run_with_server(protocol, function(server, run_client, wait_connections)
        stopped_server = server
        local step_time, stop_requested = server.step_time, false
        function server:step_time()
            local progressed = step_time(self)
            if not progressed and not stop_requested then
                for future in pairs(self.active) do
                    if
                        future.answered
                        and (future.event == vgu.EVENTS.prove_outputs_merkle_root
                            or future.event == vgu.EVENTS.prove_output)
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
        scenario(server, run_client, wait_connections)
    end)
    assert(not next(stopped_server.active), "stopping retained a proof request")
    return stopped_server
end
