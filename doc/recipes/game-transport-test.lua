local cartesi = require("cartesi")
local transport = require("game-transport")
local run_with_server = require("game-test-server")
local event = transport.define_event("move", "Move", "Base64")
local protocol = transport.new_protocol({ move = event }, { Move = { items = {} } })
local hash = string.rep("\255", 32)
local function accept(value)
    return type(value) == "string" and #value == 32 and value
end

for _, delay in ipairs({ 0, 2, 5, 6 }) do
    run_with_server(protocol, function(server, run_client, wait_connections)
        local client = { label = "owner", event_handler = {} }
        function client.event_handler.move(self)
            if delay == 0 then
                return hash
            end
            return transport.schedule_response(self, delay, function()
                return hash
            end)
        end
        run_client(nil, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(1)
        local owner = server:get_players()[1]
        local future <close> = server:request_owner(owner, event, {}, accept)
        local result = future:wait(5)
        assert(result == (delay < 5 and hash or nil))
        if delay < 5 then
            assert(future.accepted_at == delay, "clock did not stop at the chosen reply block")
        else
            assert(server:get_time() == 5, "acknowledgement extended the deadline")
        end
    end)
end

-- A copied label, a valid ID and a valid hash confer no ownership. Both immediate
-- controls and scheduled batches retain the actual connection. Stale and duplicate
-- answers cannot consume a later request.
run_with_server(protocol, function(server, run_client, wait_connections)
    local owner_client = { label = "honest", event_handler = {} }
    function owner_client.event_handler.move(self)
        return transport.schedule_response(self, 3, function()
            return hash
        end)
    end
    run_client(nil, function(_, line)
        return transport.answer_event(owner_client, line, protocol)
    end, true)
    wait_connections(1)
    local owner = server:get_players()[1]
    local future <close> = server:request_owner(owner, event, {}, accept)
    run_client(nil, function(wire)
        if wire.operation == "advance_time" then
            return {
                label = "honest",
                value = { { id = future.id, value = cartesi.tojson(hash, -1, "Base64"):sub(2, -2) } },
            }
        end
        return { value = true }
    end, true)
    wait_connections(2)
    local attacker = server:get_players()[2]
    -- A transport fixture injects a forged immediate reply before the owner replies.
    local control = server.controls[1]
    control.replies[#control.replies + 1] = {
        connection = attacker,
        id = future.id,
        value = { answer = "forged" },
        order = 2,
    }
    server:wait_until(1)
    assert(future.value == nil, "outsider answered the owner's move")
    assert(future:wait(5) == hash and future.accepted_at == 3)
    future:close()
    local later <close> = server:request_owner(owner, event, {}, accept)
    assert(later.id ~= future.id)
    -- The owner schedules at an already visited block. It cannot resolve this request.
    assert(later:wait(5) == nil)
end)

run_with_server(protocol, function(server, run_client, wait_connections)
    for _ = 1, 3 do
        run_client(nil, function()
            return { value = true }
        end)
    end
    wait_connections(3)
    local admitted = server:accept_players(2)
    assert(admitted[1] == server.connections[1] and admitted[2] == server.connections[2])
    assert(server.connections[3].dead)
end)
print("game-transport-test: ok")
