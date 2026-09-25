local cartesi = require("cartesi")
local transport = require("game-transport")
local run_with_server = require("game-test-server")
local event = transport.define_event("move", "Move", "Base64")
local notification = transport.define_event("notice", "Notice")
local protocol = transport.new_protocol(
    { move = event, notice = notification },
    { Move = { items = {} }, Notice = { items = { "Default" } } }
)
local hash = string.rep("\255", 32)
local function accept(value)
    return type(value) == "string" and #value == 32 and value
end

-- A notification handler returns nothing. Its completion still participates in
-- the referee's barrier, while a request must produce its declared result.
run_with_server(protocol, function(server, run_client, wait_connections)
    local received = {}
    for index = 1, 2 do
        local client = { event_handler = {} }
        function client.event_handler.notice(_, value)
            received[index] = value
        end
        run_client(nil, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(index)
    end
    local replies <close> = server:request_all(nil, notification, { 42 })
    local acknowledgements = replies:wait()
    assert(received[1] == 42 and received[2] == 42)
    assert(#acknowledgements == 2)
    for _, reply in ipairs(acknowledgements) do
        assert(reply == true)
    end
end)

do
    local client = { event_handler = {
        move = function() end,
        notice = function()
            error("notification failed")
        end,
    } }
    local ok, err = pcall(transport.answer_event, client, cartesi.tojson({ operation = "move", arguments = {} }), protocol)
    assert(not ok and err:find("the event handler produced no value", 1, true))
    ok, err = pcall(transport.answer_event, client, cartesi.tojson({ operation = "notice", arguments = { 42 } }), protocol)
    assert(not ok and err:find("notification failed", 1, true))
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
        local future <close> = server:request_from_player(owner, event, {}, accept)
        local result = future:wait(5)
        assert(result == (delay < 5 and hash or nil))
        if delay < 5 then
            assert(future.accepted_at == delay, "clock did not stop at the chosen reply block")
        else
            assert(server:get_time() == 5, "acknowledgement extended the deadline")
        end
    end)
end

-- All validator variants expose the authenticated connection and logical receipt
-- time, while validators accepting only the original value still work above.
for _, kind in ipairs({ "first", "all", "owner", "scheduled" }) do
    run_with_server(protocol, function(server, run_client, wait_connections)
        local client = { label = "validator fixture", event_handler = {} }
        function client.event_handler.move(self)
            if kind == "scheduled" then
                return transport.schedule_response(self, 3, function()
                    return hash
                end)
            end
            return hash
        end
        run_client(nil, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(1)
        local connection = server:get_players()[1]
        local function validate(value, label, sender, received_at)
            assert(label == client.label and sender == connection)
            assert(received_at == server:get_time())
            assert(received_at == ({ owner = 0, first = 1, all = 1, scheduled = 3 })[kind])
            return accept(value)
        end
        local future <close> = kind == "first" and server:request_first_valid(nil, event, {}, validate)
            or kind == "all" and server:request_all(nil, event, {}, validate)
            or kind == "scheduled" and server:request_first_valid(nil, event, {}, validate, 3)
            or server:request_from_player(connection, event, {}, validate)
        local result = future:wait(5)
        assert((kind == "all" and result[1] or result) == hash)
    end)
end

-- A single collection enforces individual deadlines in its validator, preserves
-- join order, and cannot accept an outsider merely because it copied a label or ID.
run_with_server(protocol, function(server, run_client, wait_connections)
    local delays, deadlines = { 3, 2, 1, 5 }, { 4, 2, 3, 5 }
    local connections, index_by_connection, received = {}, {}, {}
    for index = 1, 4 do
        local client = { label = "same label", event_handler = {} }
        function client.event_handler.move(self)
            return transport.schedule_response(self, delays[index], function() return hash end)
        end
        run_client(nil, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(index)
        local connection = server:get_players()[index]
        connections[index], index_by_connection[connection] = connection, index
    end
    local collection
    local encoded_hash = cartesi.fromjson(cartesi.tojson(hash, -1, "Base64"))
    run_client(nil, function(wire)
        if wire.operation == "advance_time" then
            return { label = "same label", value = { { id = collection.id, value = encoded_hash } } }
        end
        return { value = true }
    end, true)
    wait_connections(5)
    local future <close> = server:request_all(connections, event, {}, function(value, label, connection, received_at)
        local index = assert(index_by_connection[connection], "outsider reached the validator")
        assert(label == "same label" and value == hash)
        assert(received_at == delays[index])
        received[index] = received_at
        assert(received_at < deadlines[index], "late reply")
        return index
    end)
    collection = future
    local control = server.controls[#server.controls]
    control.replies[#control.replies + 1] = {
        connection = server:get_players()[5],
        label = "same label",
        id = future.id,
        value = { answer = encoded_hash },
        order = 5,
    }
    local replies = future:wait(5)
    assert(#replies == 2 and replies[1] == 1 and replies[2] == 3)
    assert(received[1] == 3 and received[3] == 1)
    assert(received[2] == 2 and received[4] == 5, "deadlines were not checked by the validator")
end)

-- Rejecting a reply leaves its sender eligible to retry. Acceptance is once per
-- sender, even if it sends the same valid response again later.
run_with_server(protocol, function(server, run_client, wait_connections)
    local client = { event_handler = {} }
    function client.event_handler.move(self)
        transport.schedule_response(self, 1, function() return "invalid" end)
        transport.schedule_response(self, 2, function() return hash end)
        return transport.schedule_response(self, 3, function() return hash end)
    end
    run_client(nil, function(_, line)
        return transport.answer_event(client, line, protocol)
    end, true)
    wait_connections(1)
    local calls = 0
    local future <close> = server:request_all(server:get_players(), event, {}, function(value, _, connection, received_at)
        assert(connection == server:get_players()[1] and received_at == server:get_time())
        calls = calls + 1
        return accept(value)
    end)
    assert(#future:wait(1) == 0)
    assert(#future:wait(2) == 0, "collection deadline is not exclusive")
    local replies = future:wait(5)
    assert(#replies == 1 and replies[1] == hash)
    server:wait_until(3)
    assert(calls == 2, "duplicate reply reached the validator")
end)

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
    local future <close> = server:request_from_player(owner, event, {}, accept)
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
    local later <close> = server:request_from_player(owner, event, {}, accept)
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

-- Referee errors unwind its suspended resources and close all transport handles.
do
    local server, future, closed
    local ok, err = pcall(run_with_server, protocol, function(s)
        server = s
        local resource <close> = setmetatable({}, { -- luacheck: ignore 211
            __close = function()
                closed = true
            end,
        })
        future = s:request_first_valid({}, event, {}, accept, 3)
        error("deliberate referee error")
    end)
    assert(not ok and err:find("deliberate referee error", 1, true))
    assert(closed and future.closed and not next(server.active))
    assert(not server.listener:getsockname())
end

-- A stale or duplicate immediate reply on the owner's socket must not consume
-- the next request. Send all three lines together to exercise stream framing.
run_with_server(protocol, function(server, run_client, wait_connections)
    local client = { event_handler = {
        move = function()
            return hash
        end,
    } }
    local previous
    run_client(nil, function(wire, line)
        local reply, done = transport.answer_event(client, line, protocol)
        if wire.operation == "move" then
            local result = (previous and previous .. "\n" or "") .. reply .. "\n" .. reply
            previous = reply
            return result, done
        end
        return reply, done
    end, true)
    wait_connections(1)
    for _ = 1, 2 do
        local future <close> = server:request_from_player(server:get_players()[1], event, {}, accept)
        assert(future:wait(server:get_time() + 5) == hash)
    end
end)
-- An unannounced EOF is a failed simulation, not a player's timeout. Both an
-- ordinary barrier and an owner control must fail immediately and unwind resources.
for _, owned in ipairs({ false, true }) do
    local server, future
    local ok, err = pcall(run_with_server, protocol, function(s, run_client, wait_connections)
        server = s
        run_client(nil, function()
            return "close"
        end, true)
        wait_connections(1)
        local pending <close> = owned and s:request_from_player(s:get_players()[1], event, {}, accept)
            or s:request_first_valid(nil, event, {}, accept)
        future = pending
        pending:wait(5)
        error("connection loss was treated as a timeout")
    end)
    assert(not ok and err:find("unexpected connection loss", 1, true))
    assert(future.closed and not next(server.active) and not server.listener:getsockname())
end
print("game-transport-test: ok")
