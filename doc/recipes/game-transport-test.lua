local cartesi = require("cartesi")
local transport = require("game-transport")
local run_with_server = require("game-test-server")
local FOREVER = nil
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
        run_client({ role = "player", label = client.label }, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(index)
    end
    local replies <close> = server:request_all(nil, notification, { 42 })
    local acknowledgements, order = replies:wait_at_most(FOREVER)
    assert(replies.closed and not server.active[replies])
    assert(not pcall(replies.wait_at_most, replies), "a consumed future accepted another wait")
    assert(received[1] == 42 and received[2] == 42)
    assert(#order == 2)
    for index, sender in ipairs(order) do
        assert(sender == server:get_players()[index] and acknowledgements[sender] == true)
    end
    local block = server:get_time()
    assert(select("#", server:notify_all(nil, notification, { 43 })) == 0)
    assert(received[1] == 43 and received[2] == 43, "notification returned before its handlers completed")
    assert(server:get_time() == block, "notification advanced logical time")
    assert(not next(server.active), "notification left an active future")
    assert(not pcall(server.notify_all, server, nil, event, {}), "notification accepted a response-bearing event")
end)

do
    local client = {
        event_handler = {
            move = function() end,
            notice = function()
                error("notification failed")
            end,
        },
    }
    local ok, err =
        pcall(transport.answer_event, client, cartesi.tojson({ operation = "move", arguments = {} }), protocol)
    assert(not ok and err:find("the event handler produced no value", 1, true))
    ok, err =
        pcall(transport.answer_event, client, cartesi.tojson({ operation = "notice", arguments = { 42 } }), protocol)
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
        run_client({ role = "player", label = client.label }, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(1)
        local owner = server:get_players()[1]
        local future <close> = server:request_from_player(owner, event, {}, accept)
        local result = future:wait_at_most(5)
        assert(result == (delay < 5 and hash or nil))
        assert(future.closed and not server.active[future] and not server.scheduled_responses[future.id])
        if delay < 5 then
            assert(future.accepted_at == math.max(delay, 1), "clock did not stop at the chosen reply block")
        else
            assert(server:get_time() == 5, "acknowledgement extended the deadline")
        end
        if delay > 5 then
            server:wait_until(delay)
            assert(future.value == nil, "a reply after expiry was accepted")
        end
    end)
end

-- All validator variants expose the connection's announced label and logical receipt
-- time. A response cannot rename its sender, and normal responses omit the label.
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
        run_client({ role = "player", label = client.label }, function(_, line)
            local encoded, done = transport.answer_event(client, line, protocol)
            local response = cartesi.fromjson(encoded)
            assert(response.label == nil, "response repeated the sender label")
            response.label = "forged response label"
            return response, done
        end, true)
        wait_connections(1)
        local connection = server:get_players()[1]
        assert(connection.label == client.label, "announcement lost the sender label")
        client.label = "changed after announcement"
        local function validate(value, sender, received_at)
            assert(sender.label == "validator fixture" and sender == connection)
            assert(received_at == server:get_time())
            assert(received_at == ({ owner = 1, first = 1, all = 1, scheduled = 3 })[kind])
            return accept(value)
        end
        local future <close> = kind == "first" and server:request_first_valid(nil, event, {}, validate)
            or kind == "all" and server:request_all(nil, event, {}, validate)
            or kind == "scheduled" and server:request_first_valid(nil, event, {}, validate)
            or server:request_from_player(connection, event, {}, validate)
        local result = future:wait_at_most(5)
        assert((kind == "all" and result[connection] or result) == hash)
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
            return transport.schedule_response(self, delays[index], function()
                return hash
            end)
        end
        run_client({ role = "player", label = client.label }, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(index)
        local connection = server:get_players()[index]
        connections[index], index_by_connection[connection] = connection, index
    end
    local collection
    local encoded_hash = cartesi.fromjson(cartesi.tojson(hash, -1, "Base64"))
    run_client({ role = "player", label = "same label" }, function(wire)
        if wire.operation == "advance_time" then
            return { value = { { id = collection.id, value = encoded_hash } } }
        end
        return { value = true }
    end, true)
    wait_connections(5)
    local future <close> = server:request_all(connections, event, {}, function(value, connection, received_at)
        local index = assert(index_by_connection[connection], "outsider reached the validator")
        assert(connection.label == "same label" and value == hash)
        assert(received_at == delays[index])
        received[index] = received_at
        assert(received_at < deadlines[index], "late reply")
        return index
    end)
    collection = future
    local control = server.controls[#server.controls]
    control.replies[#control.replies + 1] = {
        connection = server:get_players()[5],
        id = future.id,
        value = { answer = encoded_hash },
        order = 5,
    }
    local replies, order = future:wait_at_most(5)
    assert(#order == 2 and order[1] == connections[1] and order[2] == connections[3])
    assert(replies[connections[1]] == 1 and replies[connections[3]] == 3)
    assert(not replies[connections[2]] and not replies[connections[4]] and not replies[server:get_players()[5]])
    assert(received[1] == 3 and received[3] == 1)
    assert(received[2] == 2 and received[4] == 5, "deadlines were not checked by the validator")
end)

-- Expiry returns the accepted prefix and unregisters the remaining replies.
run_with_server(protocol, function(server, run_client, wait_connections)
    local delays, validated = { 1, 3, 4 }, {}
    for index, delay in ipairs(delays) do
        local client = { event_handler = {} }
        function client.event_handler.move(self)
            return transport.schedule_response(self, delay, function()
                return hash
            end)
        end
        run_client({ role = "player", label = client.label }, function(_, line)
            return transport.answer_event(client, line, protocol)
        end, true)
        wait_connections(index)
    end
    local connections = server:get_players()
    local future = server:request_all(connections, event, {}, function(value, connection)
        validated[connection] = true
        return accept(value)
    end)
    local replies, order = future:wait_at_most(3)
    assert(#order == 1 and order[1] == connections[1] and replies[connections[1]] == hash)
    assert(not replies[connections[2]] and not replies[connections[3]], "collection deadline is not exclusive")
    assert(future.closed and not server.active[future] and not server.scheduled_responses[future.id])
    server:wait_until(4)
    assert(not validated[connections[3]], "a reply after expiry reached the validator")
    assert(#order == 1 and not replies[connections[3]], "a late reply changed the returned collection")
end)

-- Rejecting a reply leaves its sender eligible to retry. Acceptance is once per
-- sender, even if it sends the same valid response again later.
run_with_server(protocol, function(server, run_client, wait_connections)
    local client = { event_handler = {} }
    function client.event_handler.move(self)
        transport.schedule_response(self, 1, function()
            return "invalid"
        end)
        transport.schedule_response(self, 2, function()
            return hash
        end)
        return transport.schedule_response(self, 3, function()
            return hash
        end)
    end
    run_client({ role = "player", label = client.label }, function(_, line)
        return transport.answer_event(client, line, protocol)
    end, true)
    wait_connections(1)
    local calls = 0
    local future <close> = server:request_all(server:get_players(), event, {}, function(value, connection, received_at)
        assert(connection == server:get_players()[1] and received_at == server:get_time())
        calls = calls + 1
        return accept(value)
    end)
    local replies, order = future:wait_at_most(5)
    assert(#order == 1 and order[1] == server:get_players()[1] and replies[order[1]] == hash)
    assert(future.closed and not pcall(future.wait_at_most, future), "a consumed future accepted another wait")
    server:wait_until(3)
    assert(calls == 2, "duplicate reply reached the validator")
end)

-- A copied label, a valid ID and a valid hash confer no ownership. Both immediate
-- controls and scheduled batches retain the actual connection. Stale and duplicate
-- answers cannot consume a later request.
run_with_server(protocol, function(server, run_client, wait_connections)
    local owner_client = { label = "honest", event_handler = {} }
    function owner_client.event_handler.move(self)
        if server:get_time() >= 3 then
            assert(not pcall(transport.schedule_response, self, 3, function()
                return hash
            end))
            return "invalid"
        end
        return transport.schedule_response(self, 3, function()
            return hash
        end)
    end
    run_client({ role = "player", label = owner_client.label }, function(_, line)
        return transport.answer_event(owner_client, line, protocol)
    end, true)
    wait_connections(1)
    local owner = server:get_players()[1]
    local future <close> = server:request_from_player(owner, event, {}, accept)
    run_client({ role = "player", label = "honest" }, function(wire)
        if wire.operation == "advance_time" then
            return {
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
    assert(future:wait_at_most(5) == hash and future.accepted_at == 3)
    assert(future.closed, "waiting did not close the owner's request")
    local later <close> = server:request_from_player(owner, event, {}, accept)
    assert(later.id ~= future.id)
    -- The old response ID cannot resolve this later request.
    assert(later:wait_at_most(5) == nil)
end)

-- Admission closes externally, regardless of player count. Players arriving
-- during admission are included; later connections cannot enter the fixed list.
for _, count in ipairs({ 0, 1, 3 }) do
    run_with_server(protocol, function(server, run_client, wait_connections)
        run_client({ role = "phase_closer" }, function()
            for _ = 1, count do
                run_client({ role = "player", label = "same label" }, function()
                    return { value = true }
                end)
            end
            wait_connections(count + 1)
            return { value = true }
        end)
        local admitted = server:accept_subscribers(hash)
        assert(#admitted == count and #server.open_phases == 0)
        for index, connection in ipairs(admitted) do
            assert(connection == server.connections[index + 1] and not connection.dead)
            assert(connection.label == "same label", "admission lost the sender label")
            assert(server.subscriptions[hash][connection], "admitted player was not subscribed")
        end
        run_client(nil, function()
            return { value = true }
        end)
        wait_connections(count + 2)
        assert(#admitted == count and #server:get_players() == count + 1)
        assert(#server:get_subscribers(hash) == count, "late player entered the initial subscription")
    end)
end

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
        future = s:request_first_valid({}, event, {}, accept)
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
    run_client({ role = "player", label = client.label }, function(wire, line)
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
        assert(future:wait_at_most(server:get_time() + 5) == hash)
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
        pending:wait_at_most(5)
        error("connection loss was treated as a timeout")
    end)
    assert(not ok and err:find("unexpected connection loss", 1, true))
    assert(future.closed and not next(server.active) and not server.listener:getsockname())
end
-- A lower-bound wait owns both its result and its clock boundary. Early results
-- remain valid, a result at the boundary is accepted, and later results keep it waiting.
for _, response_block in ipairs({ 1, 3, 5 }) do
    for _, already_received in ipairs({ false, true }) do
        run_with_server(protocol, function(server, run_client, wait_connections)
            local client = { event_handler = {} }
            function client.event_handler.move(self)
                assert(server:get_time() == 0, "event delivery advanced the clock")
                if response_block == 1 then
                    return hash
                end
                return transport.schedule_response(self, response_block, function()
                    return hash
                end)
            end
            run_client(nil, function(_, line)
                return transport.answer_event(client, line, protocol)
            end, true)
            wait_connections(1)
            local future <close> = server:request_first_valid(nil, event, {}, accept)
            if already_received then
                server:wait_until(response_block)
                assert(future.resolved and future.accepted_at == response_block)
            end
            assert(future:wait_at_least(3) == hash)
            assert(server:get_time() == math.max(3, response_block))
            assert(future.accepted_at == response_block, "lower bound changed the receipt block")
            assert(future.closed and not pcall(future.wait_at_most, future, FOREVER))
            assert(not pcall(future.wait_at_least, future, 3))
        end)
    end
end

-- Different lower bounds share the clock, including results collected before any
-- bound is reached. Collections retain both return values; groups retain true.
run_with_server(protocol, function(server, run_client, wait_connections)
    local client = { event_handler = {
        move = function()
            return hash
        end,
    } }
    run_client(nil, function(_, line)
        return transport.answer_event(client, line, protocol)
    end, true)
    wait_connections(1)
    local order = {}
    local function wait_for(block)
        local future <close> = server:request_first_valid(nil, event, {}, accept)
        assert(future:wait_at_least(block) == hash)
        order[#order + 1] = server:get_time()
    end
    local group <close> = server:run_all({
        function()
            wait_for(8)
        end,
        function()
            wait_for(3)
        end,
        function()
            wait_for(5)
        end,
    })
    assert(group:wait_at_least(9))
    assert(table.concat(order, ",") == "3,5,8" and server:get_time() == 9)
    local collection <close> = server:request_all(nil, event, {}, accept)
    local values, senders = collection:wait_at_least(12)
    assert(#senders == 1 and values[senders[1]] == hash and server:get_time() == 12)
    assert(collection.accepted_at == 10, "lower bound changed collection completion time")
end)

-- The proof deadline may precede elimination, as with unequal uarch clocks.
-- No unrelated coroutine is needed to reach the later elimination block.
run_with_server(protocol, function(server, run_client, wait_connections)
    local client = { event_handler = {} }
    function client.event_handler.move(self)
        return transport.schedule_response(self, 5, function()
            return hash
        end)
    end
    run_client(nil, function(_, line)
        return transport.answer_event(client, line, protocol)
    end, true)
    wait_connections(1)
    local elimination <close> = server:request_first_valid(nil, event, {}, function(value)
        assert(server:get_time() >= 5, "early elimination")
        return accept(value)
    end)
    local proof <close> = server:request_first_valid({}, event, {}, accept)
    assert(proof:wait_at_most(2) == nil and server:get_time() == 2)
    assert(elimination:wait_at_least(5) == hash and server:get_time() == 5)
end)

-- Closing a lower-bound wait releases its coroutine and removes its clock boundary.
run_with_server(protocol, function(server)
    local future, resumed
    local group <close> = server:run_all({
        function()
            future = server:request_first_valid({}, event, {}, accept)
            assert(future:wait_at_least(10) == nil)
            resumed = server:get_time()
        end,
    })
    server:wait_until(2)
    assert(not pcall(future.wait_at_most, future, FOREVER), "a second waiter was accepted")
    assert(not pcall(future.wait_at_least, future, 3), "a second lower-bound waiter was accepted")
    future:close()
    assert(group:wait_at_most(FOREVER) and resumed == 2)
    assert(not next(server.active) and not next(server.scheduled_responses))
end)

-- Bounds are block numbers; FOREVER is valid only as an upper bound.
run_with_server(protocol, function(server)
    local future <close> = server:run_all({})
    for _, invalid in ipairs({ false, -1, 1.5, "3" }) do
        assert(not pcall(future.wait_at_most, future, invalid))
        assert(not pcall(future.wait_at_least, future, invalid))
    end
    assert(not pcall(future.wait_at_least, future, FOREVER))
    assert(future:wait_at_least(0))
end)

print("game-transport-test: ok")
