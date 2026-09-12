-- Deadline regressions exercise the real referee, player handlers, and transport.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local prtu = require("prtu")
local keccak = cartesi.keccak256
local EVERYONE = prtu.EVERYONE

local function copy(value)
    if type(value) ~= "table" then
        return value
    end
    local result = {}
    for key, field in pairs(value) do
        result[key] = copy(field)
    end
    return result
end

local function repeated_tree(value, height)
    local forest = hash_tree.frontier_forest(height, "keccak256")
    for _ = 1, 1 << height do
        hash_tree.frontier_forest_push_back(forest, value)
    end
    return prtu.new_tree(height, 0, forest)
end

return function(run_with_server)
    -- Time waits advance to their requested block, but do not suspend or emit another
    -- time request when the requested block has already been reached.
    run_with_server(function(server, run_client, wait_connections)
        local blocks = {}
        run_client(nil, function(event)
            if event.operation == "advance_time" then
                blocks[#blocks + 1] = event.arguments[1]
                return { value = {} }
            end
            assert(event.operation == "finish", "a time wait emitted a player request")
            return { value = true }, true
        end, true)
        wait_connections(1)
        for _, invalid in ipairs({ -1, 1.5, "1" }) do
            assert(not pcall(server.wait_until, server, invalid), "an invalid block was accepted")
        end
        local yielded = false
        server.dispatcher:spawn(function()
            yielded = true
        end)
        server:wait_until(0)
        assert(not yielded, "waiting for the current block suspended the caller")
        server:wait_until(3)
        assert(yielded and server:get_time() == 3)
        server:wait_until(2)
        server:wait_until(3)
        assert(server:get_time() == 3)
        server:wait_until(10)
        assert(server:get_time() == 10)
        assert(#blocks == 2 and blocks[1] == 3 and blocks[2] == 10, "time waits added an unexpected block")
    end)

    -- A bridge can observe new blocks while responses are still missing. Exercise that
    -- future state directly, independently of the documentation's response barrier.
    do
        local server = prtu.new_server()
        local collection <close> = server:request_all({}, prtu.define_event("probe"), {})
        local first_valid <close> = server:request_first_valid({}, prtu.define_event("probe"), {}, function(v)
            return v
        end)
        server.clock:advance(1)
        local first = { value = "first", received_at = server:get_time() }
        collection.replies[#collection.replies + 1] = first
        server.clock:advance(2)
        local snapshot = collection:wait(2)
        assert(#snapshot == 1 and snapshot[1] == first, "expiry discarded responses already received")
        assert(first_valid:wait(2) == nil, "first-valid expiry returned a collection")
        local at_deadline = { value = "at deadline", received_at = server:get_time() }
        collection.replies[#collection.replies + 1] = at_deadline
        assert(#snapshot == 1, "a late response changed an expired wait's snapshot")
        assert(#collection:wait(2) == 1, "a response at the deadline entered the collection")
        server.clock:advance(3)
        collection.replies[#collection.replies + 1] = { value = "late", received_at = server:get_time() }
        local later = collection:wait(3)
        assert(#later == 2 and later[2] == at_deadline, "a later wait did not retain earlier replies")
        assert(#collection:wait(2) == 1, "a response after the deadline entered the collection")
        local empty <close> = server:request_all({}, prtu.define_event("probe"), {})
        assert(#empty:wait(3) == 0, "expiry without responses did not return an empty list")
    end

    -- Collection and time waits can happen in either order. Both obey
    -- the response barriers, including delayed skips, disconnects, and time acknowledgements.
    for _, block_first in ipairs({ false, true }) do
        run_with_server(function(server, run_client, wait_connections)
            local collected, closed = false, false
            local opening = server:request_block()
            local close_block = opening + 1
            run_client(nil, function(event)
                assert(event.operation == "probe", "a cancelled collection was dispatched")
                return { value = "answer" }
            end)
            run_client(nil, function(event)
                if event.operation == "finish" then
                    return { value = true }, true
                elseif event.operation == "advance_time" then
                    for _ = 1, 3 do
                        if event.arguments[1] <= close_block then
                            assert(not closed, "the time wait bypassed the time barrier")
                        end
                        server.dispatcher:schedule(coroutine.running(), "delay")
                        coroutine.yield()
                    end
                    return { value = {} }
                end
                assert(event.operation == "probe", "a cancelled collection was dispatched")
                for _ = 1, 3 do
                    assert(not collected and not closed, "a future bypassed the collection barrier")
                    assert(server:get_time() == opening, "time advanced before the audience finished")
                    server.dispatcher:schedule(coroutine.running(), "delay")
                    coroutine.yield()
                end
                return { skip = true }
            end, true)
            run_client(nil, function(event)
                assert(event.operation == "probe", "a cancelled collection was dispatched")
                return "close"
            end)
            wait_connections(3)
            for _, connection in ipairs(server:get_players()) do
                server:subscribe_connection("audience", connection)
            end
            server:subscribe_connection("overlap", server.connections[1])
            local collection <close> = server:request_all({ "audience", "overlap" }, prtu.define_event("probe"), {})
            local cancelled <close> = server:request_all(EVERYONE, prtu.define_event("cancelled_collection"), {})
            cancelled:close()
            assert(server:get_time() == 0, "request_all suspended the caller")
            run_client(nil, function()
                error("a late subscriber received the existing collection")
            end)
            wait_connections(4)
            server:subscribe_connection("audience", server.connections[4])
            if block_first then
                server:wait_until(close_block)
                closed = true
            end
            local responses = collection:wait(close_block)
            collected = true
            assert(
                responses and #responses == 1 and responses[1].value == "answer",
                "collection lost, duplicated, or broadened its responses"
            )
            assert(responses[1].connection == server.connections[1], "collection lost its sender")
            assert(responses[1].received_at == opening, "collection lost its receipt block")
            if not block_first then
                assert(server:get_time() == opening, "collection waited for the closing block")
                server:wait_until(close_block)
                closed = true
            end
            assert(server:get_time() == close_block)
            assert(collection:wait() == responses, "a collected result was not retained")
            local empty <close> = server:request_all({}, prtu.define_event("probe"), {})
            assert(#empty:wait(close_block) == 0)
            assert(#empty:wait() == 0, "an empty collection did not resolve to an empty list")
        end)
    end

    -- Main must not leave an unanswered future behind, even after a timed wait.
    for _, deadline in ipairs({ false, 1 }) do
        local server = prtu.new_server()
        local ok, err = pcall(server.run, server, function()
            local future = server:request_first_valid(
                {},
                prtu.EVENTS.schedule_match_elimination,
                { 1 },
                function(response)
                    return response
                end
            )
            if deadline then
                assert(future:wait(deadline) == nil)
            end
        end)
        assert(not ok and err:find("referee finished with pending requests"), "an unclosed future escaped detection")
    end

    -- No scheduled acknowledgement means no elimination, even after the deadline.
    do
        local server = prtu.new_server()
        local resumed = false
        server.dispatcher:spawn(function()
            local elimination <close> = server:request_first_valid(
                {},
                prtu.EVENTS.schedule_match_elimination,
                { 3 },
                function(response)
                    assert(response == true)
                    return 0
                end
            )
            elimination:wait()
            resumed = true
        end)
        local ok, err = pcall(function()
            while true do
                if server.dispatcher.ready_first <= server.dispatcher.ready_last or not server:step_time() then
                    server.dispatcher:step()
                end
            end
        end)
        assert(not ok and err:find("would block forever") and not resumed)
        assert(next(server.active), "an unanswered future completed without a response")
    end

    -- Route premature, expired, forged, and duplicate responses to independent waiters.
    do
        local server = prtu.new_server()
        local resumed, checked, ids = {}, {}, {}
        local function schedule(name, block, expires)
            local future = server:request_first_valid(
                {},
                prtu.EVENTS.schedule_match_elimination,
                { block },
                function(response)
                    checked[#checked + 1] = { name, server:get_time() }
                    assert(server:get_time() >= block and (not expires or server:get_time() < expires))
                    assert(response == true)
                    return 0
                end
            )
            ids[name] = future.id
            return future
        end
        for index = 1, 2 do
            server.dispatcher:spawn(function()
                if index == 1 then
                    local timeout <close> = schedule("timeout", 3, 4)
                    local elimination <close> = schedule("eliminate", 5)
                    local reveal <close> = server:request_first_valid(
                        {},
                        prtu.EVENTS.reveal_bisection,
                        { keccak("claim"), 0, 3, keccak("left") },
                        function()
                            error("another event supplied a reveal response")
                        end
                    )
                    assert(reveal:wait(2) == nil)
                    assert(timeout:wait(4) == nil)
                    assert(elimination:wait() == 0)
                else
                    local unrelated <close> = schedule("unrelated", 6)
                    assert(unrelated:wait() == 0)
                end
                assert(not resumed[index])
                resumed[index] = server:get_time()
            end)
        end
        local injected = {}
        while not resumed[2] do
            local block = server:get_time()
            if server.batch_kind == "time" and server.batch and not injected[block] then
                injected[block] = true
                local responses = {}
                local function offer(name, value)
                    responses[#responses + 1] =
                        { id = ids[name], value = value, eligible = 0, expires = math.maxinteger }
                end
                if block == 1 or block == 4 then
                    offer("timeout", true)
                    offer("eliminate", true)
                elseif block == 3 then
                    responses = { { id = -1, value = true }, { id = "forged", value = true }, false }
                    offer("timeout", false)
                elseif block == 5 then
                    offer("eliminate", true)
                    offer("eliminate", true)
                    offer("unrelated", true)
                elseif block == 6 then
                    assert(resumed[1] == 5 and not resumed[2])
                    offer("eliminate", true)
                    offer("unrelated", true)
                    offer("unrelated", true)
                end
                server.batch[1].replies = { { value = responses } }
            end
            if server.dispatcher.ready_first <= server.dispatcher.ready_last or not server:step_time() then
                server.dispatcher:step()
            end
        end
        assert(resumed[1] == 5 and resumed[2] == 6 and not next(server.active) and not next(server.scheduled_responses))
        local early, late = false, false
        for _, check in ipairs(checked) do
            early = early or check[2] == 1
            late = late or (check[1] == "timeout" and check[2] == 4)
        end
        assert(early and late, "transport filtered timing instead of invoking the referee")
    end

    -- Results survive until their own wait, and a timed wait can be retried.
    run_with_server(function(server, run_client, wait_connections)
        local player = prt.new_player({ mcycle_height = 3, uarch_height = 3, periods_per_input = 8 }, {}, nil)
        local left, right = keccak("future left"), keccak("future right")
        local scheduled_calls, reveal_calls = {}, 0
        player.get_claim_children = function()
            return { computation_hash_left = left, computation_hash_right = right }
        end
        player.schedule_match_elimination = function(_, block)
            return function()
                scheduled_calls[block] = (scheduled_calls[block] or 0) + 1
                return true
            end
        end
        run_client(nil, function(event, line)
            assert(event.operation ~= "cancelled_probe", "a closed ordinary future was dispatched")
            return prtu.answer_event(player, line)
        end, true)
        wait_connections(1)
        do
            local block = server:get_time()
            local marker = {}
            local timeout <close> = server:request_first_valid(
                EVERYONE,
                prtu.EVENTS.schedule_match_timeout_win,
                { block + 2, keccak(left, right) },
                function(response)
                    assert(response.computation_hash_left == left and response.computation_hash_right == right)
                    return marker
                end
            )
            local reveal <close> = server:request_first_valid(
                {},
                prtu.EVENTS.reveal_bisection,
                { keccak("claim"), 0, 3, keccak("left") },
                function()
                    reveal_calls = reveal_calls + 1
                end
            )
            local elimination <close> = server:request_first_valid(
                EVERYONE,
                prtu.EVENTS.schedule_match_elimination,
                { block + 5 },
                function(response)
                    assert(response == true)
                    return 0
                end
            )
            assert(server:get_time() == block, "request_first_valid suspended its caller")
            local ok, err = pcall(function()
                local cancelled <close> = server:request_first_valid( -- luacheck: ignore 211
                    EVERYONE,
                    prtu.EVENTS.schedule_match_elimination,
                    { block + 4 },
                    function() end
                )
                local ordinary <close> = server:request_first_valid( -- luacheck: ignore 211
                    EVERYONE,
                    prtu.define_event("cancelled_probe"),
                    {},
                    function() end
                )
                error("close pending futures")
            end)
            assert(not ok and err:find("close pending futures"))
            assert(reveal:wait(block + 3) == nil and server:get_time() == block + 3)
            assert(timeout:wait(block + 2) == nil, "wait accepted a result at its exclusive deadline")
            assert(timeout:wait(block + 3) == marker, "an earlier result was lost before its own wait")
            assert(elimination:wait(block + 4) == nil and server:get_time() == block + 4)
            assert(elimination:wait() == 0 and server:get_time() == block + 5)
            assert(reveal_calls == 0 and not scheduled_calls[block + 4] and scheduled_calls[block + 5] == 1)
            timeout:close()
            timeout:close()
            assert(not pcall(timeout.wait, timeout), "a closed future accepted a wait")
        end
        assert(not next(server.active) and not next(server.scheduled_responses), "closed futures retained pending work")
    end)

    -- A block waits for every audience before releasing any ordinary response.
    run_with_server(function(server, run_client, wait_connections)
        local resumed, seen = 0, 0
        run_client(nil, function()
            seen = seen + 1
            return { value = true }
        end)
        run_client(nil, function()
            for _ = 1, 3 do
                server.dispatcher:schedule(coroutine.running(), "delay")
                coroutine.yield()
            end
            assert(resumed == 0, "an early response released a protocol coroutine")
            return { skip = true }
        end)
        wait_connections(2)
        local parent, blocks = coroutine.running(), {}
        for index = 1, 2 do
            server.dispatcher:spawn(function()
                server:subscribe_connection(index, server.connections[index])
                blocks[index] = server:request_block()
                local future <close> = server:request_first_valid({ index }, prtu.define_event("probe"), {}, function(v)
                    assert(seen == 1 and server:get_time() == blocks[index])
                    return v
                end)
                local value = future:wait(blocks[index] + 1)
                assert((index == 1 and value == true) or (index == 2 and value == nil))
                resumed = resumed + 1
                if resumed == 2 then
                    server.dispatcher:schedule(parent, "done")
                end
            end)
        end
        while resumed < 2 do
            coroutine.yield()
        end
        assert(blocks[1] == blocks[2])
    end)

    -- A scheduling request waits behind an in-flight response on the same socket.
    run_with_server(function(server, run_client, wait_connections)
        local nested_done, scheduled, cancelled = false, false, false
        local parent = coroutine.running()
        local probe = prtu.define_event("probe")
        run_client(nil, function(event)
            if event.operation == "advance_time" then
                return { value = {} }
            elseif event.operation == "schedule_match_elimination" then
                scheduled = true
            elseif event.operation == "cancel_response" then
                cancelled = true
            elseif event.operation == "probe" and not scheduled then
                local connection = server.connections[1]
                server:subscribe_connection("probe", connection)
                server.dispatcher:spawn(function()
                    local elimination <close> = server:request_first_valid( -- luacheck: ignore 211
                        { "probe" },
                        prtu.EVENTS.schedule_match_elimination,
                        { server:request_block() + 10 },
                        function() end
                    )
                    local future <close> = server:request_first_valid({ "probe" }, probe, {}, function(v)
                        return v
                    end)
                    assert(future:wait())
                    nested_done = true
                    server.dispatcher:schedule(parent, "nested_done")
                end)
                server.dispatcher:schedule(coroutine.running(), "reply")
                coroutine.yield()
                assert(connection.current_event and #connection.events == 1)
            end
            return { value = true }
        end, true)
        wait_connections(1)
        local first <close> = server:request_first_valid(EVERYONE, probe, {}, function(v)
            assert(scheduled, "scheduling did not drain before continuing")
            return v
        end)
        assert(first:wait())
        while not nested_done do
            coroutine.yield()
        end
        local second <close> = server:request_first_valid(EVERYONE, probe, {}, function(v)
            assert(cancelled, "closing the future did not cancel its pending response")
            return v
        end)
        assert(second:wait())
    end)

    -- Malformed computed values cannot discard other responses in the same batch.
    run_with_server(function(server, run_client, wait_connections)
        local player = prt.new_player({ mcycle_height = 3, uarch_height = 3, periods_per_input = 8 }, {}, nil)
        local left, right = keccak("left"), keccak("right")
        player.get_claim_children = function()
            return { computation_hash_left = left, computation_hash_right = right, output = "!" }
        end
        local accepted, malformed = 0, false
        run_client(nil, function(event, line)
            if event.operation == "probe" then
                return { skip = true }
            end
            local encoded, done = prtu.answer_event(player, line)
            if event.operation == "advance_time" then
                local response = cartesi.fromjson(encoded)
                if #response.value > 0 then
                    assert(#response.value == 2)
                    local valid = response.value[1]
                    assert(valid.value.output == "!")
                    valid.request = "prove_output"
                    local invalid = copy(valid)
                    invalid.value.computation_hash_left = "!"
                    table.insert(response.value, 1, invalid)
                    encoded, malformed = cartesi.tojson(response, -1), true
                end
            end
            return encoded, done
        end, true)
        wait_connections(1)
        local parent, completed = coroutine.running(), 0
        for index = 1, 2 do
            server.dispatcher:spawn(function()
                local block = server:request_block() + 1
                if index == 1 then
                    local timeout <close> = server:request_first_valid(
                        EVERYONE,
                        prtu.EVENTS.schedule_match_timeout_win,
                        { block, keccak(left, right) },
                        function(response)
                            assert(response.computation_hash_left == left and response.computation_hash_right == right)
                            assert(response.output == "!", "an unrelated response schema decoded the value")
                            accepted = accepted + 1
                            return true
                        end
                    )
                    assert(timeout:wait(block + 1))
                else
                    local elimination <close> = server:request_first_valid(
                        EVERYONE,
                        prtu.EVENTS.schedule_match_elimination,
                        { block },
                        function(response)
                            assert(response == true)
                            accepted = accepted + 1
                            return true
                        end
                    )
                    assert(elimination:wait())
                end
                completed = completed + 1
                if completed == 2 then
                    server.dispatcher:schedule(parent, "done")
                end
            end)
        end
        while completed < 2 do
            coroutine.yield()
        end
        assert(malformed and accepted == 2, "a malformed response interfered with its batch peers")
    end)

    -- The first uarch step is a small real proof, independent of guest execution.
    local machine <close> = cartesi.machine({ ram = { length = 4096 } })
    local initial = machine:get_root_hash()
    local logs = { step_log = machine:log_step_uarch() }
    local after = machine:get_root_hash()
    assert(cartesi.machine:verify_step_uarch(initial, logs.step_log) == after)
    local geometry = { mcycle_height = 3, uarch_height = 3, periods_per_input = 8 }

    -- Narration remains outside the referee. Capture semantic reports so each
    -- fixture can assert its outcome without writing walkthrough artifacts.
    local original_story = copy(prtu.story)
    local reports, probing, current_server
    for name in pairs(prtu.story) do
        prtu.story[name] = function(...)
            if not probing then
                reports[#reports + 1] = { name, ... }
                reports[#reports].block = current_server:get_time()
            end
        end
    end

    local function scenario(mode, reverse)
        reports = {}
        local schedules, cancellations, proof_checks, stale_checks = {}, {}, 0, 0
        local opening_blocks, unrelated_responses = {}, 0
        local players = {}
        local finals = { after, keccak("false final") }
        if mode == "concurrent" then
            finals[3], finals[4] = keccak("third final"), keccak("fourth final")
        elseif mode == "uarch_inactive" then
            finals[3], finals[4] = after, after
        end
        for index, final in ipairs(finals) do
            local player = prt.new_player(geometry, {}, nil, { label = "fixture" .. index })
            player.make_mcycle_tree = function()
                return repeated_tree(final, geometry.mcycle_height)
            end
            player.make_uarch_tree = function()
                return repeated_tree(final, geometry.uarch_height)
            end
            player.prove_state_transition = function()
                return logs
            end
            player.prove_outputs_merkle_root = function()
                return {}
            end
            players[index] = player
        end
        if mode == "uarch_inactive" then
            local ordered = { players[1].make_mcycle_tree():get_root(), players[2].make_mcycle_tree():get_root() }
            table.sort(ordered, function(a, b)
                return cartesi.tohex(a) < cartesi.tohex(b)
            end)
            local inactive = {}
            for index = 3, 4 do
                local seed = index * 100
                local tree
                repeat
                    seed = seed + 1
                    local forest = hash_tree.frontier_forest(3, "keccak256")
                    for leaf = 0, 7 do
                        hash_tree.frontier_forest_push_back(forest, leaf == 1 and keccak("inactive" .. seed) or after)
                    end
                    tree = prtu.new_tree(3, 0, forest)
                until cartesi.tohex(tree:get_root()) > cartesi.tohex(ordered[2])
                players[index].make_uarch_tree = function()
                    return tree
                end
                inactive[#inactive + 1] = tree:get_root()
            end
            table.sort(inactive, function(a, b)
                return cartesi.tohex(a) < cartesi.tohex(b)
            end)
            assert(inactive[1] ~= inactive[2])
        end
        -- Determine the bracket without relying on connection order.
        local roots = { players[1].make_mcycle_tree():get_root(), players[2].make_mcycle_tree():get_root() }
        local first = cartesi.tohex(roots[1]) < cartesi.tohex(roots[2]) and 1 or 2
        run_with_server(function(server, run_client, wait_connections)
            current_server = server
            local request_first_valid = server.request_first_valid
            server.request_first_valid = function(self, subscriptions, event, arguments, accept)
                if event.scheduled_schema then
                    local block = arguments[1]
                    local expires = event == prtu.EVENTS.schedule_match_timeout_win and block + 1 or nil
                    local delay = block - self:request_block()
                    assert(delay == 1 or (event == prtu.EVENTS.schedule_match_elimination and delay == 2))
                    local response = true
                    if event == prtu.EVENTS.schedule_match_timeout_win then
                        assert(expires == block + 1)
                        for _, player in ipairs(players) do
                            for _, tree in ipairs({ player.mcycle_claim, player.uarch_claim }) do
                                if tree:get_root() == arguments[2] then
                                    response = player:get_claim_children(arguments[2])
                                end
                            end
                        end
                        assert(type(response) == "table")
                    end
                    local saved = self.clock.block
                    probing = true
                    self.clock.block = block - 1
                    assert(not pcall(accept, response), "premature scheduled response accepted")
                    self.clock.block = block
                    local ok, value = pcall(accept, response)
                    assert(ok and value, "eligible scheduled response rejected")
                    local invalid = type(response) == "table" and copy(response) or false
                    if type(invalid) == "table" then
                        invalid.computation_hash_left = keccak("wrong children")
                    end
                    assert(not pcall(accept, invalid), "invalid scheduled response accepted")
                    if expires then
                        self.clock.block = expires
                        assert(not pcall(accept, response), "scheduled response accepted at expiry")
                        self.clock.block = expires + 1
                        assert(not pcall(accept, response), "scheduled response accepted after expiry")
                    end
                    probing = false
                    self.clock.block = saved
                elseif
                    event == prtu.EVENTS.reveal_bisection
                    or event == prtu.EVENTS.seal_divergence
                    or event == prtu.EVENTS.prove_state_transition
                then
                    local block = self:request_block()
                    local request = event.name
                    if request == "reveal_bisection" and arguments[3] == 3 then
                        opening_blocks[#opening_blocks + 1] = block
                    end
                    local proof_deadline = block + 1
                    -- Ordinary validators themselves reject at exact expiry,
                    -- even when a response lies about its eligibility and timestamp.
                    local holder = request == "prove_state_transition" and players[1]
                    if request == "reveal_bisection" or request == "seal_divergence" then
                        for _, player in ipairs(players) do
                            local root = arguments[1]
                            if
                                player.mcycle_claim:get_root() == root
                                or (player.uarch_claim and player.uarch_claim:get_root() == root)
                            then
                                holder = player
                            end
                        end
                    end
                    if holder then
                        local response = holder[request](holder, table.unpack(arguments))
                        response.block, response.eligible, response.expires = 0, 0, math.maxinteger
                        local saved = self.clock.block
                        self.clock.block = proof_deadline
                        probing = true
                        assert(not pcall(accept, response), "ordinary response accepted at expiry")
                        self.clock.block = proof_deadline + 1
                        assert(not pcall(accept, response), "ordinary response accepted after expiry")
                        self.clock.block = block
                        local ok, value = pcall(accept, response)
                        assert(ok and value, "valid response rejected before expiry")
                        if request == "prove_state_transition" then
                            proof_checks = proof_checks + 1
                            local invalid = {}
                            local valid, result = pcall(accept, invalid)
                            assert(not valid or not result, "invalid transition proof accepted")
                        end
                        probing = false
                        self.clock.block = saved
                    end
                end
                if event == prtu.EVENTS.prove_outputs_merkle_root then
                    -- These fixtures settle matches, but have no valid epoch-output proof.
                    -- End the example through its controller instead of a proof deadline.
                    local closer = prtu.new_phase_closer("stop")
                    run_client(cartesi.fromjson(closer.hello), function(_, line)
                        return prtu.answer_event(closer, line)
                    end, true)
                end
                return request_first_valid(self, subscriptions, event, arguments, accept)
            end
            for slot = 1, #players do
                local index = reverse and #players + 1 - slot or slot
                local player = players[index]
                run_client(nil, function(event, line)
                    if prtu.EVENTS[event.operation] and prtu.EVENTS[event.operation].scheduled_schema then
                        schedules[event.id] = (schedules[event.id] or 0) + 1
                    elseif event.operation == "cancel_response" then
                        local id = event.arguments[1]
                        cancellations[id] = (cancellations[id] or 0) + 1
                    else
                        local request = event.operation
                        local opening = request == "reveal_bisection" or request == "seal_divergence"
                        if
                            (mode == "timeout" and index == first and opening)
                            or (mode == "timeout_advanced" and opening and event.arguments[3] == 2)
                            or (mode == "timeout_seal" and opening and request == "seal_divergence")
                            or ((mode == "eliminate" or mode == "concurrent") and opening)
                            or (mode == "leaf_expiry" and request == "prove_state_transition")
                            or (mode == "uarch_inactive" and index >= 3 and opening and player.uarch_claim)
                        then
                            return cartesi.tojson({ skip = true }, -1)
                        end
                        if
                            request == "commit_uarch_claim"
                            and (
                                mode == "empty_uarch"
                                or ((mode == "uarch" or mode == "uarch_without_holder") and index == 2)
                            )
                        then
                            return cartesi.tojson({ skip = true }, -1)
                        end
                    end
                    local encoded, done = prtu.answer_event(player, line)
                    if mode == "uarch_without_holder" and index == 1 and event.operation == "commit_uarch_claim" then
                        return encoded, true
                    end
                    if event.operation == "advance_time" then
                        local response = cartesi.fromjson(encoded)
                        local kept = {}
                        for _, reply in ipairs(response.value) do
                            local future = server.scheduled_responses[reply.id]
                            local timeout = future.event == prtu.EVENTS.schedule_match_timeout_win
                            local suppress = mode == "eliminate"
                                or mode == "concurrent"
                                or (mode == "uarch_inactive" and index >= 3)
                            if not (suppress and timeout) then
                                kept[#kept + 1] = reply
                                if not timeout then
                                    kept[#kept + 1] = copy(reply)
                                end
                                if index == 1 and future.event == prtu.EVENTS.schedule_match_elimination then
                                    unrelated_responses = unrelated_responses + 1
                                end
                            end
                        end
                        for id in pairs(cancellations) do
                            kept[#kept + 1] = { id = id, value = true }
                            stale_checks = stale_checks + 1
                        end
                        response.value = kept
                        encoded = cartesi.tojson(response, -1)
                    end
                    return encoded, done
                end, true)
                wait_connections(slot)
            end
            run_client({ role = "phase_closer" }, function(_, line)
                return prtu.answer_event(prtu.new_phase_closer(), line)
            end, true)
            prt.new_referee({ geometry = geometry, initial_state_hash = initial, inputs = {} }):run(server)
        end)
        assert(#current_server.open_phases == 0 and not next(current_server.scheduled_responses))
        assert(current_server.phase_closer.dead, "phase closer stayed necessary after subscriptions")
        local winner, timeouts, eliminated = nil, 0, 0
        local trace = {}
        for index, report in ipairs(reports) do
            trace[#trace + 1] = report[1]
            if report[1] == "report_uarch_result" then
                local previous = reports[index - 1]
                assert(
                    previous[2].level == "uarch" and previous.block == report.block,
                    "uarch result propagation waited after the tournament finished"
                )
            end
            if report[1] == "report_winner" then
                winner = report[2]
            elseif report[1] == "report_timeout_win" then
                timeouts = timeouts + 1
            elseif report[1] == "report_uarch_result" and mode == "empty_uarch" then
                assert(not report[3], "an empty uarch tournament was reported as having a winner")
            elseif report[1] == "report_match_eliminated" then
                eliminated = eliminated + 1
            end
        end
        if mode == "timeout" or mode == "timeout_seal" or mode == "timeout_advanced" then
            local winner_index = mode == "timeout_advanced" and first or 3 - first
            assert(winner and winner.computation_hash == roots[winner_index] and timeouts == 1)
        elseif mode == "eliminate" or mode == "concurrent" then
            assert(not winner and eliminated == #players // 2, "elimination did not resolve exactly once")
            if mode == "concurrent" then
                assert(#opening_blocks == 2 and opening_blocks[1] == opening_blocks[2])
            end
        elseif mode == "empty_uarch" or mode == "leaf_expiry" then
            assert(not winner, "an unavailable uarch result propagated")
        else
            assert(winner and winner.final_state_hash == after, "wrong uarch winner propagated")
        end
        if mode == "proof" or mode == "leaf_expiry" or mode == "uarch_inactive" then
            assert(proof_checks == 1 and stale_checks > 0)
        end
        if mode == "uarch_inactive" then
            assert(unrelated_responses == 1 and eliminated == 1, "honest lineage left an unrelated uarch match pending")
        end
        for id, count in pairs(schedules) do
            assert(cancellations[id] == count, "completion did not cancel each scheduled response exactly once")
        end
        return table.concat(trace, ",")
    end

    for _, mode in ipairs({
        "timeout",
        "timeout_advanced",
        "timeout_seal",
        "eliminate",
        "concurrent",
        "uarch_inactive",
        "uarch",
        "empty_uarch",
        "uarch_without_holder",
        "proof",
        "leaf_expiry",
    }) do
        assert(scenario(mode, false) == scenario(mode, true), "connection order changed the protocol trace")
    end
    for name, handler in pairs(original_story) do
        prtu.story[name] = handler
    end
end
