-- Deadline regressions exercise the real referee, player executor, and transport.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local prtu = require("prtu")
local keccak = cartesi.keccak256

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
    -- No scheduled acknowledgement means no elimination, even after the deadline.
    do
        local server = prtu.new_server()
        local resumed = false
        server.dispatcher:spawn(function()
            server:schedule({}, prtu.EVENTS.schedule_match_elimination, {}, 3, function(response)
                assert(response == true)
                return 0
            end)
            server:emit({}, prtu.define_event("probe"), {}, function() end)
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
        assert(next(server.active), "an unanswered obligation completed without a response")
    end

    -- Route premature, expired, forged, and duplicate responses to independent waiters.
    do
        local server = prtu.new_server()
        local resumed, checked, ids = {}, {}, {}
        local function schedule(name, block, expires)
            ids[name] = server:schedule({}, prtu.EVENTS.schedule_match_elimination, {}, block, function(response)
                checked[#checked + 1] = { name, server:get_time() }
                assert(server:get_time() >= block and (not expires or server:get_time() < expires))
                assert(response == true)
                return 0
            end, expires)
        end
        for index = 1, 2 do
            server.dispatcher:spawn(function()
                if index == 1 then
                    schedule("timeout", 3, 4)
                    schedule("eliminate", 5)
                else
                    schedule("unrelated", 6)
                end
                assert(server:emit({}, prtu.define_event("probe"), {}, function() end) == 0)
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
        assert(resumed[1] == 5 and resumed[2] == 6 and not next(server.active) and not next(server.routes))
        local early, late = false, false
        for _, check in ipairs(checked) do
            early = early or check[2] == 1
            late = late or (check[1] == "timeout" and check[2] == 4)
        end
        assert(early and late, "transport filtered timing instead of invoking the referee")
    end

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
                blocks[index] = server:request_block()
                local value = server:emit({ server.connections[index] }, prtu.define_event("probe"), {}, function(v)
                    assert(seen == 1 and server:get_time() == blocks[index])
                    return v
                end)
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
                server.dispatcher:spawn(function()
                    server:schedule(
                        { connection },
                        prtu.EVENTS.schedule_match_elimination,
                        {},
                        server:request_block() + 10,
                        function() end
                    )
                    assert(server:emit({ connection }, probe, {}, function(v)
                        return v
                    end))
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
        assert(server:emit(server:get_players(), probe, {}, function(v)
            assert(scheduled, "scheduling did not drain before continuing")
            return v
        end))
        while not nested_done do
            coroutine.yield()
        end
        assert(server:emit(server:get_players(), probe, {}, function(v)
            assert(cancelled, "completion did not cancel its pending response")
            return v
        end))
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
                    server:schedule(
                        server:get_players(),
                        prtu.EVENTS.schedule_child_propagation,
                        { keccak(left, right) },
                        block,
                        function(response)
                            assert(response.computation_hash_left == left and response.computation_hash_right == right)
                            assert(response.output == "!", "an unrelated response schema decoded the value")
                            accepted = accepted + 1
                            return true
                        end,
                        block + 1
                    )
                else
                    server:schedule(
                        server:get_players(),
                        prtu.EVENTS.schedule_child_elimination,
                        {},
                        block,
                        function(response)
                            assert(response == true)
                            accepted = accepted + 1
                            return true
                        end
                    )
                end
                assert(server:emit(server:get_players(), prtu.define_event("probe"), {}, function() end))
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
    local reports, probing
    for name in pairs(prtu.story) do
        prtu.story[name] = function(...)
            if not probing then
                reports[#reports + 1] = { name, ... }
            end
        end
    end

    local function scenario(mode, reverse)
        reports = {}
        local schedules, cancellations, proof_checks, stale_checks = {}, {}, 0, 0
        local opening_blocks, unrelated_calls = {}, 0
        local players = {}
        local finals = { after, keccak("false final") }
        if mode == "concurrent" then
            finals[3], finals[4] = keccak("third final"), keccak("fourth final")
        elseif mode == "child_inactive" then
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
        if mode == "child_inactive" then
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
            local schedule = server.schedule
            server.schedule = function(self, conns, event, arguments, block, accept, expires)
                local delay = block - self:request_block()
                assert(delay == 1 or (event == prtu.EVENTS.schedule_match_elimination and delay == 2))
                local response = true
                if event == prtu.EVENTS.schedule_timeout_win then
                    assert(expires == block + 1)
                    for _, player in ipairs(players) do
                        for _, tree in ipairs({ player.mcycle_claim, player.uarch_claim }) do
                            if tree:get_root() == arguments[1] then
                                response = player:get_claim_children(arguments[1])
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
                return schedule(self, conns, event, arguments, block, accept, expires)
            end
            local emit = server.emit
            server.emit = function(self, conns, event, arguments, accept)
                if self.scheduled[coroutine.running()] then
                    local block = self:request_block()
                    local request = event.name
                    if request == "reveal_bisection" and arguments[3] == 3 then
                        opening_blocks[#opening_blocks + 1] = block
                    end
                    local proof_deadline = block + 1
                    -- Ordinary validators themselves reject at exact expiry,
                    -- even when a call lies about its eligibility and timestamp.
                    local holder = request == "propagate_child" and arguments[1] and players[1]
                        or (request == "prove_state_transition" and players[1])
                    if request == "propagate_child" and arguments[1] then
                        holder = arguments[1] == roots[1] and players[1] or players[2]
                    elseif request == "reveal_bisection" or request == "seal_divergence" then
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
                return emit(self, conns, event, arguments, accept)
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
                            or (mode == "expired_child" and request == "propagate_child")
                            or (mode == "leaf_expiry" and request == "prove_state_transition")
                            or (mode == "child_inactive" and index >= 3 and opening and player.uarch_claim)
                        then
                            return cartesi.tojson({ skip = true }, -1)
                        end
                        if
                            request == "commit_uarch_claim"
                            and (mode == "empty_child" or ((mode == "child" or mode == "expired_child") and index == 2))
                        then
                            return cartesi.tojson({ skip = true }, -1)
                        end
                    end
                    local encoded, done = prtu.answer_event(player, line)
                    if event.operation == "advance_time" then
                        local response = cartesi.fromjson(encoded)
                        local kept = {}
                        for _, reply in ipairs(response.value) do
                            local route = server.routes[reply.id]
                            local timeout = route.event == prtu.EVENTS.schedule_timeout_win
                            local suppress = mode == "eliminate"
                                or mode == "concurrent"
                                or (mode == "child_inactive" and index >= 3)
                            if not (suppress and timeout) then
                                kept[#kept + 1] = reply
                                if not timeout then
                                    kept[#kept + 1] = copy(reply)
                                end
                                if index == 1 and route.event == prtu.EVENTS.schedule_match_elimination then
                                    unrelated_calls = unrelated_calls + 1
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
            assert(#server.open_phases == 0 and not next(server.routes))
            assert(server.phase_closer.dead, "phase closer stayed necessary after subscriptions")
        end)
        local winner, timeouts, eliminated, consumed = nil, 0, 0, 0
        local trace = {}
        for _, report in ipairs(reports) do
            trace[#trace + 1] = report[1]
            if report[1] == "report_winner" then
                winner = report[2]
            elseif report[1] == "report_timeout_win" then
                timeouts = timeouts + 1
            elseif report[1] == "report_uarch_result_consumed" then
                assert(mode == "expired_child" and report[3] and report[3].final_state_hash == after)
                consumed = consumed + 1
            elseif report[1] == "report_uarch_result" and mode == "empty_child" then
                assert(not report[3], "an empty child was reported as having a winner")
            elseif report[1] == "report_uarch_result" and mode == "expired_child" then
                error("an expired child winner was reported as a propagated or absent winner")
            elseif report[1] == "report_match_eliminated" then
                eliminated = eliminated + 1
            end
        end
        assert(
            consumed == (mode == "expired_child" and 1 or 0),
            "child result consumption was not reported exactly once"
        )
        if mode == "timeout" or mode == "timeout_seal" or mode == "timeout_advanced" then
            local winner_index = mode == "timeout_advanced" and first or 3 - first
            assert(winner and winner.computation_hash == roots[winner_index] and timeouts == 1)
        elseif mode == "eliminate" or mode == "concurrent" then
            assert(not winner and eliminated == #players // 2, "elimination did not resolve exactly once")
            if mode == "concurrent" then
                assert(#opening_blocks == 2 and opening_blocks[1] == opening_blocks[2])
            end
        elseif mode == "empty_child" or mode == "expired_child" or mode == "leaf_expiry" then
            assert(not winner, "an unavailable child result propagated")
        else
            assert(winner and winner.final_state_hash == after, "wrong child winner propagated")
        end
        if mode == "proof" or mode == "leaf_expiry" or mode == "child_inactive" then
            assert(proof_checks == 1 and stale_checks > 0)
        end
        if mode == "child_inactive" then
            assert(unrelated_calls == 1 and eliminated == 1, "honest lineage left an unrelated child match pending")
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
        "child_inactive",
        "child",
        "empty_child",
        "expired_child",
        "proof",
        "leaf_expiry",
    }) do
        assert(scenario(mode, false) == scenario(mode, true), "connection order changed the protocol trace")
    end
    for name, handler in pairs(original_story) do
        prtu.story[name] = handler
    end
end
