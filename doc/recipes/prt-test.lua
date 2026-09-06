-- Checks claim trees, proofs, and the referee with synthetic state, then, when given an initial
-- machine hash and inputs, checks checkpoint replay against a real machine. The synthetic claims
-- are walked under both claim orders. The loopback referee tests its tournament lifecycle,
-- first-valid moves, rejected proofs that leave connections open, and claims eliminated once every
-- holder answered without proof or closed. The real-machine cases cover tampering exactly at a
-- cached period and refinement inside a rejected input. Exits nonzero on the first failure.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local socket = require("socket")
local prt_player = require("prt-player")
local prtu = require("prtu")
local prt = require("prt")

local keccak = cartesi.keccak256

--------------------------------------------------------------------------------
-- Machine checkpoint cache
--------------------------------------------------------------------------------

local function new_fake_machine(root_hash)
    local machine = { root_hash = root_hash }
    function machine:fork_server()
        return new_fake_machine(self.root_hash)
    end
    function machine.set_cleanup_call() end
    function machine:get_root_hash()
        return self.root_hash
    end
    function machine:shutdown_server()
        self.shutdown = true
    end
    return machine
end

do
    local cache = prt_player.new_machine_cache("unused", 4)
    for epoch_period_index = 1, 5 do
        cache:consider(epoch_period_index, new_fake_machine(tostring(epoch_period_index)))
    end
    local retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.epoch_period_index] = true
    end
    assert(retained[1] and retained[2] and retained[3] and retained[4], "cache replaced a checkpoint too early")
    cache:consider(6, new_fake_machine("6"))
    retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.epoch_period_index] = true
    end
    assert(retained[2] and retained[3] and retained[4] and retained[6], "cache did not replace one odd offer")
    cache:consider(7, new_fake_machine("7"))
    cache:consider(8, new_fake_machine("8"))
    retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.epoch_period_index] = true
    end
    assert(retained[2] and retained[4] and retained[6] and retained[8], "cache did not thin its checkpoints")
    local machine, epoch_period_index = cache:fork_closest(7)
    assert(machine:get_root_hash() == "6")
    assert(epoch_period_index == 6)
    machine:shutdown_server()
    assert(
        not pcall(cache.consider, cache, 8, new_fake_machine("different")),
        "cache accepted different machine states at the same position"
    )
end

do
    local cache = prt_player.new_machine_cache("unused", 4)
    for _, epoch_period_index in ipairs({ 3, 6, 9, 12, 15, 18, 21, 24 }) do
        cache:consider(epoch_period_index, new_fake_machine(tostring(epoch_period_index)))
    end
    local retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.epoch_period_index] = true
    end
    assert(retained[6] and retained[12] and retained[18] and retained[24], "cache ignored checkpoint distances")
end

local HEIGHT = 5
local LEAVES = 1 << HEIGHT
local INITIAL_STATE_HASH = keccak("initial")

-- A claim over leaves that repeat `base_state_hash` except at `lie`, which holds
-- `fake_state_hash`. Built either
-- flat or bundled 2^2 leaves per stored bundle, so the refine path is exercised too.
local function make_synthetic_claim(base_state_hash, lie, fake_state_hash, bundled)
    local leaves = {}
    for i = 0, LEAVES - 1 do
        leaves[i] = i == lie and fake_state_hash or base_state_hash
    end
    local function build_leaf_forest(first, log2_count)
        local forest = hash_tree.frontier_forest(log2_count, "keccak256")
        for i = first, first + (1 << log2_count) - 1 do
            hash_tree.frontier_forest_push_back(forest, leaves[i])
        end
        return forest
    end
    local tree
    if bundled then
        local bundle_height = 2
        local outer = hash_tree.frontier_forest(HEIGHT - bundle_height, "keccak256")
        for bundle = 0, (LEAVES >> bundle_height) - 1 do
            hash_tree.frontier_forest_push_back(
                outer,
                hash_tree.frontier_forest_get_root_hash(build_leaf_forest(bundle << bundle_height, bundle_height))
            )
        end
        tree = prtu.new_tree(HEIGHT, bundle_height, outer, function(_, bundle)
            return build_leaf_forest(bundle << bundle_height, bundle_height)
        end)
    else
        tree = prtu.new_tree(HEIGHT, 0, build_leaf_forest(0, HEIGHT), nil)
    end
    local computation_hash_left, computation_hash_right = tree:get_children(0, HEIGHT)
    if tree.bundle_height > 0 then
        tree:open_bundle((LEAVES - 1) >> tree.bundle_height)
    end
    local proof = tree:prove(LEAVES - 1)
    hash_tree.verify_slice(proof)
    assert(
        proof.target_address == LEAVES - 1
            and proof.log2_target_size == 0
            and proof.log2_root_size == HEIGHT
            and #proof.sibling_hashes == HEIGHT
            and proof.root_hash == tree:get_root(),
        "wrong final-state proof"
    )
    return {
        computation_hash = tree:get_root(),
        computation_hash_left = computation_hash_left,
        computation_hash_right = computation_hash_right,
        final_state_hash = proof.target_hash,
        tree = tree,
        leaves = leaves,
    }
end

-- The internal-node response a player holding the on-turn claim makes.
local function make_bisection_response(match)
    assert(match.height > 1)
    local tree = match.claims[match.turn].tree
    if match.height == tree.bundle_height then
        tree:open_bundle(match.position >> tree.bundle_height)
    end
    local turn_left_node, turn_right_node = tree:get_children(match.position, match.height)
    local descend_left = turn_left_node ~= match.other_left_node
    local child_position = descend_left and match.position or match.position + (1 << (match.height - 1))
    if match.height - 1 == tree.bundle_height then
        tree:open_bundle(child_position >> tree.bundle_height)
    end
    local turn_next_left_node, turn_next_right_node = tree:get_children(child_position, match.height - 1)
    return {
        turn_left_node = turn_left_node,
        turn_right_node = turn_right_node,
        turn_next_left_node = turn_next_left_node,
        turn_next_right_node = turn_next_right_node,
    }
end

-- The final response exposes the divergent leaves and proves the preceding agreed state.
local function make_seal_response(match)
    assert(match.height == 1)
    local tree = match.claims[match.turn].tree
    local turn_left_node, turn_right_node = tree:get_children(match.position, 1)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= match.other_left_node
    local state_index = match.position + (descend_left and 0 or 1)
    if state_index ~= 0 then
        local agreed_state_index = state_index - 1
        if tree.bundle_height > 0 then
            tree:open_bundle(agreed_state_index >> tree.bundle_height)
        end
        response.agreed_state_hash_proof = tree:prove(agreed_state_index)
    end
    return response
end

local function swap_turn_children(response)
    return {
        turn_left_node = response.turn_right_node,
        turn_right_node = response.turn_left_node,
        turn_next_left_node = response.turn_next_left_node,
        turn_next_right_node = response.turn_next_right_node,
        agreed_state_hash_proof = response.agreed_state_hash_proof,
    }
end

-- Walks a match to its divergence, checking every response validates and a corrupted one does not.
local function walk(claim1, claim2)
    local match = prt.new_match(claim1, claim2, HEIGHT)
    local tournament = { height = HEIGHT, initial_state_hash = INITIAL_STATE_HASH }
    while match.height > 1 do
        local response = make_bisection_response(match)
        prt.validate_bisection_response(match, response)
        local valid = pcall(prt.validate_bisection_response, match, swap_turn_children(response))
        assert(not valid or response.turn_left_node == response.turn_right_node, "a swapped response validated")
        prt.advance_bisection(match, response)
    end
    local response = make_seal_response(match)
    local valid = pcall(prt.validate_seal_response, tournament, match, swap_turn_children(response))
    assert(not valid or response.turn_left_node == response.turn_right_node, "a swapped seal validated")
    return prt.validate_seal_response(tournament, match, response)
end

local base_state_hash, fake_state_hash = keccak("base"), keccak("fake")
do
    local claim = make_synthetic_claim(base_state_hash, nil, nil, true)
    local unopened_index = 0
    assert(not pcall(claim.tree.get_node, claim.tree, unopened_index, 0), "a node query implicitly opened its bundle")
    claim.tree:open_bundle(unopened_index >> claim.tree.bundle_height)
    assert(claim.tree:get_node(unopened_index, 0) == base_state_hash, "opened bundle has the wrong leaf")
end
for _, lie in ipairs({ 0, 1, 4, 6, 13, LEAVES - 1 }) do
    for _, bundled in ipairs({ false, true }) do
        local honest = make_synthetic_claim(base_state_hash, nil, nil, bundled)
        local liar = make_synthetic_claim(base_state_hash, lie, fake_state_hash, bundled)
        assert(honest.computation_hash ~= liar.computation_hash)
        -- honest opens first
        local divergence = walk(honest, liar)
        assert(divergence.state_index == lie, "walk missed the divergent state")
        assert(
            divergence.next_state_hashes[1] == base_state_hash and divergence.next_state_hashes[2] == fake_state_hash,
            "walk misattributed the states"
        )
        -- liar opens first: the same leaf, the claims swapped
        local mirrored = walk(liar, honest)
        assert(
            mirrored.state_index == lie
                and mirrored.next_state_hashes[1] == fake_state_hash
                and mirrored.next_state_hashes[2] == base_state_hash,
            "walk is not symmetric"
        )
        if lie == 0 then
            assert(
                divergence.agreed_state_hash == INITIAL_STATE_HASH and mirrored.agreed_state_hash == INITIAL_STATE_HASH,
                "wrong initial agreed state"
            )
        else
            assert(
                divergence.agreed_state_hash == honest.leaves[lie - 1]
                    and mirrored.agreed_state_hash == divergence.agreed_state_hash,
                "wrong agreed state"
            )
        end
    end
end

--------------------------------------------------------------------------------
-- Referee server
--------------------------------------------------------------------------------

-- Runs `scenario` as the referee's main logic against a fresh server on a loopback port. The
-- scenario gets the server and a `client` constructor. Each client is a coroutine of the same
-- dispatcher that connects, announces itself (as a player unless told otherwise), and answers
-- every event line with what `handler` returns for it: a reply table (encoded as is),
-- "close" to hang up, a raw line to send verbatim, or nil to delay its answer.
local function run_with_server(scenario)
    local server = prtu.new_server("127.0.0.1:0")
    local _, port = server.listener:getsockname()
    local dispatcher = server.dispatcher
    local function run_client(hello, handler)
        dispatcher:spawn(function()
            local sock = assert(socket.connect("127.0.0.1", port))
            sock:settimeout(0)
            assert(sock:send(cartesi.tojson(hello or { role = "player" }, -1) .. "\n"))
            local partial
            while true do
                assert(dispatcher:wake_when_readable(sock) == "io")
                local line, err
                line, err, partial = sock:receive("*l", partial)
                if not line and err ~= "timeout" then
                    return
                elseif line then
                    local wire_event = cartesi.fromjson(line)
                    local reply = wire_event.operation == "finish" and { value = true } or handler(wire_event)
                    if reply == "close" then
                        sock:close()
                        return
                    elseif type(reply) == "table" then
                        reply = cartesi.tojson(reply, -1)
                    end
                    if reply ~= nil then
                        assert(sock:send(reply .. "\n"))
                    end
                end
            end
        end)
    end
    -- Waits until n connections have announced themselves, or been closed for trying (clients
    -- connect asynchronously).
    local function wait_connections(n)
        while true do
            local announced = 0
            for _, connection in ipairs(server.connections) do
                if connection.is_player or connection.is_phase_closer or connection.dead then
                    announced = announced + 1
                end
            end
            if announced >= n then
                return
            end
            dispatcher:schedule(coroutine.running(), "poll")
            coroutine.yield()
        end
    end
    server:run(function()
        scenario(server, run_client, wait_connections)
    end)
end

-- A player that returns `claim` to any tournament and answers every event with `answer`.
local function make_claimer(claim, answer)
    return function(event)
        if event.operation == "commit_mcycle_claim" then
            return { label = claim, value = claim }
        end
        return answer(event)
    end
end

local function is_valid(v)
    return v == "valid" and v
end

local function define_event(name, response_schema)
    return prtu.define_event(name, nil, response_schema)
end

run_with_server(function(server, run_client, wait_connections)
    -- Two players connect before the phase closer, one after it. The mcycle tournament must
    -- gather exactly the first two, and must not resolve before the phase closer closes it.
    local answered = {}
    local function answer(value)
        return function()
            answered[#answered + 1] = value
            return { value = value }
        end
    end
    run_client(nil, make_claimer("a", answer("valid")))
    run_client(nil, make_claimer("b", answer("invalid")))
    run_client({ role = "phase_closer" }, function()
        return { value = true }
    end)
    server:accept_subscribers("initial")
    local responses =
        server:collect_claims(server:get_subscribers({ "initial" }), define_event("commit_mcycle_claim"), {})
    assert(#server.open_phases == 0, "closed phases were retained")
    table.sort(responses, function(x, y)
        return x.value < y.value
    end)
    assert(
        #responses == 2 and responses[1].value == "a" and responses[2].value == "b",
        "mcycle tournament gathered the wrong claims"
    )
    assert(server.phase_closer and server.phase_closer.is_phase_closer, "the phase closer was not adopted")
    local a, b = responses[1].connection, responses[2].connection
    server:subscribe("x", a)
    server:subscribe("x", b)
    -- A late joiner, after the phase closes, is not part of the mcycle tournament.
    run_client(nil, make_claimer("c", answer("valid")))
    wait_connections(4)

    -- The first valid response wins; a rejected response leaves its connection open.
    assert(
        server:emit(server:get_subscribers({ "x" }), define_event("answer"), {}, is_valid) == "valid",
        "valid response not taken"
    )
    assert(not a.dead and not b.dead, "a rejected proof closed a connection")

    -- The acceptor's result, rather than the submitted value, is returned.
    local mapped = server:emit({ a }, define_event("mapped"), {}, function(v)
        return is_valid(v) and "mapped"
    end)
    assert(mapped == "mapped", "emit did not return the acceptor result")

    -- A valid response resolves the event while another holder still owes a reply. When that
    -- holder is asked again, TCP delivers the old reply first; the referee drops it by count
    -- and accepts the following reply for the current event.
    local delayed = false
    run_client(nil, function(wire_event)
        if wire_event.operation == "early" then
            delayed = true
            return nil
        elseif delayed then
            delayed = false
            return cartesi.tojson({ value = "invalid" }, -1) .. "\n" .. cartesi.tojson({ value = "valid" }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(5)
    local delayed_connection = server.connections[5]
    assert(
        server:emit({ delayed_connection, a }, define_event("early"), {}, is_valid) == "valid",
        "valid response not taken early"
    )
    assert(
        server:emit({ delayed_connection }, define_event("after_early"), {}, is_valid) == "valid",
        "stale reply was accepted"
    )
    assert(
        delayed_connection.stale_replies_pending == 0 and not delayed_connection.current_event,
        "stale reply was not consumed"
    )
    assert(not delayed_connection.dead, "a pending holder was closed")
    -- Without a valid response, the event waits for every holder, and resolves to nil only then.
    local replies_seen = 0
    run_client(nil, function()
        replies_seen = replies_seen + 1
        return { value = "invalid" }
    end)
    wait_connections(6)
    local n = server.connections[6]
    assert(server:emit({ n, b }, define_event("answer"), {}, is_valid) == nil, "an invalid response was taken")
    assert(replies_seen == 1, "the event resolved before every holder answered")
    assert(not n.dead and not b.dead, "an invalid response closed a connection")

    -- A nested tournament asks only its audience, and closes at once.
    local nested = server:collect_claims({ a }, define_event("commit_mcycle_claim"), {})
    assert(#nested == 1 and nested[1].value == "a", "nested tournament asked the wrong audience")
    assert(#server.open_phases == 0, "closed nested tournament was retained")

    -- Every holder answers without proof: the event resolves to nil, connections stay open.
    assert(server:emit({ b }, define_event("answer"), {}, is_valid) == nil, "an invalid response was taken")
    assert(not b.dead, "an invalid response closed its connection")

    -- A holder that closes counts as answered. With every holder gone, the claim is unanswered.
    run_client(nil, function()
        return "close"
    end)
    wait_connections(7)
    local replies = server:collect(nil, define_event("label"), {})
    local d = server.connections[7]
    assert(d.dead and #replies == 5, "the closing client was not dropped from the collection")
    assert(
        server:emit({ d }, define_event("answer"), {}, is_valid) == nil,
        "an event to a closed connection did not resolve"
    )

    -- A reply whose value violates the event's response schema is an invalid response, not a
    -- malformed connection. Asked alone, a holder answering with such a value leaves the
    -- event with nothing, and the holder open. This is the invariant itself, and needs no
    -- assumption about the order two sockets become readable.
    prtu.SCHEMA_DICT.PairResponse = { l = "Base64", r = "Base64" }
    prtu.SCHEMA_DICT.PairResponseEnvelope = { value = "PairResponse" }
    -- Each fake client answers typed events with its fixed value.
    local function run_typed_client(value, schema)
        run_client(nil, function(wire_event)
            if wire_event.operation == "typed" then
                return cartesi.tojson({ value = value }, -1, schema, prtu.SCHEMA_DICT)
            end
            return { value = "valid" }
        end)
        wait_connections(#server.connections + 1)
        return server.connections[#server.connections]
    end
    local function is_well_typed(v)
        return v.l == "a" and v.r == "b" and v
    end
    local bad = run_typed_client({ l = 1, r = "not base64!" })
    assert(
        server:emit({ bad }, define_event("typed", "PairResponse"), {}, is_well_typed) == nil,
        "a schema-invalid value was taken"
    )
    assert(not next(server.active), "emit left a resolved event active")
    assert(not bad.dead, "a schema-invalid reply closed its connection")
    -- Alongside a well-typed reply, whichever arrives first, the well-typed value is taken and
    -- both connections stay open.
    local good = run_typed_client({ l = "a", r = "b" }, "PairResponseEnvelope")
    local taken = server:emit({ bad, good }, define_event("typed", "PairResponse"), {}, is_well_typed)
    assert(taken and taken.l == "a", "the well-typed reply was not taken")
    assert(not next(server.active), "emit left a resolved event active")
    assert(not bad.dead and not good.dead, "a schema-invalid reply closed a connection")

    -- An undecodable line closes its sender.
    run_client(nil, function()
        return "this is not json"
    end)
    wait_connections(10)
    server:collect(nil, define_event("label"), {})
    local dead = 0
    for _, connection in ipairs(server.connections) do
        if connection.dead then
            dead = dead + 1
        end
    end
    assert(dead == 2, "an undecodable line did not close its sender")
    assert(not a.dead and not b.dead, "a live player was closed")

    -- Phase closing is connection-bound. An extra player reply cannot close a phase; the
    -- tournament closes only on the phase closer's reply and includes the player's claim.
    run_client(nil, function(wire_event)
        if wire_event.operation == "commit_mcycle_claim" then
            return cartesi.tojson({ value = "forger" }, -1) .. "\n" .. cartesi.tojson({ value = true }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(11)
    local f = server.connections[11]
    local t2 = server:collect_claims({ f }, define_event("commit_mcycle_claim"), {})
    assert(#t2 == 1 and t2[1].value == "forger" and not f.dead, "the forged close was not ignored")

    -- A connection announces its role once. Announcing again closes it, and so does a second
    -- phase closer.
    run_client({ role = "player" }, function()
        return { role = "player" }
    end)
    wait_connections(12)
    server:collect({ server.connections[12] }, define_event("again"), {})
    assert(server.connections[12].dead, "a repeated role announcement was accepted")
    run_client({ role = "phase_closer" }, function()
        return "close"
    end)
    wait_connections(13)
    assert(
        server.connections[13].dead and server.phase_closer == server.connections[3],
        "a second phase closer was accepted"
    )

    -- A stale reply is still a protocol line: malformed JSON closes the connection before the
    -- stale position is discarded.
    local delayed_malformed = false
    run_client(nil, function(wire_event)
        if wire_event.operation == "malformed_early" then
            delayed_malformed = true
            return nil
        elseif delayed_malformed then
            return "not json\n" .. cartesi.tojson({ value = "valid" }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(14)
    local malformed = server.connections[14]
    assert(
        server:emit({ malformed, a }, define_event("malformed_early"), {}, is_valid) == "valid",
        "valid response did not resolve before the delayed malformed reply"
    )
    assert(
        server:emit({ malformed }, define_event("after_malformed"), {}, is_valid) == nil,
        "a malformed stale line produced a value"
    )
    assert(malformed.dead, "a malformed stale line did not close its sender")
end)

-- An invalid close response is a phase-closer bug and fails the referee.
local ok, err = pcall(run_with_server, function(server, run_client, wait_connections)
    run_client({ role = "phase_closer" }, function()
        return { value = "other" }
    end)
    wait_connections(1)
    server:collect_claims({}, define_event("commit_mcycle_claim"), {})
end)
assert(not ok and err:find("did not close the phase asked"), "an invalid phase close was accepted")

-- The phase closer going away fails the referee outright: a tournament could never close again.
ok, err = pcall(run_with_server, function(server, run_client, wait_connections)
    run_client({ role = "phase_closer" }, function()
        return "close"
    end)
    wait_connections(1)
    server:collect_claims({}, define_event("commit_mcycle_claim"), {})
end)
assert(not ok and err:find("the phase closer went away"), "phase-closer EOF did not fail the referee")

--------------------------------------------------------------------------------
-- Machine checkpoint replay
--------------------------------------------------------------------------------

if arg[1] then
    local initial_state_hash = cartesi.fromhex(arg[1])
    local inputs = {}
    for i = 2, #arg do
        inputs[#inputs + 1] = util.read_file(arg[i])
    end
    assert(#inputs >= 3, "machine checkpoint tests require three inputs")
    local dapp_contract = {
        initial_state_hash = initial_state_hash,
        inputs = inputs,
        geometry = prt.new_geometry(10),
    }

    -- A collection ending exactly where a tamperer changes its machine caches the pre-tamper
    -- state. Replaying from that checkpoint must still apply the tamper before continuing.
    local tamperer =
        prt_player.new_tamperer(dapp_contract, 0, 100, prt_player.new_machine_cache(initial_state_hash, 64))
    local tampered_tree = tamperer:make_mcycle_tree()
    tampered_tree:open_bundle(99)
    tampered_tree:open_bundle(100)

    -- Refinement is a read of the committed claim. It must not replace build checkpoints with
    -- speculative machines from an input whose committed suffix is its revert state.
    local cache = prt_player.new_machine_cache(initial_state_hash, 1)
    local honest = prt_player.new_honest(dapp_contract, cache)
    local honest_tree = honest:make_mcycle_tree()
    local checkpoint = assert(cache.checkpoints[1], "claim build retained no machine checkpoint").epoch_period_index
    honest_tree:open_bundle(honest.bundles_per_input)
    assert(cache.checkpoints[1].epoch_period_index == checkpoint, "mcycle refinement changed the machine cache")
    honest:make_uarch_tree(3, 0)
end

print("prt-test: ok")
