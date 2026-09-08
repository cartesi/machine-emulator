-- Checks claim trees, proofs, and the referee with synthetic state, then, when given an initial
-- machine hash and inputs, checks checkpoint replay against a real machine. The synthetic claims
-- are walked under both claim orders. The loopback referee tests its tournament lifecycle,
-- first-valid moves, rejected proofs that leave connections open, and claims eliminated once every
-- holder answered without proof or closed. The real-machine cases cover tampering during replay
-- and refinement inside and past rejected inputs. Exits nonzero on the first failure.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local socket = require("socket")
local dishonest = require("prt-dishonest")
local prtu = require("prtu")
local prt = require("prt")

local keccak = cartesi.keccak256
local LOG2_MCYCLE_BUNDLE = prt.LOG2_MCYCLE_BUNDLE
local LOG2_UARCH_BUNDLE = prt.LOG2_UARCH_BUNDLE

--------------------------------------------------------------------------------
-- Machine checkpoint cache
--------------------------------------------------------------------------------

local function new_fake_machine(root_hash, mcycle)
    local machine = { root_hash = root_hash, mcycle = mcycle or 0 }
    function machine:fork_server()
        return new_fake_machine(self.root_hash, self.mcycle)
    end
    function machine.set_cleanup_call() end
    function machine:read_reg()
        return self.mcycle
    end
    function machine:get_root_hash()
        return self.root_hash
    end
    function machine:shutdown_server()
        self.shutdown = true
    end
    return machine
end

do
    local cache = prt.new_machine_cache({}, 5, 1, new_fake_machine("0"))
    for input_index = 1, 5 do
        cache:consider(input_index, new_fake_machine(tostring(input_index)))
    end
    local retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.input_index] = true
    end
    assert(retained[0] and retained[1] and retained[2] and retained[3] and retained[4], "cache filled incorrectly")
    cache:consider(6, new_fake_machine("6"))
    retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.input_index] = true
    end
    assert(
        retained[0] and retained[2] and retained[3] and retained[4] and retained[6],
        "cache replaced the wrong checkpoint"
    )
    cache:consider(7, new_fake_machine("7"))
    cache:consider(8, new_fake_machine("8"))
    retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.input_index] = true
    end
    assert(
        retained[0] and retained[2] and retained[4] and retained[6] and retained[8],
        "cache did not thin its checkpoints"
    )
    local machine, input_index = cache:fork_closest(7)
    assert(machine:get_root_hash() == "6")
    assert(input_index == 6)
    machine:shutdown_server()
    assert(not pcall(cache.consider, cache, 8, new_fake_machine("8")), "cache accepted an out-of-order checkpoint")
end

do
    local cache = prt.new_machine_cache({}, 5, 3, new_fake_machine("0"))
    for _, input_index in ipairs({ 3, 6, 9, 12, 15, 18, 21, 24 }) do
        cache:consider(input_index, new_fake_machine(tostring(input_index)))
    end
    local retained = {}
    for _, checkpoint in ipairs(cache.checkpoints) do
        retained[checkpoint.input_index] = true
    end
    assert(retained[0] and retained[6] and retained[12] and retained[18] and retained[24], "cache ignored distances")
end

-- A checkpoint owns its snapshot, independently of the machine that offered it and of working
-- forks. Eviction closes the saved machine and leaves the initial checkpoint alone.
do
    local cache = prt.new_machine_cache({}, 3, 1, new_fake_machine("0"))
    local machine = new_fake_machine("boundary", 100)
    cache:consider(1, machine)
    local saved = cache.checkpoints[2]
    machine.root_hash = "changed"
    local fork, input_index = cache:fork_closest(1)
    assert(input_index == 1 and fork:get_root_hash() == "boundary" and fork:read_reg("mcycle") == 100)
    fork.root_hash = "working"
    assert(saved.machine:get_root_hash() == "boundary", "working fork shares the saved machine")
    fork:shutdown_server()
    cache:consider(2, machine)
    cache:consider(3, machine)
    cache:consider(4, machine)
    assert(saved.machine.shutdown, "eviction did not close the saved machine")
    assert(not cache.checkpoints[1].machine.shutdown, "eviction closed the initial checkpoint")
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

-- Exercise the actual player responses against the referee's synthetic walk.
local function make_bisection_response(match)
    local tree = match.claims[match.turn].tree
    return prt.player_handlers.reveal_bisection(
        { mcycle_claim = tree },
        tree:get_root(),
        match.position,
        match.height,
        match.other_left_node
    )
end

local function make_seal_response(match)
    local tree = match.claims[match.turn].tree
    return prt.player_handlers.seal_divergence(
        { mcycle_claim = tree },
        tree:get_root(),
        match.position,
        match.other_left_node
    )
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
    for i = 2, 4 do
        inputs[#inputs + 1] = util.read_file(arg[i])
    end
    assert(#inputs >= 3, "machine checkpoint tests require three inputs")
    local dapp_contract = {
        initial_state_hash = initial_state_hash,
        inputs = inputs,
        geometry = prt.new_geometry(10),
    }

    -- A tamperer corrupts its machine at a fixed point of the first input. Replay from a cached
    -- boundary must apply the same corruption again, so refinement matches an uncached build.
    local tamperer = dishonest.new_tamperer(dapp_contract, 0, 100, { cache_capacity = 64, cache_gap = 1 })
    local tampered_tree = tamperer:make_mcycle_tree()
    tampered_tree:open_bundle(99)
    tampered_tree:open_bundle(100)
    local uncached_tamperer = dishonest.new_tamperer(dapp_contract, 0, 100, { cache_capacity = 1 })
    local uncached_tampered_tree = uncached_tamperer:make_mcycle_tree()
    assert(uncached_tampered_tree:get_root() == tampered_tree:get_root(), "cache changed the tampered claim")
    uncached_tampered_tree:open_bundle(100)
    for leaf = 100 << LOG2_MCYCLE_BUNDLE, (100 << LOG2_MCYCLE_BUNDLE) + (1 << LOG2_MCYCLE_BUNDLE) - 1 do
        assert(
            uncached_tampered_tree:get_node(leaf, 0) == tampered_tree:get_node(leaf, 0),
            "cache changed replay out of the tamper point"
        )
    end

    -- Refinement is a read of the committed claim. It must not replace build checkpoints with
    -- speculative machines from an input whose committed suffix is its revert state.
    local honest = prt.new_honest(dapp_contract, { cache_capacity = 1 })
    local cache = honest.machine_cache
    local native <close> = honest.new_machine(initial_state_hash)
    assert(type(native) == "userdata", "honest machine is wrapped")
    assert(type(cache.checkpoints[1].machine) == "userdata", "honest checkpoint machine is wrapped")
    local native_claim = honest.new_mcycle_computation_hash(honest, native)
    assert(getmetatable(native_claim) == nil and native_claim.machine == native, "honest computation hash is wrapped")
    assert(native_claim.unbundle == nil, "honest collector exposes strategy-only refinement")
    local native_uarch = honest.new_uarch_computation_hash(honest, native, {
        epoch_period_index = 0,
        first_leaf = 0,
        log2_leaf_count = honest.geometry.uarch_height,
        log2_bundle = LOG2_UARCH_BUNDLE,
    })
    assert(getmetatable(native_uarch) == nil and native_uarch.machine == native, "honest uarch collector is wrapped")
    assert(native_uarch.unbundle == nil, "honest uarch collector exposes strategy-only refinement")
    assert(getmetatable(honest.new_null_computation_hash(native)) == nil, "honest replay collector is wrapped")

    local honest_tree = honest:make_mcycle_tree()
    local checkpoint = assert(cache.checkpoints[1], "claim build retained no machine checkpoint").input_index
    honest_tree:open_bundle(honest.bundles_per_input)
    assert(cache.checkpoints[1].input_index == checkpoint, "mcycle refinement changed the machine cache")
    local cached = prt.new_honest(dapp_contract)
    assert(cached.new_machine == prt.new_machine, "honest machine default changed")
    assert(cached.new_mcycle_computation_hash == prt.new_mcycle_computation_hash)
    assert(cached.new_uarch_computation_hash == prt.new_uarch_computation_hash)
    local cached_tree = cached:make_mcycle_tree()
    for _, saved in ipairs(cached.machine_cache.checkpoints) do
        assert(type(saved.machine) == "userdata", "checkpoint machine is wrapped")
    end
    assert(cached_tree:get_root() == honest_tree:get_root(), "cache policy changed the mcycle root")
    assert(honest_tree:get_root() == util.read_file(assert(arg[5])), "mcycle root differs from CLI")
    for _, bundle in ipairs({
        0,
        99,
        honest.bundles_per_input,
        2 * honest.bundles_per_input,
        (1 << (honest.geometry.mcycle_height - LOG2_MCYCLE_BUNDLE)) - 1,
    }) do
        honest_tree:open_bundle(bundle)
        cached_tree:open_bundle(bundle)
        for leaf = bundle << LOG2_MCYCLE_BUNDLE, (bundle << LOG2_MCYCLE_BUNDLE) + (1 << LOG2_MCYCLE_BUNDLE) - 1 do
            assert(honest_tree:get_node(leaf, 0) == cached_tree:get_node(leaf, 0), "cache changed refinement")
        end
    end
    local first_uarch = honest:make_uarch_tree(1, 0)
    assert(first_uarch:get_root() == util.read_file(assert(arg[6])), "uarch root differs from CLI")
    first_uarch:open_bundle(0)
    first_uarch:open_bundle((1 << (honest.geometry.uarch_height - LOG2_UARCH_BUNDLE)) - 1)
    local rejected_uarch = honest:make_uarch_tree(2, 60000)
    rejected_uarch:open_bundle(0)
    rejected_uarch:open_bundle((1 << (honest.geometry.uarch_height - LOG2_UARCH_BUNDLE)) - 1)
    assert(
        honest:make_uarch_tree(3, 0):get_root() == cached:make_uarch_tree(3, 0):get_root(),
        "cache changed post-rejection uarch replay"
    )

    -- Every checkpoint is a virgin boundary. A rejected input offers none, so replay into and
    -- past it starts at the preceding boundary and rolls back exactly as the forward build did.
    local dense = prt.new_honest(dapp_contract, { cache_capacity = 64, cache_gap = 1 })
    local dense_tree = dense:make_mcycle_tree()
    local rejected_input_index = 1
    local retained_boundaries = {}
    for _, saved in ipairs(dense.machine_cache.checkpoints) do
        retained_boundaries[saved.input_index] = true
    end
    assert(
        retained_boundaries[0] and retained_boundaries[rejected_input_index] and retained_boundaries[3],
        "dense cache lost an accepted input's boundary"
    )
    assert(not retained_boundaries[rejected_input_index + 1], "the rejected input offered a boundary checkpoint")
    assert(dense_tree:get_root() == honest_tree:get_root(), "dense cache changed the mcycle root")
    local saved_checkpoints = {}
    for i, saved in ipairs(dense.machine_cache.checkpoints) do
        saved_checkpoints[i] = saved
    end
    for _, period_index in ipairs({ 16, 60000, honest.geometry.periods_per_input - 1 }) do
        local bundle = (rejected_input_index * honest.geometry.periods_per_input + period_index) >> LOG2_MCYCLE_BUNDLE
        honest_tree:open_bundle(bundle)
        dense_tree:open_bundle(bundle)
        for leaf = bundle << LOG2_MCYCLE_BUNDLE, (bundle << LOG2_MCYCLE_BUNDLE) + (1 << LOG2_MCYCLE_BUNDLE) - 1 do
            assert(
                honest_tree:get_node(leaf, 0) == dense_tree:get_node(leaf, 0),
                "dense cache changed refinement inside the rejected input"
            )
        end
    end
    assert(
        honest:make_uarch_tree(rejected_input_index + 2, 0):get_root()
            == dense:make_uarch_tree(rejected_input_index + 2, 0):get_root(),
        "dense cache changed replay past the rejected input"
    )
    assert(#saved_checkpoints == #dense.machine_cache.checkpoints, "refinement changed checkpoint count")
    for i, saved in ipairs(saved_checkpoints) do
        assert(dense.machine_cache.checkpoints[i] == saved, "refinement replaced a checkpoint")
    end

    -- Uarch collection and transition proofs replay from the rejected input's own boundary, both
    -- before and after its rejection, and their logs authenticate against the claims.
    local selected_input_index
    local dense_fork = dense.machine_cache.fork_closest
    dense.machine_cache.fork_closest = function(self, target)
        local m, index = dense_fork(self, target)
        selected_input_index = index
        return m, index
    end
    for _, period in ipairs({ 16, 60000 }) do
        local uarch = dense:make_uarch_tree(2, period)
        assert(selected_input_index == rejected_input_index, "uarch collection did not use the nearest boundary")
        uarch:open_bundle(0)
        local logs = dense:prove_state_transition(1, period, 0)
        assert(selected_input_index == rejected_input_index, "transition proof did not use the nearest boundary")
        local preceding_leaf = dense.geometry.periods_per_input + period - 1
        dense_tree:open_bundle(preceding_leaf >> LOG2_MCYCLE_BUNDLE)
        assert(
            cartesi.machine:verify_step_uarch(dense_tree:get_node(preceding_leaf, 0), logs.step_log)
                == uarch:get_node(0, 0),
            "cached transition does not match the uarch claim"
        )
        local reset_offset = cartesi.UARCH_CYCLE_MAX
        uarch:open_bundle(reset_offset >> LOG2_UARCH_BUNDLE)
        local reset_logs = dense:prove_state_transition(1, period, reset_offset)
        local after_step = cartesi.machine:verify_step_uarch(uarch:get_node(reset_offset - 1, 0), reset_logs.step_log)
        assert(
            cartesi.machine:verify_reset_uarch(after_step, reset_logs.reset_uarch_log)
                == uarch:get_node(reset_offset, 0),
            "cached reset does not match the uarch claim"
        )
    end

    -- Two consecutive rejections. Replay past them starts at the boundary before the chain and
    -- rolls each back once. The single-rejection reference has the same pre-feed and post-chain
    -- machine states.
    local chain_contract = {
        initial_state_hash = initial_state_hash,
        inputs = { inputs[1], inputs[2], inputs[2], inputs[3] },
        geometry = dapp_contract.geometry,
    }
    local chain = prt.new_honest(chain_contract, { cache_capacity = 128, cache_gap = 1 })
    local chain_tree = chain:make_mcycle_tree()
    local chain_reference = prt.new_honest(chain_contract, { cache_capacity = 1 })
    assert(chain_tree:get_root() == chain_reference:make_mcycle_tree():get_root(), "cache changed rejection-chain root")
    local chain_boundaries = {}
    for _, saved in ipairs(chain.machine_cache.checkpoints) do
        chain_boundaries[saved.input_index] = saved
    end
    assert(chain_boundaries[1] and chain_boundaries[4], "chain fixture lacks the boundaries around the chain")
    assert(not chain_boundaries[2] and not chain_boundaries[3], "a rejected input offered a boundary checkpoint")
    -- The cache API resolves the requested boundary, including an uncached boundary after
    -- rejection and positions past the last posted input. The target input remains undelivered.
    for _, target in ipairs({ 0, 1, 3, 4, 5 }) do
        local resolved <close> = chain.machine_cache:fork_input_boundary(target)
        local saved = chain_boundaries[target == 3 and 1 or math.min(target, 4)]
        assert(resolved:get_root_hash() == saved.machine:get_root_hash(), "cache returned the wrong input boundary")
    end
    local lookups, input_runs = 0, {}
    local replay_begins, replay_ends = 0, 0
    local fork_closest = chain.machine_cache.fork_closest
    chain.machine_cache.fork_closest = function(self, target)
        lookups = lookups + 1
        return fork_closest(self, target)
    end
    local new_null = chain.new_null_computation_hash
    chain.new_null_computation_hash = function(m)
        local claim = new_null(m)
        claim.begin_epoch = function()
            replay_begins = replay_begins + 1
        end
        claim.end_epoch = function()
            replay_ends = replay_ends + 1
        end
        claim.begin_input = function(_, index)
            input_runs[index] = (input_runs[index] or 0) + 1
        end
        return claim
    end
    local last_period = chain.geometry.periods_per_input - 1
    local chain_bundle = (2 * chain.geometry.periods_per_input + last_period) >> LOG2_MCYCLE_BUNDLE
    chain_tree:open_bundle(chain_bundle)
    assert(lookups == 1, "reverted-tail refinement performed multiple lookups")
    assert(replay_begins == 1 and replay_ends == 1, "cache replay bypassed the epoch driver's collector lifecycle")
    assert(
        not input_runs[0] and input_runs[1] == 1 and input_runs[2] == 1,
        "reverted-tail refinement did not replay from the boundary before the chain"
    )
    local reference_leaf = 2 * honest.geometry.periods_per_input - 1
    assert(
        chain_tree:get_node(3 * chain.geometry.periods_per_input - 1, 0) == honest_tree:get_node(reference_leaf, 0),
        "rejection-chain tail differs from the reference"
    )
    lookups, input_runs = 0, {}
    local after_chain = chain:make_uarch_tree(4, 0)
    assert(lookups == 1, "post-chain boundary performed multiple lookups")
    assert(
        not input_runs[0] and input_runs[1] == 1 and input_runs[2] == 1,
        "boundary replay did not roll back each rejected input once"
    )
    assert(after_chain:get_root() == honest:make_uarch_tree(3, 0):get_root(), "chain changed next-input uarch claim")

    -- The actual input-inclusion and first-step logs must authenticate against the state that
    -- the chain resolves to, not merely produce a matching computation root.
    after_chain:open_bundle(0)
    local logs = chain:prove_state_transition(3, 0, 0)
    local before = honest_tree:get_node(reference_leaf, 0)
    local after_send = cartesi.machine:verify_send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        chain.inputs[4],
        before,
        logs.send_cmio_log,
        before
    )
    assert(
        cartesi.machine:verify_step_uarch(after_send, logs.step_log) == after_chain:get_node(0, 0),
        "post-chain transition does not authenticate against the claim"
    )

    -- With only the initial checkpoint, replay runs every input once, rejections included.
    -- Restore the list afterward; these immutable machines remain owned by the original cache.
    local all_checkpoints = chain.machine_cache.checkpoints
    chain.machine_cache.checkpoints = { all_checkpoints[1] }
    lookups, input_runs = 0, {}
    local final_logs = chain:prove_state_transition(4, 0, 0)
    assert(lookups == 1, "sparse recovery performed more than one lookup")
    for index = 0, 3 do
        assert(input_runs[index] == 1, "sparse recovery skipped or repeated an input")
    end
    local final_boundary = chain_boundaries[4]
    local final_hash = final_boundary.machine:get_root_hash()
    local final_machine <close> = assert(final_boundary.machine:fork_server())
    final_machine:set_cleanup_call(require("cartesi.jsonrpc").SHUTDOWN)
    final_machine:run_uarch(1)
    assert(
        cartesi.machine:verify_step_uarch(final_hash, final_logs.step_log) == final_machine:get_root_hash(),
        "sparse recovery lost the accepted input's final state"
    )
    chain.machine_cache.checkpoints = all_checkpoints

    -- Result replay uses the same input lifecycle, and its proofs authenticate
    -- against the final state of the sampled execution.
    local result = honest:prove_outputs_merkle_root()
    local final_leaf = (1 << honest.geometry.mcycle_height) - 1
    assert(
        result.iflags_y_proof.root_hash == honest_tree:get_node(final_leaf, 0),
        "result replay differs from the claim's final state"
    )
    assert(honest:prove_output().output, "accepted output was lost during replay")

    local forger = dishonest.new_forger(dapp_contract, 0, "forged")
    assert(forger.inputs == dapp_contract.inputs, "forger replaced the contract's inputs")
    local machine <close> = forger.new_machine(initial_state_hash)
    forger.new_null_computation_hash(machine):begin_input(0, machine:read_reg("mcycle"))
    local fork <close> = machine:fork_server()
    local read_reg = machine.read_reg
    assert(read_reg == machine.read_reg and read_reg == fork.read_reg, "machine forwarders are not shared")
    assert(machine.send_cmio_response == machine.overrides.send_cmio_response, "forwarder masked an override")
    assert(read_reg(machine, "mcycle") == machine.machine:read_reg("mcycle"), "forwarder used the wrong receiver")
    assert(read_reg(fork, "mcycle") == fork.machine:read_reg("mcycle"), "shared forwarder used the wrong receiver")
    assert(
        fork.overrides == machine.overrides and fork.state ~= machine.state,
        "fork lost overrides or shared mutable input context"
    )
    fork.state.input_index = 1
    machine:swap(fork)
    assert(machine.state.input_index == 1 and fork.state.input_index == 0, "swap did not restore input context")

    -- Terminal inputs and empty epochs must fill logical windows even when the
    -- physical counter cannot advance (including the unsigned counter maximum).
    for _, terminal in ipairs({ "halt", "exception", "unexpected", "overflow", "empty", "halt_after_input" }) do
        local function terminal_machine(hash)
            local m = prt.new_machine(hash)
            if terminal == "halt" then
                m:write_reg("iflags_Y", 0)
                m:write_reg("iflags_H", 1)
            elseif terminal == "exception" or terminal == "unexpected" then
                local reason = terminal == "exception" and cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION or 0xffff
                m:write_reg(
                    "htif_tohost",
                    (cartesi.HTIF_DEV_YIELD << 56) | (cartesi.HTIF_YIELD_CMD_MANUAL << 48) | (reason << 32)
                )
            elseif terminal == "overflow" then
                m:write_reg("iflags_Y", 0)
                m:write_reg("mcycle", cartesi.MCYCLE_MAX)
            end
            return m
        end
        -- Force a halt just after delivery in this fixture, identically for sampled execution
        -- and plain replay. Later logical inputs idle at the halt without delivery.
        local function stop_after_delivery(m)
            if terminal == "halt_after_input" then
                m:write_reg("iflags_H", 1)
            end
        end
        local contract = {
            initial_state_hash = initial_state_hash,
            geometry = dapp_contract.geometry,
            inputs = terminal == "empty" and {} or inputs,
        }
        local counts = { outer = 0, refined = 0, uarch = 0 }
        local function observe_inputs(claim, m)
            local run = claim.run
            claim.run = function(self, target)
                stop_after_delivery(m)
                return run(self, target)
            end
            return claim
        end
        local player = prt.new_honest(contract, {
            new_machine = terminal_machine,
            new_mcycle_computation_hash = function(self, m, window)
                local kind = window and "refined" or "outer"
                counts[kind] = counts[kind] + 1
                return observe_inputs(prt.new_mcycle_computation_hash(self, m, window), m)
            end,
            new_uarch_computation_hash = function(self, m, window)
                counts.uarch = counts.uarch + 1
                return observe_inputs(prt.new_uarch_computation_hash(self, m, window), m)
            end,
        })
        player.new_null_computation_hash = function(m)
            return observe_inputs(prt.new_null_computation_hash(m), m)
        end
        local reference <close> = terminal_machine(initial_state_hash)
        if terminal == "halt_after_input" then
            reference:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, inputs[1], reference:get_root_hash())
            stop_after_delivery(reference)
        end
        local terminal_root = reference:get_root_hash()
        local expected = terminal_root
        for _ = 1, contract.geometry.mcycle_height do
            expected = keccak(expected, expected)
        end
        local tree = player:make_mcycle_tree()
        assert(tree:get_root() == expected, terminal .. " has the wrong fixed-point tail")
        tree:open_bundle(0)
        tree:open_bundle((1 << (contract.geometry.mcycle_height - LOG2_MCYCLE_BUNDLE)) - 1)
        local uarch = player:make_uarch_tree(3, 60000)
        uarch:open_bundle(0)
        uarch:open_bundle((1 << (contract.geometry.uarch_height - LOG2_UARCH_BUNDLE)) - 1)
        assert(
            counts.outer == 1 and counts.refined == 2 and counts.uarch == 3,
            "build or refinement bypassed the selected collector factory"
        )
        local terminal_logs = player:prove_state_transition(2, 60000, 0)
        assert(
            cartesi.machine:verify_step_uarch(terminal_root, terminal_logs.step_log) == uarch:get_node(0, 0),
            "terminal step does not authenticate against the claim"
        )
        local reset_offset = cartesi.UARCH_CYCLE_MAX
        uarch:open_bundle(reset_offset >> LOG2_UARCH_BUNDLE)
        local reset_logs = player:prove_state_transition(2, 60000, reset_offset)
        local after_step = cartesi.machine:verify_step_uarch(uarch:get_node(reset_offset - 1, 0), reset_logs.step_log)
        assert(
            cartesi.machine:verify_reset_uarch(after_step, reset_logs.reset_uarch_log)
                == uarch:get_node(reset_offset, 0),
            "terminal reset does not authenticate against the claim"
        )
        local boundary = player:make_uarch_tree(3, 0)
        boundary:open_bundle(0)
        local boundary_logs = player:prove_state_transition(2, 0, 0)
        local boundary_root = terminal_root
        if terminal ~= "empty" then
            boundary_root = cartesi.machine:verify_send_cmio_response(
                cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
                inputs[3],
                terminal_root,
                boundary_logs.send_cmio_log,
                terminal_root
            )
            assert(boundary_root == terminal_root, "terminal input delivery was not a no-op")
        else
            assert(not boundary_logs.send_cmio_log, "empty epoch invented an input-inclusion log")
        end
        assert(
            cartesi.machine:verify_step_uarch(boundary_root, boundary_logs.step_log) == boundary:get_node(0, 0),
            "terminal input-boundary proof does not authenticate against the claim"
        )
    end
end

print("prt-test: ok")
