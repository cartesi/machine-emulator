-- Checks the parts of the PRT game that need no machine. First the claim trees over runs, claim
-- proofs, and the match walk: two synthetic claims that differ at one leaf are walked down
-- under every claim order, and the walk must isolate exactly that leaf, name what each claim
-- committed to there, and carry a proof of the agreed state before it in the final response.
-- Then the referee server, driven over loopback sockets by fake players living in the same
-- dispatcher: the tournament lifecycle, first-valid moves, rejected proofs that leave their
-- connection open, and claims eliminated once every holder answered without proof or closed.
-- The sealer connects while the mcycle tournament is open and must not be asked to submit.
-- Runs in well under a second and exits nonzero on the first failure.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local socket = require("socket")
local prtu = require("prtu")
local prt = require("prt")

local keccak = cartesi.keccak256
local push_run = prtu.push_run

local HEIGHT = 5
local LEAVES = 1 << HEIGHT
local INITIAL_STATE_HASH = keccak("initial")

-- A claim over leaves that repeat `base_state_hash` except at `lie`, which holds
-- `fake_state_hash`. Built either
-- flat or bundled 2^2 leaves per stored entry, so the refine path is exercised too.
local function make_synthetic_claim(base_state_hash, lie, fake_state_hash, bundled)
    local leaves = {}
    for i = 0, LEAVES - 1 do
        leaves[i] = i == lie and fake_state_hash or base_state_hash
    end
    local function build_leaf_runs(first, count)
        local runs = {}
        for i = first, first + count - 1 do
            push_run(runs, leaves[i], 1)
        end
        return runs
    end
    local tree
    if bundled then
        local entry_height = 2
        local runs = {}
        for entry = 0, (LEAVES >> entry_height) - 1 do
            local entry_tree =
                prtu.new_tree(entry_height, 0, build_leaf_runs(entry << entry_height, 1 << entry_height), nil)
            push_run(runs, entry_tree:get_root(), 1)
        end
        tree = prtu.new_tree(HEIGHT, entry_height, runs, function(_, entry)
            return build_leaf_runs(entry << entry_height, 1 << entry_height)
        end)
    else
        tree = prtu.new_tree(HEIGHT, 0, build_leaf_runs(0, LEAVES), nil)
    end
    local computation_hash_left, computation_hash_right = tree:get_children(HEIGHT, 0)
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
    local turn_left_node, turn_right_node = tree:get_children(match.height, match.index)
    local descend_left = turn_left_node ~= match.other_left_node
    local turn_next_left_node, turn_next_right_node =
        tree:get_children(match.height - 1, descend_left and 2 * match.index or 2 * match.index + 1)
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
    local turn_left_node, turn_right_node = tree:get_children(1, match.index)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= match.other_left_node
    local state_index = 2 * match.index + (descend_left and 0 or 1)
    if state_index ~= 0 then
        response.agreed_state_hash_proof = tree:prove(state_index - 1)
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
for _, lie in ipairs({ 0, 1, 6, 13, LEAVES - 1 }) do
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
-- every request line with what `handler` returns for it: a reply table (encoded as is),
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
                    local reply = handler(cartesi.fromjson(line))
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
                if connection.is_player or connection.is_sealer or connection.dead then
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

-- A player that returns `claim` to any tournament and answers every request with `answer`.
local function make_claimer(claim, answer)
    return function(request)
        if request.operation == "commit_mcycle_claim" then
            return { label = claim, value = claim }
        end
        return answer(request)
    end
end

local function is_valid(v)
    return v == "valid" and v
end

local function define_request(name, response_schema)
    return prtu.define_request(name, nil, response_schema)
end

run_with_server(function(server, run_client, wait_connections)
    -- Two players connect before the sealer, one after it. The mcycle tournament must gather
    -- exactly the first two, and must not resolve before the sealer seals it.
    local answered = {}
    local function answer(value)
        return function()
            answered[#answered + 1] = value
            return { value = value }
        end
    end
    run_client(nil, make_claimer("a", answer("valid")))
    run_client(nil, make_claimer("b", answer("invalid")))
    run_client({ role = "sealer" }, function()
        return { value = true }
    end)
    server:accept_subscribers("initial")
    local responses =
        server:collect_claims(server:get_subscribers({ "initial" }), define_request("commit_mcycle_claim"))
    assert(#server.open_phases == 0, "sealed phases were retained")
    table.sort(responses, function(x, y)
        return x.value < y.value
    end)
    assert(
        #responses == 2 and responses[1].value == "a" and responses[2].value == "b",
        "mcycle tournament gathered the wrong claims"
    )
    assert(server.sealer and server.sealer.is_sealer, "the sealer was not adopted")
    local a, b = responses[1].connection, responses[2].connection
    server:subscribe("x", a)
    server:subscribe("x", b)
    -- A late joiner, after the seal, is not part of the mcycle tournament.
    run_client(nil, make_claimer("c", answer("valid")))
    wait_connections(4)

    -- The first valid response wins; a rejected response leaves its connection open.
    assert(
        server:accept_first_valid(server:get_subscribers({ "x" }), is_valid, define_request("answer")) == "valid",
        "valid response not taken"
    )
    assert(not a.dead and not b.dead, "a rejected proof closed a connection")

    -- The acceptor's result, rather than the submitted value, is returned.
    local mapped = server:accept_first_valid({ a }, function(v)
        return is_valid(v) and "mapped"
    end, define_request("mapped"))
    assert(mapped == "mapped", "accept_first_valid did not return the acceptor result")

    -- A valid response resolves the request while another holder still owes a reply. When that
    -- holder is asked again, TCP delivers the old reply first; the referee drops it by count
    -- and accepts the following reply for the current request.
    local delayed = false
    run_client(nil, function(wire_request)
        if wire_request.operation == "early" then
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
        server:accept_first_valid({ delayed_connection, a }, is_valid, define_request("early")) == "valid",
        "valid response not taken early"
    )
    assert(
        server:accept_first_valid({ delayed_connection }, is_valid, define_request("after_early")) == "valid",
        "stale reply was accepted"
    )
    assert(
        delayed_connection.stale_requests_pending == 0 and not delayed_connection.current_request,
        "stale reply was not consumed"
    )
    assert(not delayed_connection.dead, "a pending holder was closed")
    -- Without a valid response, the request waits for every holder, and resolves to nil only then.
    local replies_seen = 0
    run_client(nil, function()
        replies_seen = replies_seen + 1
        return { value = "invalid" }
    end)
    wait_connections(6)
    local n = server.connections[6]
    assert(
        server:accept_first_valid({ n, b }, is_valid, define_request("answer")) == nil,
        "an invalid response was taken"
    )
    assert(replies_seen == 1, "the request resolved before every holder answered")
    assert(not n.dead and not b.dead, "an invalid response closed a connection")

    -- A nested tournament asks only its audience, and seals at once.
    local nested = server:collect_claims({ a }, define_request("commit_mcycle_claim"))
    assert(#nested == 1 and nested[1].value == "a", "nested tournament asked the wrong audience")
    assert(#server.open_phases == 0, "sealed nested tournament was retained")

    -- Every holder answers without proof: the request resolves to nil, connections stay open.
    assert(server:accept_first_valid({ b }, is_valid, define_request("answer")) == nil, "an invalid response was taken")
    assert(not b.dead, "an invalid response closed its connection")

    -- A holder that closes counts as answered. With every holder gone, the claim is unanswered.
    run_client(nil, function()
        return "close"
    end)
    wait_connections(7)
    local replies = server:collect(nil, define_request("label"))
    local d = server.connections[7]
    assert(d.dead and #replies == 5, "the closing client was not dropped from the collection")
    assert(
        server:accept_first_valid({ d }, is_valid, define_request("answer")) == nil,
        "a request to a closed connection did not resolve"
    )

    -- A reply whose value violates the operation's response schema is an invalid operation, not a
    -- malformed connection. Asked alone, a holder answering with such a value leaves the
    -- request with nothing, and the holder open. This is the invariant itself, and needs no
    -- assumption about the order two sockets become readable.
    prtu.SCHEMA_DICT.PairResponse = { l = "Base64", r = "Base64" }
    prtu.SCHEMA_DICT.PairResponseEnvelope = { value = "PairResponse" }
    -- Each fake client answers typed requests with its fixed value.
    local function run_typed_client(value, schema)
        run_client(nil, function(wire_request)
            if wire_request.operation == "typed" then
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
        server:accept_first_valid({ bad }, is_well_typed, define_request("typed", "PairResponse")) == nil,
        "a schema-invalid value was taken"
    )
    assert(not next(server.active), "accept_first_valid left a resolved request active")
    assert(not bad.dead, "a schema-invalid reply closed its connection")
    -- Alongside a well-typed reply, whichever arrives first, the well-typed value is taken and
    -- both connections stay open.
    local good = run_typed_client({ l = "a", r = "b" }, "PairResponseEnvelope")
    local taken = server:accept_first_valid({ bad, good }, is_well_typed, define_request("typed", "PairResponse"))
    assert(taken and taken.l == "a", "the well-typed reply was not taken")
    assert(not next(server.active), "accept_first_valid left a resolved request active")
    assert(not bad.dead and not good.dead, "a schema-invalid reply closed a connection")

    -- An undecodable line closes its sender.
    run_client(nil, function()
        return "this is not json"
    end)
    wait_connections(10)
    server:collect(nil, define_request("label"))
    local dead = 0
    for _, connection in ipairs(server.connections) do
        if connection.dead then
            dead = dead + 1
        end
    end
    assert(dead == 2, "an undecodable line did not close its sender")
    assert(not a.dead and not b.dead, "a live player was closed")

    -- Sealing is connection-bound. An extra player reply cannot be consumed as a seal; the
    -- tournament closes only on the sealer's reply and includes the player's claim.
    run_client(nil, function(wire_request)
        if wire_request.operation == "commit_mcycle_claim" then
            return cartesi.tojson({ value = "forger" }, -1) .. "\n" .. cartesi.tojson({ value = true }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(11)
    local f = server.connections[11]
    local t2 = server:collect_claims({ f }, define_request("commit_mcycle_claim"))
    assert(#t2 == 1 and t2[1].value == "forger" and not f.dead, "the forged seal was not ignored")

    -- A connection announces its role once. Announcing again closes it, and so does a second
    -- sealer.
    run_client({ role = "player" }, function()
        return { role = "player" }
    end)
    wait_connections(12)
    server:collect({ server.connections[12] }, define_request("again"))
    assert(server.connections[12].dead, "a repeated role announcement was accepted")
    run_client({ role = "sealer" }, function()
        return "close"
    end)
    wait_connections(13)
    assert(server.connections[13].dead and server.sealer == server.connections[3], "a second sealer was accepted")

    -- A stale reply is still a protocol line: malformed JSON closes the connection before the
    -- stale position is discarded.
    local delayed_malformed = false
    run_client(nil, function(wire_request)
        if wire_request.operation == "malformed_early" then
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
        server:accept_first_valid({ malformed, a }, is_valid, define_request("malformed_early")) == "valid",
        "valid response did not resolve before the delayed malformed reply"
    )
    assert(
        server:accept_first_valid({ malformed }, is_valid, define_request("after_malformed")) == nil,
        "a malformed stale line produced a value"
    )
    assert(malformed.dead, "a malformed stale line did not close its sender")
end)

-- An invalid seal response is a sealer bug and fails the referee.
local ok, err = pcall(run_with_server, function(server, run_client, wait_connections)
    run_client({ role = "sealer" }, function()
        return { value = "other" }
    end)
    wait_connections(1)
    server:collect_claims({}, define_request("commit_mcycle_claim"))
end)
assert(not ok and err:find("did not close the phase asked"), "an invalid seal was accepted")

-- The sealer going away fails the referee outright: a tournament could never close again.
ok, err = pcall(run_with_server, function(server, run_client, wait_connections)
    run_client({ role = "sealer" }, function()
        return "close"
    end)
    wait_connections(1)
    server:collect_claims({}, define_request("commit_mcycle_claim"))
end)
assert(not ok and err:find("the sealer went away"), "sealer EOF did not fail the referee")
print("prt-test: ok")
