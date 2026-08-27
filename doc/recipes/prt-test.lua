-- Checks the parts of the PRT game that need no machine. First the claim trees over runs, join
-- proofs, and the match walk: two synthetic claims that differ at one leaf are walked down
-- under every claim order, and the walk must isolate exactly that leaf, name what each claim
-- committed to there, and expose the agreed state before it when the leaf is a right one.
-- Then the referee server, driven over loopback sockets by fake players living in the same
-- dispatcher: the tournament lifecycle, first-valid moves, rejected proofs that leave their
-- connection open, and claims eliminated once every holder answered without proof or closed.
-- The sealer connects while the mcycle tournament is open and must not be asked to submit.
-- Runs in well under a second and exits nonzero on the first failure.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local socket = require("socket")
local prtu = require("prtu")

local keccak = cartesi.keccak256
local push_run = prtu.push_run

local HEIGHT = 5
local LEAVES = 1 << HEIGHT

-- A claim over leaves that repeat `base` except at `lie`, which holds `fake`. Built either
-- flat or bundled 2^2 leaves per stored entry, so the refine path is exercised too.
local function synthetic_claim(base, lie, fake, bundled)
    local leaves = {}
    for i = 0, LEAVES - 1 do
        leaves[i] = i == lie and fake or base
    end
    local function leaf_runs(first, count)
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
            local entry_tree = prtu.new_tree(entry_height, 0, leaf_runs(entry << entry_height, 1 << entry_height), nil)
            push_run(runs, entry_tree:root(), 1)
        end
        tree = prtu.new_tree(HEIGHT, entry_height, runs, function(_, entry)
            return leaf_runs(entry << entry_height, 1 << entry_height)
        end)
    else
        tree = prtu.new_tree(HEIGHT, 0, leaf_runs(0, LEAVES), nil)
    end
    local left, right = tree:children(HEIGHT, 0)
    local proof = tree:prove(LEAVES - 1)
    hash_tree.verify_slice(proof)
    assert(
        proof.target_address == LEAVES - 1
            and proof.log2_target_size == 0
            and proof.log2_root_size == HEIGHT
            and #proof.sibling_hashes == HEIGHT
            and proof.root_hash == tree:root(),
        "wrong final-state proof"
    )
    return {
        root = tree:root(),
        left = left,
        right = right,
        final_state = proof.target_hash,
        tree = tree,
        leaves = leaves,
    }
end

-- The move a player holding the on-turn claim makes, as ops.advance does in prt-player.lua.
local function open(m)
    local tree = m.turn.tree
    local l, r = tree:children(m.height, m.index)
    local move = { l = l, r = r }
    if m.height > 1 then
        local descend_left = l ~= m.left_node
        move.nl, move.nr = tree:children(m.height - 1, descend_left and 2 * m.index or 2 * m.index + 1)
    end
    return move
end

-- Walks a match to its dispute, checking every move validates and a corrupted one does not.
local function walk(one, two)
    local m = prtu.new_match(one, two, HEIGHT)
    while true do
        local move = open(m)
        assert(prtu.valid_move(m, move), "the honest move failed validation")
        local corrupted = { l = move.r, r = move.l, nl = move.nl, nr = move.nr }
        assert(not prtu.valid_move(m, corrupted) or move.l == move.r, "a swapped move validated")
        local dispute = prtu.advance_match(m, move)
        if dispute then
            return dispute
        end
    end
end

local base, fake = keccak("base"), keccak("fake")
for _, lie in ipairs({ 0, 1, 6, 13, LEAVES - 1 }) do
    for _, bundled in ipairs({ false, true }) do
        local honest = synthetic_claim(base, nil, nil, bundled)
        local liar = synthetic_claim(base, lie, fake, bundled)
        assert(honest.root ~= liar.root)
        -- honest opens first
        local dispute = walk(honest, liar)
        assert(dispute.leaf_index == lie, "walk missed the divergent leaf")
        assert(dispute.d1 == base and dispute.d2 == fake, "walk misattributed the leaves")
        -- liar opens first: the same leaf, the commitments swapped
        local mirrored = walk(liar, honest)
        assert(mirrored.leaf_index == lie and mirrored.d1 == fake and mirrored.d2 == base, "walk is not symmetric")
        -- a right leaf exposes the agreed left leaf, a left leaf does not
        if lie % 2 == 1 then
            assert(dispute.agreed == honest.leaves[lie - 1] and mirrored.agreed == dispute.agreed, "wrong agreed leaf")
        else
            assert(dispute.agreed == nil and mirrored.agreed == nil, "left leaf exposed an agreed state")
            if lie > 0 then
                local proof = liar.tree:prove(lie - 1)
                assert(proof.target_hash == honest.leaves[lie - 1], "the leaf before the divergence is not agreed")
                hash_tree.verify_slice(proof)
                assert(proof.root_hash == liar.root, "agreed-leaf proof has the wrong root")
                assert(proof.root_hash ~= honest.root or lie == 0)
            end
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
local function with_server(scenario)
    local listener = assert(socket.bind("127.0.0.1", 0))
    local _, port = listener:getsockname()
    local dispatcher = prtu.new_dispatcher()
    local server = prtu.new_server(dispatcher, listener)
    server:accept()
    local function client(hello, handler)
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
        scenario(server, client, wait_connections)
    end)
end

-- A player that submits `claim` to any tournament and answers every move with `move`.
local function submitter(claim, move)
    return function(request)
        if request.code:find("join") then
            return { label = claim, value = claim }
        end
        return move(request)
    end
end

local function is_valid(v)
    return v == "valid" and v
end

with_server(function(server, client, wait_connections)
    -- Two players connect before the sealer, one after it. The mcycle tournament must gather
    -- exactly the first two, and must not resolve before the sealer seals it.
    local answered = {}
    local function answer(value)
        return function()
            answered[#answered + 1] = value
            return { value = value }
        end
    end
    client(nil, submitter("a", answer("valid")))
    client(nil, submitter("b", answer("invalid")))
    client({ role = "sealer" }, function(request)
        return { value = request.code:match('"(.-)"') }
    end)
    local submissions = server:open_tournament("root", nil, nil, "return player:join()")
    table.sort(submissions, function(x, y)
        return x.value < y.value
    end)
    assert(
        #submissions == 2 and submissions[1].value == "a" and submissions[2].value == "b",
        "mcycle tournament gathered the wrong submissions"
    )
    assert(server.sealer and server.sealer.is_sealer, "the sealer was not adopted")
    local a, b = submissions[1].connection, submissions[2].connection
    server:add_holder("x", a)
    server:add_holder("x", b)
    -- A late joiner, after the seal, is not part of the mcycle tournament.
    client(nil, submitter("c", answer("valid")))
    wait_connections(4)

    -- First valid move wins, the rejected proof leaves its connection open.
    assert(
        server:accept_first(server:subscribers({ "x" }), nil, is_valid, "return 1") == "valid",
        "valid move not taken"
    )
    assert(not a.dead and not b.dead, "a rejected proof closed a connection")

    -- The acceptor's result, rather than the submitted value, is returned.
    local mapped = server:accept_first({ a }, nil, function(v)
        return is_valid(v) and "mapped"
    end, "return 1")
    assert(mapped == "mapped", "accept_first did not return the acceptor result")

    -- A valid move resolves the request while another holder still owes a reply. When that
    -- holder is asked again, TCP delivers the old reply first; the referee drops it by count
    -- and accepts the following reply for the current request.
    local delayed = false
    client(nil, function(request)
        if request.code == "return 'early'" then
            delayed = true
            return nil
        elseif delayed then
            delayed = false
            return cartesi.tojson({ value = "invalid" }, -1) .. "\n" .. cartesi.tojson({ value = "valid" }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(5)
    local m = server.connections[5]
    assert(server:accept_first({ m, a }, nil, is_valid, "return 'early'") == "valid", "valid move not taken early")
    assert(server:accept_first({ m }, nil, is_valid, "return 'after-early'") == "valid", "stale reply was accepted")
    assert(m.stale_requests_pending == 0 and not m.current_request, "stale reply was not consumed")
    assert(not m.dead, "a pending holder was closed")
    -- Without a valid move, the request waits for every holder, and resolves to nil only then.
    local replies_seen = 0
    client(nil, function()
        replies_seen = replies_seen + 1
        return { value = "invalid" }
    end)
    wait_connections(6)
    local n = server.connections[6]
    assert(server:accept_first({ n, b }, nil, is_valid, "return 1") == nil, "an unproved move was taken")
    assert(replies_seen == 1, "the request resolved before every holder answered")
    assert(not n.dead and not b.dead, "an unproved move closed a connection")

    -- A nested tournament asks only its audience, and seals at once.
    local nested = server:open_tournament("nested", { a }, nil, "return player:join()")
    assert(#nested == 1 and nested[1].value == "a", "nested tournament asked the wrong audience")

    -- Every holder answers without proof: the request resolves to nil, connections stay open.
    assert(server:accept_first({ b }, nil, is_valid, "return 1") == nil, "an unproved move was taken")
    assert(not b.dead, "an unproved move closed its connection")

    -- A holder that closes counts as answered. With every holder gone, the claim is unanswered.
    client(nil, function()
        return "close"
    end)
    wait_connections(7)
    local replies = server:collect(nil, nil, "return player:label()")
    local d = server.connections[7]
    assert(d.dead and #replies == 5, "the closing client was not dropped from the collection")
    assert(
        server:accept_first({ d }, nil, is_valid, "return 1") == nil,
        "a request to a closed connection did not resolve"
    )

    -- A reply whose value violates the request's schema is an invalid operation, not a
    -- malformed connection. Asked alone, a holder answering with such a value leaves the
    -- request with nothing, and the holder open. This is the invariant itself, and needs no
    -- assumption about the order two sockets become readable.
    prtu.SCHEMA_DICT.Pair = { l = "Base64", r = "Base64" }
    prtu.SCHEMA_DICT.PairReply = { value = "Pair" }
    -- Each fake client answers typed requests with its fixed value.
    local function typed_client(value, schema)
        client(nil, function(request)
            if request.schema == "Pair" then
                return cartesi.tojson({ value = value }, -1, schema, prtu.SCHEMA_DICT)
            end
            return { value = "valid" }
        end)
        wait_connections(#server.connections + 1)
        return server.connections[#server.connections]
    end
    local function well_typed(v)
        return v.l == "a" and v.r == "b" and v
    end
    local bad = typed_client({ l = 1, r = "not base64!" })
    assert(server:accept_first({ bad }, "Pair", well_typed, "return 1") == nil, "a schema-invalid value was taken")
    assert(not next(server.active), "accept_first left a resolved request active")
    assert(not bad.dead, "a schema-invalid reply closed its connection")
    -- Alongside a well-typed reply, whichever arrives first, the well-typed value is taken and
    -- both connections stay open.
    local good = typed_client({ l = "a", r = "b" }, "PairReply")
    local taken = server:accept_first({ bad, good }, "Pair", well_typed, "return 1")
    assert(taken and taken.l == "a", "the well-typed reply was not taken")
    assert(not next(server.active), "accept_first left a resolved request active")
    assert(not bad.dead and not good.dead, "a schema-invalid reply closed a connection")

    -- An undecodable line closes its sender.
    client(nil, function()
        return "this is not json"
    end)
    wait_connections(10)
    server:collect(nil, nil, "return player:label()")
    local dead = 0
    for _, connection in ipairs(server.connections) do
        if connection.dead then
            dead = dead + 1
        end
    end
    assert(dead == 2, "an undecodable line did not close its sender")
    assert(not a.dead and not b.dead, "a live player was closed")

    -- Sealing is connection-bound. An extra player reply cannot be consumed as a seal; the
    -- tournament closes only on the sealer's reply and includes the player's submission.
    client(nil, function(request)
        if request.code:find("join") then
            return cartesi.tojson({ value = "forger" }, -1) .. "\n" .. cartesi.tojson({ value = "t2" }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(11)
    local f = server.connections[11]
    local t2 = server:open_tournament("t2", { f }, nil, "return player:join()")
    assert(#t2 == 1 and t2[1].value == "forger" and not f.dead, "the forged seal was not ignored")

    -- A connection announces its role once. Announcing again closes it, and so does a second
    -- sealer.
    client({ role = "player" }, function()
        return { role = "player" }
    end)
    wait_connections(12)
    server:collect({ server.connections[12] }, nil, "return 1")
    assert(server.connections[12].dead, "a repeated role announcement was accepted")
    client({ role = "sealer" }, function()
        return "close"
    end)
    wait_connections(13)
    assert(server.connections[13].dead and server.sealer == server.connections[3], "a second sealer was accepted")
end)

-- A seal naming another tournament is a sealer bug and fails the referee.
local ok, err = pcall(with_server, function(server, client, wait_connections)
    client({ role = "sealer" }, function()
        return { value = "other" }
    end)
    wait_connections(1)
    server:open_tournament("t", {}, nil, "return player:join()")
end)
assert(not ok and err:find("did not seal the tournament asked"), "a wrong seal was accepted")

-- The sealer going away fails the referee outright: a tournament could never close again.
ok, err = pcall(with_server, function(server, client, wait_connections)
    client({ role = "sealer" }, function()
        return "close"
    end)
    wait_connections(1)
    server:open_tournament("t", {}, nil, "return player:join()")
end)
assert(not ok and err:find("the sealer went away"), "sealer EOF did not fail the referee")
print("prt-test: ok")
