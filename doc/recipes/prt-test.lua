-- Checks claim trees, proofs, and the referee with synthetic state, then, when given an initial
-- machine hash and inputs, checks checkpoint replay against a real machine. The synthetic claims
-- are walked under both claim orders. The loopback referee tests its tournament lifecycle,
-- valid moves, rejected proofs that leave connections open, and logical-block barriers.
-- The real-machine cases cover tampering during replay
-- and refinement inside and past rejected inputs. Exits nonzero on the first failure.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local socket = require("socket")
local dishonest = require("prt-dishonest")
local prtu = require("prtu")
local prt = require("prt")
local EVERYONE = prtu.EVERYONE
assert(require("prt-time-test"))

local keccak = cartesi.keccak256
local LOG2_BUNDLE_MCYCLE_COUNT = prt.LOG2_BUNDLE_MCYCLE_COUNT
local LOG2_BUNDLE_UARCH_CYCLE_COUNT = prt.LOG2_BUNDLE_UARCH_CYCLE_COUNT

--------------------------------------------------------------------------------
-- Machine checkpoint cache
--------------------------------------------------------------------------------

local function new_fake_machine(root_hash, mcycle, counts)
    counts = counts or { live = 0 }
    counts.live = counts.live + 1
    local machine = { root_hash = root_hash, mcycle = mcycle or 0, counts = counts }
    function machine:fork_server()
        assert(not self.fail_clone, "injected clone failure")
        return new_fake_machine(self.root_hash, self.mcycle, counts)
    end
    function machine.set_cleanup_call() end
    function machine:read_reg()
        return self.mcycle
    end
    function machine:get_root_hash()
        return self.root_hash
    end
    function machine:shutdown_server()
        if not self.shutdown then
            self.shutdown = true
            counts.live = counts.live - 1
        end
    end
    function machine:swap(other)
        self.root_hash, other.root_hash = other.root_hash, self.root_hash
        self.mcycle, other.mcycle = other.mcycle, self.mcycle
        self.shutdown, other.shutdown = other.shutdown, self.shutdown
    end
    function machine.run()
        return cartesi.BREAK_REASON_YIELDED_MANUALLY
    end
    function machine.receive_cmio_request()
        return cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, ""
    end
    function machine:send_cmio_response(_, data, revert_root_hash)
        assert(revert_root_hash == self.root_hash, "revert root hash does not match the machine root hash")
        self.root_hash = data
    end
    return setmetatable(machine, { __close = machine.shutdown_server })
end

local function noop() end

-- All builders expose machine methods with the native receiver, but not machine data fields.
do
    local machine = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(machine)
    local geometry = prt.new_geometry(10)
    for _, builder in ipairs({
        prt.new_null_computation_hash(machine),
        prt.new_mcycle_computation_hash(geometry.log2_mcycles_per_period, cache, machine),
        prt.new_uarch_computation_hash(geometry.log2_mcycles_per_period, machine, 0),
    }) do
        assert(builder:get_root_hash() == "initial", "builder did not forward to its machine")
        assert(rawget(builder, "get_root_hash") == builder.get_root_hash, "builder did not cache its forwarded method")
        machine.root_hash = "changed"
        assert(builder:get_root_hash() == "changed", "forwarded method read stale state")
        assert(builder.root_hash == nil and builder.counts == nil, "builder exposed machine data fields")
        assert(builder.absent == nil, "builder invented a missing method")
        machine.root_hash = "initial"
    end
end

do
    local cache <close> = prt.new_machine_cache(new_fake_machine("0"), 5, 1)
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
    local machine, owner <close> = cache:clone_at_input_boundary(7, noop) -- luacheck: ignore 211
    assert(machine:get_root_hash() == "6")
    assert(not pcall(cache.consider, cache, 8, new_fake_machine("8")), "cache accepted an out-of-order checkpoint")
end

do
    local cache <close> = prt.new_machine_cache(new_fake_machine("0"), 5, 3)
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
    local cache <close> = prt.new_machine_cache(new_fake_machine("0"), 3, 1)
    local machine = new_fake_machine("boundary", 100)
    cache:consider(1, machine)
    local saved = cache.checkpoints[2]
    machine.root_hash = "changed"
    local fork, owner <close> = cache:clone_at_input_boundary(1, noop)
    assert(fork:get_root_hash() == "boundary" and fork:read_reg("mcycle") == 100)
    fork.root_hash = "working"
    assert(saved.machine:get_root_hash() == "boundary", "working fork shares the saved machine")
    owner:close()
    cache:consider(2, machine)
    cache:consider(3, machine)
    cache:consider(4, machine)
    assert(saved.machine.shutdown, "eviction did not close the saved machine")
    assert(not cache.checkpoints[1].machine.shutdown, "eviction closed the initial checkpoint")
end

-- Owners and cache shutdown release servers immediately, without a collection cycle. Snapshots
-- belong to working machines, so nested replay cannot consume the outer run's backup.
do
    local initial = new_fake_machine("initial")
    local counts = initial.counts
    local cache <close> = prt.new_machine_cache(initial, 4, 1)
    local outer, outer_owner <close> = cache:clone_at_input_boundary(0, noop)
    cache:snapshot(outer)
    outer.root_hash = "outer"
    assert(counts.live == 3, "snapshot did not retain an independent backup")
    assert(not pcall(cache.snapshot, cache, outer), "second unresolved snapshot was accepted")
    do
        local inner, inner_owner <close> = cache:clone_at_input_boundary(0, noop) -- luacheck: ignore 211
        assert(inner.root_hash == "initial", "clone shared the outer working state")
        cache:snapshot(inner)
        inner.root_hash = "inner"
        cache:commit(inner)
        cache:commit(inner)
        assert(counts.live == 4 and inner.root_hash == "inner", "commit did not dispose of only its backup")
        assert(not pcall(cache.revert, cache, inner), "revert without a snapshot was accepted")
    end
    assert(counts.live == 3, "inner owner waited for GC")
    cache:revert(outer)
    assert(outer.root_hash == "initial" and counts.live == 2, "inner execution lost the outer snapshot")
    outer_owner:close()
    outer_owner:close()
    assert(counts.live == 1, "owner close was not immediate and idempotent")

    local moved
    do
        local machine, owner <close> = cache:clone_at_input_boundary(0, noop)
        cache:snapshot(machine)
        moved = owner:move()
    end
    assert(counts.live == 3, "ownership transfer closed the working machine")
    moved:close()
    assert(counts.live == 1, "transferred owner leaked its snapshot")

    local machine, owner = cache:clone_at_input_boundary(0, noop)
    cache:snapshot(machine)
    cache:close()
    assert(counts.live == 0 and not next(cache.machines), "cache shutdown left owned machines alive")
    owner:close()
    cache:close()
    assert(not pcall(cache.clone_at_input_boundary, cache, 0, noop), "closed cache allowed acquisition")
end

-- Failed acquisition or replay must leave only the retained checkpoint alive, whether the
-- failure happened before snapshotting, during execution, or after committing the input.
for _, phase in ipairs({ "factory", "begin_epoch", "begin_input", "run", "end_input", "end_epoch" }) do
    local initial = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(initial, 2, 1)
    local player = prt.new_player(prt.new_geometry(10), { "accepted" }, cache, {
        new_null_computation_hash = function(machine)
            assert(phase ~= "factory", "injected factory failure")
            local builder = prt.new_null_computation_hash(machine)
            builder[phase] = function()
                error("injected " .. phase .. " failure")
            end
            return builder
        end,
    })
    local ok, err = pcall(player.make_uarch_tree, player, 2, 0)
    assert(not ok and err:find("injected " .. phase .. " failure"), "replay did not propagate the original error")
    assert(initial.counts.live == 1, phase .. " failure leaked a working machine or backup")
    initial.fail_clone = true
    assert(not pcall(cache.clone_at_input_boundary, cache, 0, noop), "failed clone was returned")
    assert(not pcall(cache.consider, cache, 1, initial), "failed checkpoint clone was retained")
    assert(#cache.checkpoints == 1 and initial.counts.live == 1, "failed clone changed retained checkpoints")
end

-- The player uses the supplied cache, including when a builder throws inside the forward
-- claim build. The cache remains owned by the caller.
for _, phase in ipairs({ "factory", "begin_input", "run", "end_input" }) do
    local initial = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(initial)
    local player = prt.new_player(prt.new_geometry(10), { "accepted" }, cache, {
        new_mcycle_computation_hash = function(_, _, machine)
            assert(phase ~= "factory", "injected factory failure")
            local builder = prt.new_null_computation_hash(machine)
            builder[phase] = function()
                error("injected " .. phase .. " failure")
            end
            return builder
        end,
    })
    assert(player.inputs == nil and player.machine_cache == nil, "player exposes caller-owned resources")
    local ok, err = pcall(player.make_mcycle_tree, player)
    assert(not ok and err:find("injected " .. phase .. " failure"), "builder failure was not propagated")
    assert(initial.counts.live == 1, "builder failure leaked its execution scope")
end

-- Soft yields and console breaks must not end an input. Automatic yields are serviced, and
-- the terminal reason still determines whether the epoch can close at a fixed point.
for _, terminal in ipairs({
    cartesi.BREAK_REASON_YIELDED_MANUALLY,
    cartesi.BREAK_REASON_HALTED,
    cartesi.BREAK_REASON_MCYCLE_OVERFLOW,
    cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
}) do
    local initial = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(initial)
    local reasons = {
        cartesi.BREAK_REASON_YIELDED_SOFTLY,
        cartesi.BREAK_REASON_CONSOLE_OUTPUT,
        cartesi.BREAK_REASON_CONSOLE_INPUT,
        cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY,
        terminal,
    }
    local runs, automatic_reads, manual_reads, ended_inputs = 0, 0, 0, 0
    local player = prt.new_player(prt.new_geometry(10), { "accepted" }, cache, {
        new_mcycle_computation_hash = function(_, _, machine)
            local builder = prt.new_null_computation_hash(machine)
            builder.run = function(_, mcycle_end)
                assert(
                    mcycle_end == 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE,
                    "runner received the wrong cycle limit"
                )
                runs = runs + 1
                return assert(reasons[runs], "runner resumed past its terminal reason")
            end
            machine.receive_cmio_request = function()
                if reasons[runs] == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                    automatic_reads = automatic_reads + 1
                    return cartesi.HTIF_YIELD_CMD_AUTOMATIC, cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, "output"
                end
                manual_reads = manual_reads + 1
                return cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED, ""
            end
            builder.end_input = function()
                ended_inputs = ended_inputs + 1
            end
            builder.end_epoch = function()
                error("epoch complete")
            end
            return builder
        end,
    })
    local ok, err = pcall(player.make_mcycle_tree, player)
    local at_target = terminal == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
    local expected = at_target and "input stopped outside a fixed point" or "epoch complete"
    assert(not ok and err:find(expected, 1, true), "input did not stop for its terminal reason")
    assert(runs == #reasons and automatic_reads == 1, "input did not resume through intermediate breaks")
    assert(manual_reads == (terminal == cartesi.BREAK_REASON_YIELDED_MANUALLY and 2 or 1))
    assert(ended_inputs == (at_target and 0 or 1), "input finalization did not respect the terminal reason")
    assert(initial.counts.live == 1, "input execution leaked a working machine or backup")
end

-- Input delivery must use the saved boundary hash even if preparation changes the running machine.
for _, phase in ipairs({ "begin_epoch", "begin_input", "snapshot" }) do
    local initial = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(initial)
    local snapshot = cache.snapshot
    cache.snapshot = function(self, machine)
        snapshot(self, machine)
        if phase == "snapshot" then
            machine.root_hash = "changed"
        end
    end
    local player = prt.new_player(prt.new_geometry(10), { "accepted" }, cache, {
        new_mcycle_computation_hash = function(_, _, machine)
            local builder = prt.new_null_computation_hash(machine)
            if phase ~= "snapshot" then
                builder[phase] = function()
                    machine.root_hash = "changed"
                end
            end
            return builder
        end,
    })
    local ok, err = pcall(player.make_mcycle_tree, player)
    assert(
        not ok and err:find("revert root hash does not match the machine root hash", 1, true),
        "input delivery accepted a changed boundary"
    )
    assert(initial.counts.live == 1, "boundary mismatch leaked a working machine or backup")
end

-- Acceptance establishes the next boundary. Rejection must restore that same hash, including
-- when it is the last input replayed before returning a machine to the caller.
for _, corrupt in ipairs({ false, true }) do
    local initial = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(initial)
    local revert = cache.revert
    cache.revert = function(self, machine)
        revert(self, machine)
        if corrupt then
            machine.root_hash = "wrong boundary"
        end
    end
    local player = prt.new_player(prt.new_geometry(10), { "first", "second" }, cache, {
        new_null_computation_hash = function(machine)
            local builder = prt.new_null_computation_hash(machine)
            local input_index
            builder.begin_input = function(_, index)
                input_index = index
            end
            builder.run = function()
                machine.root_hash = input_index == 0 and "accepted" or "rejected"
                return cartesi.BREAK_REASON_YIELDED_MANUALLY
            end
            machine.receive_cmio_request = function()
                local reason = machine.root_hash == "rejected" and cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
                    or cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
                return cartesi.HTIF_YIELD_CMD_MANUAL, reason, ""
            end
            return builder
        end,
        new_uarch_computation_hash = function()
            error("replay complete")
        end,
    })
    local ok, err = pcall(player.make_uarch_tree, player, 3, 0)
    local expected = corrupt and "rollback did not restore the input boundary" or "replay complete"
    assert(not ok and err:find(expected, 1, true), "replay lost its expected boundary hash")
    assert(initial.counts.live == 1, "replay left a working machine or backup alive")
end

-- A missing wrapper field forwards a machine method; absence of a private snapshot must instead
-- be represented explicitly. Exercise this before the slower real-machine checks.
do
    local cache <close> = prt.new_machine_cache(new_fake_machine("initial"))
    dishonest.new_tamperer(prt.new_geometry(10), { "accepted" }, cache, 0, 100)
    local machine, owner <close> = cache:clone_at_input_boundary(0, noop) -- luacheck: ignore 211
    machine.state.input_index = 0
    cache:snapshot(machine)
    machine.state.input_index = 1
    cache:revert(machine)
    assert(machine.state.input_index == 0 and not machine.snapshot_state, "private rollback state was not consumed")
    cache:snapshot(machine)
    cache:commit(machine)
    assert(not machine.snapshot_state, "private commit state was not consumed")
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
        local forest = hash_tree.frontier_forest(HEIGHT, "keccak256")
        for bundle_index = 0, (LEAVES >> bundle_height) - 1 do
            local bundle = build_leaf_forest(bundle_index << bundle_height, bundle_height)
            hash_tree.frontier_forest_push_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), bundle_height)
        end
        tree = prtu.new_tree(HEIGHT, bundle_height, forest, function(_, bundle_index)
            return build_leaf_forest(bundle_index << bundle_height, bundle_height)
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
-- Expanded padding serves all repeated bundles without replaying them separately.
do
    local bundle = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_pad_back(bundle, base_state_hash, 4)
    local forest = hash_tree.frontier_forest(HEIGHT, "keccak256")
    hash_tree.frontier_forest_pad_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), LEAVES >> 2, 2)
    local calls = 0
    local tree = prtu.new_tree(HEIGHT, 2, forest, function()
        calls = calls + 1
        return bundle
    end)
    local root = tree:get_root()
    tree:open_bundle((LEAVES >> 2) - 1)
    tree:open_bundle(0)
    assert(calls == 1, "opening repeated bundles reran the machine")
    assert(tree:get_root() == root, "opening a bundle changed the commitment")
    for i = 0, LEAVES - 1 do
        assert(tree:get_node(i, 0) == base_state_hash, "expanded padding has the wrong leaf")
        hash_tree.verify_slice(tree:prove(i))
    end
end

-- A failed reconstruction must leave the commitment opaque and allow a valid retry.
do
    local bundle = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_pad_back(bundle, base_state_hash, 4)
    local forest = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_push_back(forest, hash_tree.frontier_forest_get_root_hash(bundle), 2)
    local replacement = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_pad_back(replacement, fake_state_hash, 4)
    local tree = prtu.new_tree(2, 2, forest, function()
        return replacement
    end)
    local root = tree:get_root()
    assert(not pcall(tree.open_bundle, tree, 0), "a mismatched bundle was installed")
    assert(not pcall(tree.get_node, tree, 0, 0), "a failed expansion exposed a leaf")
    assert(tree:get_root() == root, "a failed expansion changed the commitment")
    replacement = bundle
    tree:open_bundle(0)
    hash_tree.verify_slice(tree:prove(0))
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
    local function run_client(hello, handler, typed)
        -- These clients are independent processes in the real example, not referee children.
        local client = coroutine.create(function()
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
                    local reply, done
                    if typed then
                        reply, done = handler(wire_event, line)
                    elseif
                        wire_event.operation == "finish"
                        or (prtu.EVENTS[wire_event.operation] and prtu.EVENTS[wire_event.operation].scheduled_schema)
                        or wire_event.operation == "cancel_response"
                    then
                        reply = { value = true }
                    elseif wire_event.operation == "advance_time" then
                        reply = { value = {} }
                    else
                        reply = handler(wire_event)
                    end
                    if reply == "close" then
                        sock:close()
                        return
                    elseif type(reply) == "table" then
                        reply = cartesi.tojson(reply, -1)
                    end
                    if reply ~= nil then
                        assert(sock:send(reply .. "\n"))
                    end
                    if done then
                        sock:close()
                        return
                    end
                end
            end
        end)
        dispatcher:schedule(client, "start")
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

-- A group starts every closure before waiting, retains completion for later waits, and
-- does not cancel work when only the wait's deadline expires.
run_with_server(function(server)
    local empty <close> = server:run_all({})
    assert(empty.resolved and empty:wait(), "an empty group did not complete immediately")
    local started, finished = {}, {}
    local functions = {}
    for i = 1, 2 do
        functions[i] = function()
            started[#started + 1] = i
            server:wait_until(i == 1 and 6 or 4)
            finished[#finished + 1] = i
        end
    end
    local completed <close> = server:run_all(functions)
    assert(#started == 0, "run_all suspended its caller")
    assert(completed:wait(2) == nil, "a group completed before its closures")
    assert(table.concat(started, ",") == "1,2" and #finished == 0, "closures did not start concurrently in list order")
    assert(completed:wait() == true, "a timed wait cancelled unfinished closures")
    assert(table.concat(finished, ",") == "2,1", "closures did not finish independently")
    assert(completed:wait(6) == nil and completed:wait(7) == true, "completion did not retain its block")
    assert(not next(server.active), "a completed group remained active")
end)

-- Cancellation before the first dispatcher turn prevents every closure from starting.
run_with_server(function(server)
    local completed <close> = server:run_all({
        function()
            error("a cancelled closure started")
        end,
    })
    completed:close()
    server:wait_until(1)
    assert(not next(server.active), "a cancelled group remained active")
end)

-- Closing the outer group closes nested groups and their scoped resources, including
-- suspended proof requests. Other groups keep running.
run_with_server(function(server)
    local started, closed, resumed = 0, 0, false
    local pending = {}
    local function wait_for_proof()
        local resource <close> = setmetatable({}, { -- luacheck: ignore 211
            __close = function()
                closed = closed + 1
            end,
        })
        local proof <close> = server:request_first_valid({}, define_event("group_proof"), {}, is_valid)
        local elimination <close> = server:request_first_valid(
            {},
            prtu.EVENTS.schedule_match_elimination,
            { server:request_block() + 10 },
            function()
                return 0
            end
        )
        pending[#pending + 1] = proof
        pending[#pending + 1] = elimination
        started = started + 1
        proof:wait()
        resumed = true
    end
    local completed <close> = server:run_all({
        wait_for_proof,
        function()
            local nested <close> = server:run_all({ wait_for_proof })
            nested:wait()
            resumed = true
        end,
    })
    local other_finished = false
    local other <close> = server:run_all({
        function()
            server:wait_until(4)
            other_finished = true
        end,
    })
    server:wait_until(3)
    assert(started == 2, "nested closures did not reach their proof waits")
    completed:close()
    assert(closed == 2 and not resumed, "cancellation resumed a closure or skipped cleanup")
    for _, proof in ipairs(pending) do
        assert(proof.closed, "cancellation left a proof request open")
    end
    assert(not next(server.scheduled_responses), "cancellation left a scheduled response registered")
    assert(other:wait() and other_finished, "cancellation stopped another group")
    assert(not next(server.active), "cancellation left unfinished work")
end)

local group_ok, group_error = pcall(run_with_server, function(server)
    local completed <close> = server:run_all({
        function()
            error("group closure failed")
        end,
    })
    completed:wait()
end)
assert(not group_ok and group_error:find("group closure failed"), "a closure error did not fail the referee")

run_with_server(function(server, run_client, wait_connections)
    for _, label in ipairs({ "a", "b", "nil", "false", "error" }) do
        run_client(nil, function()
            return { label = label, value = label }
        end)
    end
    wait_connections(5)
    local checked = 0
    local collection <close> = server:request_all(EVERYONE, define_event("claim"), {}, function(response)
        checked = checked + 1
        assert(response ~= "error", "invalid claim")
        if response == "nil" then
            return nil
        elseif response == "false" then
            return false
        end
        return { claim = response }
    end)
    local block = server:request_block()
    local early = collection:wait(block)
    assert(#early == 0 and checked == 0, "an expired wait accepted unvalidated replies")
    local responses = collection:wait(block + 1)
    assert(checked == 5 and #responses == 2, "collection did not validate every reply")
    assert(#early == 0, "later replies changed an earlier snapshot")
    assert(server:get_time() == block, "rejected replies held up collection")
    local labels = {}
    for _, response in ipairs(responses) do
        assert(response.value.claim == response.label, "collection lost its validator result or sender label")
        assert(response.connection.is_player and not response.connection.dead, "collection lost its sender")
        assert(response.received_at == block, "collection lost the receipt block")
        labels[response.label] = true
    end
    assert(labels.a and labels.b, "collection lost an accepted claim")
    assert(#collection:wait(block) == 0, "an expired wait included replies received at its deadline")
    assert(#collection:wait() == 2 and checked == 5, "another wait revalidated replies")
    local rejected <close> = server:request_all(EVERYONE, define_event("claim"), {}, function()
        error("invalid claim")
    end)
    assert(#rejected:wait() == 0, "an all-invalid collection did not resolve empty")
    for _, connection in ipairs(server:get_players()) do
        assert(not connection.dead, "an invalid claim closed its sender")
    end
end)

run_with_server(function(server, run_client, wait_connections)
    -- Initial subscriptions require the phase closer. Mcycle and uarch claim collection
    -- then closes at supplied logical blocks, using fixed audiences.
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
    local close_block = server:request_block() + 1
    local collection <close> = server:request_all("initial", define_event("commit_mcycle_claim"), {})
    local responses = collection:wait(close_block)
    server:wait_until(close_block)
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
    server:subscribe_connection("x", a)
    server:subscribe_connection("x", b)
    server:subscribe_connection("a", a)
    server:subscribe_connection("b", b)
    -- A late joiner, after the phase closes, is not part of the mcycle tournament.
    run_client(nil, make_claimer("c", answer("valid")))
    wait_connections(4)

    local function request(subscriptions, event, arguments, accept)
        local future <close> = server:request_first_valid(subscriptions, event, arguments, accept)
        return future:wait(server:request_block() + 1)
    end

    -- The first valid response wins and a rejected response leaves its connection open.
    assert(request({ "x", "a" }, define_event("answer"), {}, is_valid) == "valid", "valid response not taken")
    assert(not a.dead and not b.dead, "a rejected proof closed a connection")
    assert(#answered == 2, "overlapping subscriptions duplicated or broadened the audience")

    -- An empty subscription list is distinct from EVERYONE.
    assert(request({}, define_event("answer"), {}, is_valid) == nil)
    assert(#answered == 2, "an empty subscription list broadcast the event")

    -- Subscription changes affect the next event, not an event already emitted.
    server:subscribe_connection("snapshot", a)
    do
        local future <close> = server:request_first_valid("snapshot", define_event("answer"), {}, function() end)
        server:subscribe_connection("snapshot", b)
        assert(future:wait(server:request_block() + 1) == nil)
        assert(#answered == 3, "an emitted event's audience changed with its subscriptions")
    end
    assert(request({ "snapshot" }, define_event("answer"), {}, function() end) == nil)
    assert(#answered == 5, "a new event reused an old subscription audience")

    -- A single subscription selects its holders, and the acceptor's result is returned.
    local mapped = request("a", define_event("mapped"), {}, function(v)
        return is_valid(v) and "mapped"
    end)
    assert(mapped == "mapped", "future did not return the acceptor result")
    assert(#answered == 6, "a single subscription selected the wrong audience")

    -- Without a valid response, the wait reaches its deadline after every holder answers.
    local replies_seen = 0
    run_client(nil, function()
        replies_seen = replies_seen + 1
        return { value = "invalid" }
    end)
    wait_connections(5)
    local n = server.connections[5]
    server:subscribe_connection("n", n)
    assert(request({ "n", "b" }, define_event("answer"), {}, is_valid) == nil, "an invalid response was taken")
    assert(replies_seen == 1, "the event resolved before every holder answered")
    assert(not n.dead and not b.dead, "an invalid response closed a connection")

    -- A nested tournament asks only its audience, and closes at the next block.
    local nested_close_block = server:request_block() + 1
    local nested_collection <close> = server:request_all("a", define_event("commit_mcycle_claim"), {})
    local nested = nested_collection:wait(nested_close_block)
    server:wait_until(nested_close_block)
    assert(#nested == 1 and nested[1].value == "a", "nested tournament asked the wrong audience")
    assert(#server.open_phases == 0, "closed nested tournament was retained")

    -- Every holder answers without proof and the wait expires with connections open.
    assert(request({ "b" }, define_event("answer"), {}, is_valid) == nil, "an invalid response was taken")
    assert(not b.dead, "an invalid response closed its connection")

    -- A holder that closes counts as answered. With every holder gone, the claim is unanswered.
    run_client(nil, function()
        return "close"
    end)
    wait_connections(6)
    local labels <close> = server:request_all(EVERYONE, define_event("label"), {})
    local replies = labels:wait()
    local d = server.connections[6]
    server:subscribe_connection("d", d)
    assert(d.dead and #replies == 4, "the closing client was not dropped from the collection")
    assert(
        request({ "d" }, define_event("answer"), {}, is_valid) == nil,
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
    server:subscribe_connection("bad", bad)
    assert(
        request({ "bad" }, define_event("typed", "PairResponse"), {}, is_well_typed) == nil,
        "a schema-invalid value was taken"
    )
    assert(not next(server.active), "closing a future left it active")
    assert(not bad.dead, "a schema-invalid reply closed its connection")
    -- Alongside a well-typed reply, whichever arrives first, the well-typed value is taken and
    -- both connections stay open.
    local good = run_typed_client({ l = "a", r = "b" }, "PairResponseEnvelope")
    server:subscribe_connection("good", good)
    local taken = request({ "bad", "good" }, define_event("typed", "PairResponse"), {}, is_well_typed)
    assert(taken and taken.l == "a", "the well-typed reply was not taken")
    assert(not next(server.active), "closing a future left it active")
    assert(not bad.dead and not good.dead, "a schema-invalid reply closed a connection")

    -- An undecodable line closes its sender.
    run_client(nil, function()
        return "this is not json"
    end)
    wait_connections(9)
    local malformed <close> = server:request_all(EVERYONE, define_event("label"), {})
    malformed:wait()
    local dead = 0
    for _, connection in ipairs(server.connections) do
        if connection.dead then
            dead = dead + 1
        end
    end
    assert(dead == 2, "an undecodable line did not close its sender")
    assert(not a.dead and not b.dead, "a live player was closed")

    -- An unsolicited player reply cannot advance logical time or invent another claim.
    run_client(nil, function(wire_event)
        if wire_event.operation == "commit_mcycle_claim" then
            return cartesi.tojson({ value = "forger" }, -1) .. "\n" .. cartesi.tojson({ value = true }, -1)
        end
        return { value = "valid" }
    end)
    wait_connections(10)
    local f = server.connections[10]
    server:subscribe_connection("f", f)
    local forged_close_block = server:request_block() + 1
    local forged_collection <close> = server:request_all("f", define_event("commit_mcycle_claim"), {})
    local t2 = forged_collection:wait(forged_close_block)
    server:wait_until(forged_close_block)
    assert(#t2 == 1 and t2[1].value == "forger" and not f.dead, "the forged close was not ignored")

    -- A connection announces its role once. Announcing again closes it, and so does a second
    -- phase closer.
    run_client({ role = "player" }, function()
        return { role = "player" }
    end)
    wait_connections(11)
    server:subscribe_connection("again", server.connections[11])
    local repeated_hello <close> = server:request_all("again", define_event("again"), {})
    repeated_hello:wait()
    assert(server.connections[11].dead, "a repeated role announcement was accepted")
    run_client({ role = "phase_closer" }, function()
        return "close"
    end)
    wait_connections(12)
    assert(
        server.connections[12].dead and server.phase_closer == server.connections[3],
        "a second phase closer was accepted"
    )
end)

-- An invalid close response is a phase-closer bug and fails the referee.
local ok, err = pcall(run_with_server, function(server, run_client, wait_connections)
    run_client({ role = "phase_closer" }, function()
        return { value = "other" }
    end)
    wait_connections(1)
    server:accept_subscribers("initial")
end)
assert(not ok and err:find("did not close the phase asked"), "an invalid phase close was accepted")

-- Losing the phase closer before the initial close fails the referee.
ok, err = pcall(run_with_server, function(server, run_client, wait_connections)
    run_client({ role = "phase_closer" }, function()
        return "close"
    end)
    wait_connections(1)
    server:accept_subscribers("initial")
end)
assert(not ok and err:find("the phase closer went away"), "phase-closer EOF did not fail the referee")

assert(require("prt-deadline-test"))(run_with_server)

-- A stop can arrive before a queued match coroutine has made its first request.
do
    local started = false
    run_with_server(function(server)
        local completed <close> = server:run_all({ -- luacheck: ignore 211
            function()
                started = true
            end,
        })
        server.stopping = true
        coroutine.yield()
        error("stopping resumed the referee")
    end)
    assert(not started, "a queued match started after the referee stopped")
end

-- The phase closer stops suspended proof waits through the server. The referee never
-- receives a special return value, its resources close, and players still receive finish.
for _, stop_during in ipairs({ "root", "output" }) do
    local closed, finished, resumed = false, false, false
    local pending, referee, stopped_server
    run_with_server(function(server, run_client, wait_connections)
        stopped_server = server
        referee = coroutine.running()
        local resource <close> = setmetatable({}, { -- luacheck: ignore 211
            __close = function()
                closed = true
            end,
        })
        run_client(nil, function(event)
            if event.operation == "finish" then
                finished = true
                return { value = true }, true
            elseif event.operation == "advance_time" then
                return { value = {} }
            elseif event.operation == "stop_test_root" and stop_during == "output" then
                return { value = "valid" }
            end
            assert(pending.cortn == referee, "proof wait was not suspended")
            local closer = prtu.new_phase_closer("stop")
            run_client(cartesi.fromjson(closer.hello), function(_, line)
                return prtu.answer_event(closer, line)
            end, true)
            return { value = {} }
        end, true)
        wait_connections(1)
        local root <close> = server:request_first_valid(EVERYONE, define_event("stop_test_root"), {}, is_valid)
        pending = root
        root:wait()
        if stop_during == "root" then
            resumed = true
        end
        local output <close> = server:request_first_valid(EVERYONE, define_event("stop_test_output"), {}, is_valid)
        pending = output
        output:wait()
        resumed = true
    end)
    assert(closed and finished, "stopping skipped resource cleanup or finish delivery")
    assert(not resumed and coroutine.status(referee) == "dead", "stopping resumed referee logic")
    assert(pending.closed and not next(stopped_server.active), "stopping retained a proof request")
end

-- Several player-selected responses can be accepted before the phase closer stops the loop.
-- Their indices deliberately do not follow numerical order.
do
    local accepted, finished = {}, false
    run_with_server(function(server, run_client, wait_connections)
        local offers, next_offer = { 7, 2, 5 }, 1
        run_client(nil, function(event)
            if event.operation == "finish" then
                finished = true
                return { value = true }, true
            elseif event.operation == "advance_time" then
                return { value = {} }
            end
            assert(not next(event.arguments), "output request supplied player selection or acceptance information")
            local index = offers[next_offer]
            next_offer = next_offer + 1
            if index then
                return { value = index }
            end
            local closer = prtu.new_phase_closer("stop")
            run_client(cartesi.fromjson(closer.hello), function(_, line)
                return prtu.answer_event(closer, line)
            end, true)
            return { value = {} }
        end, true)
        wait_connections(1)
        while true do
            local response <close> = server:request_first_valid(
                EVERYONE,
                define_event("stop_test_outputs"),
                {},
                function(value)
                    return math.type(value) == "integer" and value
                end
            )
            accepted[#accepted + 1] = response:wait()
        end
    end)
    assert(finished and table.concat(accepted, ",") == "7,2,5", "output loop lost a player-selected response")
end

--------------------------------------------------------------------------------
-- Machine checkpoint replay
--------------------------------------------------------------------------------

local function new_test_cache(contract, capacity, input_gap)
    local inputs = { table.unpack(contract.inputs) }
    return inputs, prt.new_machine_cache(prt.new_machine(contract.initial_state_hash), capacity, input_gap)
end

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
    local tamperer_inputs, tamperer_cache <close> = new_test_cache(dapp_contract, 64, 1)
    local tamperer = dishonest.new_tamperer(dapp_contract.geometry, tamperer_inputs, tamperer_cache, 0, 100)
    local tampered_tree = tamperer:make_mcycle_tree()
    tampered_tree:open_bundle(99)
    tampered_tree:open_bundle(100)
    local uncached_tamperer_inputs, uncached_tamperer_cache <close> = new_test_cache(dapp_contract, 1)
    local uncached_tamperer =
        dishonest.new_tamperer(dapp_contract.geometry, uncached_tamperer_inputs, uncached_tamperer_cache, 0, 100)
    local uncached_tampered_tree = uncached_tamperer:make_mcycle_tree()
    assert(uncached_tampered_tree:get_root() == tampered_tree:get_root(), "cache changed the tampered claim")
    uncached_tampered_tree:open_bundle(100)
    local tampered_first_leaf = 100 << LOG2_BUNDLE_MCYCLE_COUNT
    for leaf = tampered_first_leaf, tampered_first_leaf + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1 do
        assert(
            uncached_tampered_tree:get_node(leaf, 0) == tampered_tree:get_node(leaf, 0),
            "cache changed replay out of the tamper point"
        )
    end

    -- Fabulist run can refine synchronously while the outer input is still running. Both
    -- executions have outstanding snapshots, even though this is a single player process.
    do
        local fabulist_inputs, fabulist_cache <close> = new_test_cache(dapp_contract)
        local fabulist = dishonest.new_fabulist(dapp_contract.geometry, fabulist_inputs, fabulist_cache, 0, 16)
        local cache = fabulist_cache
        local snapshot = cache.snapshot
        local maximum = 0
        cache.snapshot = function(self, machine)
            snapshot(self, machine)
            local active = 0
            for _, owner in pairs(self.machines) do
                active = active + (owner.backup and 1 or 0)
            end
            maximum = math.max(maximum, active)
        end
        local tree = fabulist:make_mcycle_tree()
        tree:open_bundle(1)
        assert(maximum >= 2, "fabulist did not exercise nested snapshots")
        assert(tree:get_node(16, 0) == keccak("fabulist"), "nested refinement lost the fabricated leaf")
        local retained = 0
        for _, owner in pairs(cache.machines) do
            assert(not owner.backup, "nested refinement leaked a snapshot")
            retained = retained + 1
        end
        assert(retained == #cache.checkpoints, "nested refinement leaked an execution")
    end

    -- Refinement is a read of the committed claim. It must not replace build checkpoints with
    -- speculative machines from an input whose committed suffix is its revert state.
    local honest_inputs, honest_cache <close> = new_test_cache(dapp_contract, 1)
    local honest = prt.new_player(dapp_contract.geometry, honest_inputs, honest_cache)
    local cache = honest_cache
    local native <close> = prt.new_machine(initial_state_hash)
    assert(type(native) == "userdata", "honest machine is wrapped")
    assert(type(cache.checkpoints[1].machine) == "userdata", "honest checkpoint machine is wrapped")
    local native_builder =
        prt.new_mcycle_computation_hash(dapp_contract.geometry.log2_mcycles_per_period, cache, native)
    assert(rawget(native_builder, "machine") == native, "honest computation-hash builder is wrapped")
    assert(native_builder.unbundle == nil, "honest builder exposes strategy-only refinement")
    assert(native_builder.pad_back == nil, "honest builder exposes strategy-only insertion")
    local native_uarch_builder =
        prt.new_uarch_computation_hash(dapp_contract.geometry.log2_mcycles_per_period, native, 0)
    assert(rawget(native_uarch_builder, "machine") == native, "honest uarch builder is wrapped")
    assert(native_uarch_builder.unbundle == nil, "honest uarch builder exposes strategy-only refinement")
    assert(native_uarch_builder.pad_back == nil, "honest uarch builder exposes strategy-only insertion")
    local virgin_root = native:get_root_hash()
    native_uarch_builder:begin_input(0, native:read_reg("mcycle"))
    assert(native:get_root_hash() == virgin_root, "capturing the revert tail changed the virgin machine")
    assert(rawget(prt.new_null_computation_hash(native), "machine") == native, "honest replay builder is wrapped")

    local honest_tree = honest:make_mcycle_tree()
    local checkpoint = assert(cache.checkpoints[1], "claim build retained no machine checkpoint").input_index
    honest_tree:open_bundle((dapp_contract.geometry.periods_per_input >> LOG2_BUNDLE_MCYCLE_COUNT))
    assert(cache.checkpoints[1].input_index == checkpoint, "mcycle refinement changed the machine cache")
    local cached_inputs, cached_cache <close> = new_test_cache(dapp_contract)
    local cached = prt.new_player(dapp_contract.geometry, cached_inputs, cached_cache)
    local cached_tree = cached:make_mcycle_tree()
    for _, saved in ipairs(cached_cache.checkpoints) do
        assert(type(saved.machine) == "userdata", "checkpoint machine is wrapped")
    end
    assert(cached_tree:get_root() == honest_tree:get_root(), "cache policy changed the mcycle root")
    assert(honest_tree:get_root() == util.read_file(assert(arg[5])), "mcycle root differs from CLI")
    -- This fabricated leaf is beyond the last input, so end_epoch must insert it even when
    -- refinement never calls run. Opening the bundle also authenticates that refinement.
    do
        local fabulist_inputs, fabulist_cache <close> = new_test_cache(dapp_contract)
        local fabulist = dishonest.new_fabulist(dapp_contract.geometry, fabulist_inputs, fabulist_cache, #inputs, 16)
        local tree = fabulist:make_mcycle_tree()
        local leaf = #inputs * dapp_contract.geometry.periods_per_input + 16
        local bundle = leaf >> LOG2_BUNDLE_MCYCLE_COUNT
        tree:open_bundle(bundle)
        honest_tree:open_bundle(bundle)
        assert(tree:get_node(leaf, 0) == keccak("fabulist"), "epoch padding lost the fabricated leaf")
        assert(
            tree:get_node(leaf + 1, 0) == honest_tree:get_node(leaf + 1, 0),
            "epoch padding changed a neighboring leaf"
        )
    end
    for _, bundle_index in ipairs({
        0,
        99,
        (dapp_contract.geometry.periods_per_input >> LOG2_BUNDLE_MCYCLE_COUNT),
        2 * (dapp_contract.geometry.periods_per_input >> LOG2_BUNDLE_MCYCLE_COUNT),
        (1 << (dapp_contract.geometry.mcycle_height - LOG2_BUNDLE_MCYCLE_COUNT)) - 1,
    }) do
        honest_tree:open_bundle(bundle_index)
        cached_tree:open_bundle(bundle_index)
        local first_leaf = bundle_index << LOG2_BUNDLE_MCYCLE_COUNT
        for leaf = first_leaf, first_leaf + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1 do
            assert(honest_tree:get_node(leaf, 0) == cached_tree:get_node(leaf, 0), "cache changed refinement")
        end
    end
    local first_uarch = honest:make_uarch_tree(1, 0)
    assert(first_uarch:get_root() == util.read_file(assert(arg[6])), "uarch root differs from CLI")
    first_uarch:open_bundle(0)
    first_uarch:open_bundle((1 << (dapp_contract.geometry.uarch_height - LOG2_BUNDLE_UARCH_CYCLE_COUNT)) - 1)
    local rejected_uarch = honest:make_uarch_tree(2, 60000)
    rejected_uarch:open_bundle(0)
    rejected_uarch:open_bundle((1 << (dapp_contract.geometry.uarch_height - LOG2_BUNDLE_UARCH_CYCLE_COUNT)) - 1)
    assert(
        honest:make_uarch_tree(3, 0):get_root() == cached:make_uarch_tree(3, 0):get_root(),
        "cache changed post-rejection uarch replay"
    )

    -- Every checkpoint is a virgin boundary. A rejected input offers none, so replay into and
    -- past it starts at the preceding boundary and rolls back exactly as the forward build did.
    local dense_inputs, dense_cache <close> = new_test_cache(dapp_contract, 64, 1)
    local dense = prt.new_player(dapp_contract.geometry, dense_inputs, dense_cache)
    local dense_tree = dense:make_mcycle_tree()
    local rejected_input_index = 1
    local retained_boundaries = {}
    for _, saved in ipairs(dense_cache.checkpoints) do
        retained_boundaries[saved.input_index] = true
    end
    assert(
        retained_boundaries[0] and retained_boundaries[rejected_input_index] and retained_boundaries[3],
        "dense cache lost an accepted input's boundary"
    )
    assert(not retained_boundaries[rejected_input_index + 1], "the rejected input offered a boundary checkpoint")
    assert(dense_tree:get_root() == honest_tree:get_root(), "dense cache changed the mcycle root")
    local saved_checkpoints = {}
    for i, saved in ipairs(dense_cache.checkpoints) do
        saved_checkpoints[i] = saved
    end
    for _, period_index in ipairs({ 16, 60000, dapp_contract.geometry.periods_per_input - 1 }) do
        local bundle_index = (rejected_input_index * dapp_contract.geometry.periods_per_input + period_index)
            >> LOG2_BUNDLE_MCYCLE_COUNT
        honest_tree:open_bundle(bundle_index)
        dense_tree:open_bundle(bundle_index)
        local first_leaf = bundle_index << LOG2_BUNDLE_MCYCLE_COUNT
        for leaf = first_leaf, first_leaf + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1 do
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
    assert(#saved_checkpoints == #dense_cache.checkpoints, "refinement changed checkpoint count")
    for i, saved in ipairs(saved_checkpoints) do
        assert(dense_cache.checkpoints[i] == saved, "refinement replaced a checkpoint")
    end

    -- Uarch collection and transition proofs replay from the rejected input's own boundary, both
    -- before and after its rejection, and their logs authenticate against the claims.
    for _, period in ipairs({ 16, 60000 }) do
        local uarch = dense:make_uarch_tree(2, period)
        uarch:open_bundle(0)
        local logs = dense:prove_state_transition(1, period, 0)
        local preceding_leaf = dapp_contract.geometry.periods_per_input + period - 1
        dense_tree:open_bundle(preceding_leaf >> LOG2_BUNDLE_MCYCLE_COUNT)
        assert(
            cartesi.machine:verify_step_uarch(dense_tree:get_node(preceding_leaf, 0), logs.step_log)
                == uarch:get_node(0, 0),
            "cached transition does not match the uarch claim"
        )
        local reset_offset = cartesi.UARCH_CYCLE_MAX
        uarch:open_bundle(reset_offset >> LOG2_BUNDLE_UARCH_CYCLE_COUNT)
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
    local chain_inputs, chain_cache <close> = new_test_cache(chain_contract, 128, 1)
    local input_runs = {}
    local replay_begins, replay_ends = 0, 0
    local new_null = prt.new_null_computation_hash
    local function observe_replay(m)
        local builder = new_null(m)
        builder.begin_epoch = function()
            replay_begins = replay_begins + 1
        end
        builder.end_epoch = function()
            replay_ends = replay_ends + 1
        end
        builder.begin_input = function(_, index)
            input_runs[index] = (input_runs[index] or 0) + 1
        end
        return builder
    end
    local chain = prt.new_player(
        chain_contract.geometry,
        chain_inputs,
        chain_cache,
        { new_null_computation_hash = observe_replay }
    )
    local chain_tree = chain:make_mcycle_tree()
    local chain_reference_inputs, chain_reference_cache <close> = new_test_cache(chain_contract, 1)
    local chain_reference = prt.new_player(chain_contract.geometry, chain_reference_inputs, chain_reference_cache)
    assert(chain_tree:get_root() == chain_reference:make_mcycle_tree():get_root(), "cache changed rejection-chain root")
    local chain_boundaries = {}
    for _, saved in ipairs(chain_cache.checkpoints) do
        chain_boundaries[saved.input_index] = saved
    end
    assert(chain_boundaries[1] and chain_boundaries[4], "chain fixture lacks the boundaries around the chain")
    assert(not chain_boundaries[2] and not chain_boundaries[3], "a rejected input offered a boundary checkpoint")
    -- The cache API resolves the requested boundary, including an uncached boundary after
    -- rejection and positions past the last posted input. The target input remains undelivered.
    local clone_boundary = chain_cache.clone_at_input_boundary
    for _, target in ipairs({ 0, 1, 3, 4, 5 }) do
        local observed = false
        chain_cache.clone_at_input_boundary = function(self, index, run_to_input_boundary)
            local resolved, owner = clone_boundary(self, index, run_to_input_boundary)
            local saved = chain_boundaries[target == 3 and 1 or math.min(target, 4)]
            assert(
                index == target and resolved:get_root_hash() == saved.machine:get_root_hash(),
                "cache returned the wrong input boundary"
            )
            observed = true
            return resolved, owner
        end
        chain:make_uarch_tree(target + 1, 0)
        assert(observed, "player did not request its input boundary")
    end
    chain_cache.clone_at_input_boundary = clone_boundary
    local lookups = 0
    input_runs = {}
    replay_begins, replay_ends = 0, 0
    local clone_at_input_boundary = chain_cache.clone_at_input_boundary
    chain_cache.clone_at_input_boundary = function(self, target, run_to_input_boundary)
        lookups = lookups + 1
        return clone_at_input_boundary(self, target, run_to_input_boundary)
    end
    local last_period = dapp_contract.geometry.periods_per_input - 1
    local chain_bundle_index = (2 * dapp_contract.geometry.periods_per_input + last_period) >> LOG2_BUNDLE_MCYCLE_COUNT
    chain_tree:open_bundle(chain_bundle_index)
    assert(lookups == 1, "reverted-tail refinement performed multiple lookups")
    assert(replay_begins == 1 and replay_ends == 1, "cache replay bypassed the epoch driver's builder lifecycle")
    assert(
        not input_runs[0] and input_runs[1] == 1 and input_runs[2] == 1,
        "reverted-tail refinement did not replay from the boundary before the chain"
    )
    local reference_leaf = 2 * dapp_contract.geometry.periods_per_input - 1
    assert(
        chain_tree:get_node(3 * dapp_contract.geometry.periods_per_input - 1, 0)
            == honest_tree:get_node(reference_leaf, 0),
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
        chain_inputs[4],
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
    local all_checkpoints = chain_cache.checkpoints
    chain_cache.checkpoints = { all_checkpoints[1] }
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
    chain_cache.checkpoints = all_checkpoints

    -- Result replay uses the same input lifecycle, and its proofs authenticate
    -- against the final state of the sampled execution.
    local result = honest:prove_outputs_merkle_root()
    local final_leaf = (1 << dapp_contract.geometry.mcycle_height) - 1
    assert(
        result.iflags_y_proof.root_hash == honest_tree:get_node(final_leaf, 0),
        "result replay differs from the claim's final state"
    )
    local latest = honest:prove_output()
    assert(latest.output and latest.output_index == 1, "accepted output was lost during replay")
    assert(honest:prove_output() == latest, "the player's output choice changed between requests")
    local other_player = prt.new_player(dapp_contract.geometry, honest_inputs, honest_cache, { output_index = 0 })
    local earlier = other_player:prove_output()
    assert(earlier.output and earlier.output_index == 0, "the player did not offer its chosen output")
    for _, output in ipairs({ latest, earlier }) do
        assert(output.output_proof.root_hash == result.tx_buffer_data, "output proof used the wrong root")
        assert(output.output_proof.target_hash == keccak(output.output), "output proof used the wrong payload")
        hash_tree.verify_slice(output.output_proof)
    end
    local absent_player = prt.new_player(dapp_contract.geometry, honest_inputs, honest_cache, { output_index = 2 })
    assert(next(absent_player:prove_output()) == nil, "the player invented an output at a missing index")

    local forger_inputs, forger_cache <close> = new_test_cache(dapp_contract)
    local original_input = dapp_contract.inputs[1]
    local forger = dishonest.new_forger(dapp_contract.geometry, forger_inputs, forger_cache, 0, "forged")
    assert(
        forger_inputs[1] == "forged" and dapp_contract.inputs[1] == original_input,
        "forger modified the contract's input list"
    )
    assert(forger.inputs == nil and forger.machine_cache == nil, "forger exposes caller-owned resources")
    local forged_logs = forger:prove_state_transition(0, 0, 0)
    assert(
        not pcall(
            cartesi.machine.verify_send_cmio_response,
            cartesi.machine,
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            original_input,
            initial_state_hash,
            forged_logs.send_cmio_log,
            initial_state_hash
        ),
        "forged input passed verification against the contract"
    )
    local forged_state = cartesi.machine:verify_send_cmio_response(
        cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
        forger_inputs[1],
        initial_state_hash,
        forged_logs.send_cmio_log,
        initial_state_hash
    )
    assert(cartesi.machine:verify_step_uarch(forged_state, forged_logs.step_log), "forged execution proof is malformed")
    do
        local machine, owner <close> = tamperer_cache:clone_at_input_boundary(0, noop) -- luacheck: ignore 211
        local other, other_owner <close> = tamperer_cache:clone_at_input_boundary(0, noop) -- luacheck: ignore 211
        local read_reg = machine.read_reg
        assert(rawget(machine, "read_reg") == read_reg, "machine forwarder was not cached")
        assert(read_reg ~= other.read_reg, "bound machine forwarders are shared across receivers")
        assert(machine.run == machine.overrides.run, "forwarder masked an override")
        assert(read_reg(machine, "mcycle") == machine.machine:read_reg("mcycle"), "forwarder used the wrong receiver")
        assert(machine.state ~= other.state, "clones share mutable strategy state")
        machine.state.input_index = 0
        tamperer_cache:snapshot(machine)
        machine.state.input_index = 7
        tamperer_cache:revert(machine)
        assert(
            machine.state.input_index == 0 and not machine.snapshot_state,
            "cache revert lost private strategy state"
        )
        tamperer_cache:snapshot(machine)
        tamperer_cache:commit(machine)
        assert(not machine.snapshot_state, "commit retained private strategy snapshot state")
    end

    -- Terminal inputs and empty epochs must fill claims and reconstructed bundles even when the
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
        local function observe_inputs(builder, m)
            local run = builder.run
            builder.run = function(self, target)
                stop_after_delivery(m)
                return run(self, target)
            end
            return builder
        end
        local terminal_inputs = { table.unpack(contract.inputs) }
        local terminal_cache <close> = prt.new_machine_cache(terminal_machine(initial_state_hash))
        local player = prt.new_player(contract.geometry, terminal_inputs, terminal_cache, {
            new_mcycle_computation_hash = function(log2_period, machine_cache, m, bundle_index)
                local kind = bundle_index ~= nil and "refined" or "outer"
                counts[kind] = counts[kind] + 1
                return observe_inputs(prt.new_mcycle_computation_hash(log2_period, machine_cache, m, bundle_index), m)
            end,
            new_uarch_computation_hash = function(log2_period, m, epoch_period_index, bundle_index)
                counts.uarch = counts.uarch + 1
                return observe_inputs(
                    prt.new_uarch_computation_hash(log2_period, m, epoch_period_index, bundle_index),
                    m
                )
            end,
            new_null_computation_hash = function(m)
                return observe_inputs(prt.new_null_computation_hash(m), m)
            end,
        })
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
        assert(counts.refined == 1, "first mcycle opening bypassed the selected builder factory")
        -- Padding may share the first opening with the last bundle. Only an opaque
        -- bundle should call the factory again; both positions must remain queryable.
        local mcycle_last = (1 << contract.geometry.mcycle_height) - 1
        local mcycle_open = pcall(tree.get_node, tree, mcycle_last, 0)
        tree:open_bundle(mcycle_last >> LOG2_BUNDLE_MCYCLE_COUNT)
        assert(tree:get_node(mcycle_last, 0) == terminal_root, "last mcycle bundle has the wrong state")
        local uarch = player:make_uarch_tree(3, 60000)
        uarch:open_bundle(0)
        assert(counts.uarch == 2, "uarch build or first opening bypassed the selected builder factory")
        local uarch_last = (1 << contract.geometry.uarch_height) - 1
        local uarch_open = pcall(uarch.get_node, uarch, uarch_last, 0)
        uarch:open_bundle(uarch_last >> LOG2_BUNDLE_UARCH_CYCLE_COUNT)
        assert(counts.outer == 1, "mcycle build bypassed the selected builder factory")
        assert(counts.refined == (mcycle_open and 1 or 2), "mcycle opening called the wrong number of builders")
        assert(counts.uarch == (uarch_open and 2 or 3), "uarch opening called the wrong number of builders")
        local terminal_logs = player:prove_state_transition(2, 60000, 0)
        assert(
            cartesi.machine:verify_step_uarch(terminal_root, terminal_logs.step_log) == uarch:get_node(0, 0),
            "terminal step does not authenticate against the claim"
        )
        local reset_offset = cartesi.UARCH_CYCLE_MAX
        uarch:open_bundle(reset_offset >> LOG2_BUNDLE_UARCH_CYCLE_COUNT)
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
