-- Checks claim trees, proofs, and the referee with synthetic state, then, when given an initial
-- machine hash and inputs, checks checkpoint replay against a real machine. The synthetic claims
-- are walked under both claim orders. The loopback referee tests its tournament lifecycle,
-- valid moves, rejected proofs that leave connections open, and logical-block barriers.
-- The real-machine cases cover tampering during replay
-- and bundle collection inside and past rejected inputs. Exits nonzero on the first failure.

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

-- Coordinates remain zero-based across input boundaries and fit in separate 64-bit integers.
do
    local geometry = prt.new_geometry(10)
    local periods = geometry.periods_per_input
    for _, case in ipairs({ { 0, 0 }, { 0, periods - 1 }, { 1, 0 }, { (1 << 24) - 1, periods - 1 } }) do
        local epoch_period = prt.combine_epoch_period_index(periods, case[1], case[2])
        local input_index, period_index = prt.split_epoch_period_index(periods, epoch_period)
        assert(input_index == case[1] and period_index == case[2], "epoch period conversion changed the coordinates")
    end
    local mcycle_offset, uarch_cycle = prt.split_state_transition_offset((1 << geometry.uarch_height) - 1)
    assert(mcycle_offset == geometry.mcycles_per_period - 1 and uarch_cycle == cartesi.UARCH_CYCLE_MAX)
    assert(
        prt.combine_input_mcycle_offset(geometry.mcycles_per_period, periods - 1, mcycle_offset)
            == (1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE) - 1
    )
    mcycle_offset, uarch_cycle = prt.split_state_transition_offset(cartesi.UARCH_CYCLE_MAX + 1)
    assert(mcycle_offset == 1 and uarch_cycle == 0, "transition split missed the next mcycle")
end

-- Collector results include a final padding root at a fixed point. It is not an extra
-- ordinary bundle when the requested coverage is already full.
for _, case in ipairs({
    { log2_period = 44, ordinary = 1 }, -- one full input bundle, plus the unused padding descriptor
    { log2_period = 43, ordinary = 1 }, -- one completed bundle, followed by one padding bundle
    { log2_period = 44, ordinary = 2, invalid = true }, -- ordinary overcollection must fail
}) do
    local ordinary, padding = keccak("ordinary bundle"), keccak("padding bundle")
    local machine = { mcycle = 100 }
    function machine:read_reg(name)
        assert(name == "mcycle")
        return self.mcycle
    end
    function machine.collect_mcycle_root_hashes()
        local hashes = {}
        for i = 1, case.ordinary do
            hashes[i] = ordinary
        end
        hashes[#hashes + 1] = padding
        return { hashes = hashes, break_reason = cartesi.BREAK_REASON_MCYCLE_OVERFLOW, mcycle_phase = 0 }
    end
    local cache = { freeze = function() end }
    local builder = prt.make_mcycle_computation_hash_builder(case.log2_period, cache, machine)
    builder:begin_epoch()
    builder:begin_input(0)
    local ok, reason = pcall(builder.run, builder, cartesi.MCYCLE_MAX)
    if case.invalid then
        assert(not ok and tostring(reason):find("exceeds the input's bundle capacity", 1, true))
        assert(builder.bundle_count == 0, "overcollection changed the forest before failing")
    else
        assert(ok and reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
        assert(builder.input_bundle_count == builder.max_bundles_per_input)
        builder:end_input()
        local forest = builder:end_epoch()
        for i = 0, builder.max_bundles_per_input - 1 do
            local obtained =
                hash_tree.frontier_forest_get_node_hash(forest, i << builder.bundle_height, builder.bundle_height)
            assert(obtained == (i < case.ordinary and ordinary or padding), "fixed-point padding changed a bundle")
        end
        local last_leaf = (builder.max_bundle_count - 1) << builder.bundle_height
        assert(
            hash_tree.frontier_forest_get_node_hash(forest, last_leaf, builder.bundle_height) == padding,
            "fixed-point padding has the wrong final sample"
        )
    end
end

-- A minimal cache and input boundary for exercising the player's direct bundle collectors.
local function new_bundle_player(machine)
    machine.mcycle, machine.root_hash = 0, "virgin"
    function machine:read_reg(name)
        assert(name == "mcycle")
        return self.mcycle
    end
    function machine:get_root_hash()
        return self.root_hash
    end
    function machine:send_cmio_response()
        self.delivered, self.root_hash = true, "delivered"
    end
    function machine:receive_cmio_request()
        if self.rejected then
            return cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED, ""
        end
        return cartesi.HTIF_YIELD_CMD_AUTOMATIC, cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT, ""
    end
    machine.run = machine.run
        or function(self, target)
            self.mcycle = target
            return cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
        end
    local cache = {}
    function cache.clone_at_input_boundary(_, input_index)
        assert(input_index == 0)
        return machine
    end
    function cache:snapshot()
        self.saved_mcycle, self.saved_root = machine.mcycle, machine.root_hash
    end
    function cache.commit() end
    function cache:revert()
        machine.mcycle, machine.root_hash = self.saved_mcycle, self.saved_root
        machine.rejected, machine.delivered, machine.rolled_back = false, false, true
    end
    return prt.new_player(prt.new_geometry(10), { "input" }, cache)
end

-- Direct mcycle collection pads both an already stopped machine and a partial bundle.
for _, count in ipairs({ 0, 3, 15, 17 }) do
    local ordinary, padding = keccak("ordinary sample"), keccak("padding sample")
    local machine = {}
    function machine.collect_mcycle_root_hashes(_, target, log2_period, phase, height)
        assert(target == 128 * 1024 and log2_period == 10 and phase == 0 and height == 0)
        local hashes = {}
        for i = 1, count do
            hashes[i] = ordinary
        end
        hashes[#hashes + 1] = padding
        return { hashes = hashes, mcycle_phase = 0, break_reason = cartesi.BREAK_REASON_MCYCLE_OVERFLOW }
    end
    local player = new_bundle_player(machine)
    local ok, forest = pcall(player.collect_mcycle_bundle, player, 7)
    if count > 16 then
        assert(not ok and tostring(forest):find("exceeds the bundle's leaf capacity", 1, true))
    else
        assert(ok, forest)
        for i = 0, 15 do
            local expected = i < count and ordinary or padding
            assert(hash_tree.frontier_forest_get_node_hash(forest, i, 0) == expected)
        end
    end
end

-- Preserve the mcycle phase across automatic yields and soft yields from a strategy.
do
    local first, middle, padding = keccak("first sample"), keccak("middle sample"), keccak("padding sample")
    local machine = { calls = 0 }
    function machine:collect_mcycle_root_hashes(target, log2_period, phase, height)
        assert(target == 16384 and log2_period == 10 and height == 0)
        self.calls = self.calls + 1
        if self.calls == 1 then
            assert(phase == 0)
            self.mcycle = 1536
            return { hashes = { first }, mcycle_phase = 512, break_reason = cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY }
        elseif self.calls == 2 then
            assert(phase == 512)
            self.mcycle = 3072
            return {
                hashes = { middle, middle },
                mcycle_phase = 0,
                break_reason = cartesi.BREAK_REASON_YIELDED_SOFTLY,
            }
        end
        assert(self.calls == 3 and phase == 0)
        self.mcycle = 3584
        return { hashes = { padding }, mcycle_phase = 0, break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY }
    end
    local forest = new_bundle_player(machine):collect_mcycle_bundle(0)
    for i = 0, 15 do
        local expected = i == 0 and first or (i < 3 and middle or padding)
        assert(
            hash_tree.frontier_forest_get_node_hash(forest, i, 0) == expected,
            "bundle collection lost its phase or samples"
        )
    end
end

-- Uarch replay uses the null input driver, including rollback before collection when
-- rejection precedes the selected mcycle. Exercise the real prefix and reset-ending leaves,
-- and automatic yields during replay and at the end of collection.
for _, rejected in ipairs({ false, true }) do
    local bundles_per_mcycle = 1 << (cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - LOG2_BUNDLE_UARCH_CYCLE_COUNT)
    for _, offset in ipairs({ 0, bundles_per_mcycle - 1 }) do
        local first, second, halted, reset =
            keccak("uarch first"), keccak("uarch second"), keccak("halted"), keccak("reset")
        local tail = { first, second, halted, reset }
        local machine = { replay_calls = 0, collection_calls = 0 }
        function machine:run(target)
            assert(self.delivered and target == 1026)
            self.replay_calls = self.replay_calls + 1
            if self.replay_calls == 1 then
                self.mcycle = 1
                return cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            end
            assert(self.replay_calls == 2)
            if rejected then
                self.mcycle, self.rejected = 2, true
                return cartesi.BREAK_REASON_YIELDED_MANUALLY
            end
            self.mcycle = target
            return cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
        end
        function machine:collect_uarch_cycle_root_hashes(target, height, revert_tail)
            assert(height == 0)
            if not self.delivered and not self.rolled_back then
                assert(target == cartesi.MCYCLE_MAX and revert_tail == nil)
                return { hashes = tail }
            end
            assert(revert_tail == tail)
            self.collection_calls = self.collection_calls + 1
            assert(self.collection_calls == 1, "completed bundle collected another mcycle")
            if rejected then
                assert(self.rolled_back and self.mcycle == 0 and target == 1)
                return {
                    hashes = tail,
                    mcycle_hash_offsets = { 1, 5 },
                    break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
                }
            end
            assert(self.mcycle == 1026 and target == 1027)
            self.mcycle = target
            return {
                hashes = tail,
                mcycle_hash_offsets = { 1, 5 },
                break_reason = cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY,
            }
        end
        local player = new_bundle_player(machine)
        local forest = player:collect_uarch_cycle_bundle(0, 1, 2 * bundles_per_mcycle + offset)
        local last_leaf = (1 << LOG2_BUNDLE_UARCH_CYCLE_COUNT) - 1
        assert(hash_tree.frontier_forest_get_node_hash(forest, 0, 0) == (offset == 0 and first or halted))
        assert(hash_tree.frontier_forest_get_node_hash(forest, 1, 0) == (offset == 0 and second or halted))
        assert(hash_tree.frontier_forest_get_node_hash(forest, last_leaf, 0) == (offset == 0 and halted or reset))
        assert(machine.replay_calls == 2 and machine.collection_calls == 1)
    end
end

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
    function machine:read_reg(name)
        if name == "iflags_Y" then
            return 1
        elseif name == "htif_tohost_dev" then
            return cartesi.HTIF_DEV_YIELD
        elseif name == "htif_tohost_cmd" then
            return cartesi.HTIF_YIELD_CMD_MANUAL
        elseif name == "htif_tohost_reason" then
            return cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
        end
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
    function machine:collect_mcycle_root_hashes(_, _, phase, bundle_height)
        local hash = self.root_hash
        for _ = 1, bundle_height do
            hash = keccak(hash, hash)
        end
        return { hashes = { hash }, mcycle_phase = phase, break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY }
    end
    return setmetatable(machine, { __close = machine.shutdown_server })
end

local function noop() end

-- Construct actual strategy claims, including the final proof's bundle replay.
-- A fabricated claim must supply matching leaves before it can even be posted.
do
    local geometry = prt.new_geometry(10)
    local input_hash, forged_hash = keccak("input"), keccak("forged")
    local last_input = (1 << cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH) - 1
    for _, case in ipairs({
        {
            make = function(inputs, cache)
                return prt.new_player(geometry, inputs, cache)
            end,
            final_hash = input_hash,
        },
        {
            make = function(inputs, cache)
                return dishonest.new_forger(geometry, inputs, cache, 0, forged_hash)
            end,
            final_hash = forged_hash,
        },
        {
            make = function(inputs, cache)
                return dishonest.new_tamperer(geometry, inputs, cache, 0, 100)
            end,
            final_hash = input_hash,
        },
        {
            make = function(inputs, cache)
                return dishonest.new_fabulist(geometry, inputs, cache, last_input, geometry.periods_per_input - 1)
            end,
            final_hash = keccak("fabulist"),
        },
        {
            make = function(inputs, cache)
                return dishonest.new_quitter(geometry, inputs, cache)
            end,
            final_hash = keccak("quitter"),
            quitter = true,
        },
        {
            make = function(inputs, cache)
                return dishonest.new_quitter(geometry, inputs, cache, { seed = "custom quitter" })
            end,
            final_hash = keccak("custom quitter"),
            quitter = true,
        },
    }) do
        local cache <close> = prt.new_machine_cache(new_fake_machine(keccak("initial")))
        local inputs = { input_hash }
        local player = case.make(inputs, cache)
        local claim = player:commit_mcycle_claim()
        assert(cache.frozen, player.label .. " did not freeze the epoch's cache")
        local proof = claim.final_state_hash_proof
        assert(proof.target_address == (1 << geometry.mcycle_height) - 1)
        assert(proof.target_hash == case.final_hash, player.label .. " claimed the wrong final state")
        assert(proof.root_hash == keccak(claim.computation_hash_left, claim.computation_hash_right))
        hash_tree.verify_slice(proof)
        if case.quitter then
            local expected_root = case.final_hash
            for _ = 1, geometry.mcycle_height do
                expected_root = keccak(expected_root, expected_root)
            end
            assert(proof.root_hash == expected_root and player.done, "quitter did not post its fabricated claim")
        end
    end
end

-- All builders expose machine methods with the native receiver, but not machine data fields.
do
    local machine = new_fake_machine("initial")
    local cache <close> = prt.new_machine_cache(machine)
    local geometry = prt.new_geometry(10)
    for _, builder in ipairs({
        prt.make_null_computation_hash_builder(machine),
        prt.make_mcycle_computation_hash_builder(geometry.log2_mcycles_per_period, cache, machine),
        prt.make_uarch_cycle_computation_hash_builder(geometry.log2_mcycles_per_period, machine, 0),
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
    local rejected = new_fake_machine("rejected")
    rejected.fail_clone = true
    function rejected.receive_cmio_request()
        return cartesi.HTIF_YIELD_CMD_MANUAL, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED, ""
    end
    cache:consider(1, rejected)
    assert(#cache.checkpoints == 1, "cache retained a rejected input")
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
    cache:freeze()
    local checkpoints = { table.unpack(cache.checkpoints) }
    local input_gap, replace_cursor = cache.input_gap, cache.replace_cursor
    local ignored = new_fake_machine("ignored")
    ignored.fail_clone = true
    function ignored.receive_cmio_request()
        error("frozen cache inspected an offered machine")
    end
    cache:consider(1, ignored)
    cache:consider(9, ignored)
    assert(#cache.checkpoints == #checkpoints, "frozen cache changed its checkpoint count")
    for i, checkpoint in ipairs(checkpoints) do
        assert(cache.checkpoints[i] == checkpoint, "frozen cache replaced a checkpoint")
    end
    assert(cache.input_gap == input_gap and cache.replace_cursor == replace_cursor, "frozen cache changed its policy")
    local replay, replay_owner <close> = cache:clone_at_input_boundary(7, noop) -- luacheck: ignore 211
    assert(replay:get_root_hash() == "6", "frozen cache cannot replay from a retained checkpoint")
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
    assert(counts.live == 0 and not next(cache.owners), "cache shutdown left owned machines alive")
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
        make_null_computation_hash_builder = function(machine)
            assert(phase ~= "factory", "injected factory failure")
            local builder = prt.make_null_computation_hash_builder(machine)
            builder[phase] = function()
                error("injected " .. phase .. " failure")
            end
            return builder
        end,
    })
    local ok, err = pcall(player.make_uarch_tree, player, 1, 0)
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
        make_mcycle_computation_hash_builder = function(_, _, machine)
            assert(phase ~= "factory", "injected factory failure")
            local builder = prt.make_null_computation_hash_builder(machine)
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
        make_mcycle_computation_hash_builder = function(_, _, machine)
            local builder = prt.make_null_computation_hash_builder(machine)
            builder.run = function(_, mcycle_end)
                assert(
                    mcycle_end == 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE,
                    "builder received the wrong cycle limit"
                )
                runs = runs + 1
                return assert(reasons[runs], "builder resumed past its terminal reason")
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
    assert(
        manual_reads == (terminal == cartesi.BREAK_REASON_YIELDED_MANUALLY and 1 or 0),
        "delivery read the boundary yield"
    )
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
        make_mcycle_computation_hash_builder = function(_, _, machine)
            local builder = prt.make_null_computation_hash_builder(machine)
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
        make_null_computation_hash_builder = function(machine)
            local builder = prt.make_null_computation_hash_builder(machine)
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
        make_uarch_cycle_computation_hash_builder = function()
            error("replay complete")
        end,
    })
    local ok, err = pcall(player.make_uarch_tree, player, 2, 0)
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
-- flat or bundled 2^2 leaves per stored bundle, so the bundle collection path is exercised too.
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
        tree = forest
    else
        tree = build_leaf_forest(0, HEIGHT)
    end
    local bundle_height = bundled and 2 or 0
    tree = prt.new_tree(HEIGHT, bundle_height, tree, function(_, bundle_index)
        return build_leaf_forest(bundle_index << bundle_height, bundle_height)
    end)
    local computation_hash_left, computation_hash_right = tree:get_children(0, HEIGHT)
    local proof = tree:get_proof(LEAVES - 1)
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
    local tree = match.claims[match.turn_index].tree
    return prt.player_handlers.reveal_bisection(
        { trees = { [tree:get_root()] = tree } },
        tree:get_root(),
        match.position,
        match.height,
        match.other_left_node
    )
end

local function make_seal_response(match)
    local tree = match.claims[match.turn_index].tree
    return prt.player_handlers.seal_divergence(
        { trees = { [tree:get_root()] = tree } },
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
    local calls = 0
    local collect = claim.tree.collect_bundle
    claim.tree.collect_bundle = function(self, index)
        calls = calls + 1
        return collect(self, index)
    end
    for i = 0, 3 do
        hash_tree.verify_slice(claim.tree:get_proof(i))
    end
    assert(calls == 1, "proofs in the same bundle replayed more than once")
    assert(claim.tree:get_node(unopened_index, 0) == base_state_hash)
end
-- Expanded padding serves all repeated bundles without replaying them separately.
do
    local bundle = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_pad_back(bundle, base_state_hash, 4)
    local tree = hash_tree.frontier_forest(HEIGHT, "keccak256")
    hash_tree.frontier_forest_pad_back(tree, hash_tree.frontier_forest_get_root_hash(bundle), LEAVES >> 2, 2)
    local calls = 0
    tree = prt.new_tree(tree.height, 2, tree, function()
        calls = calls + 1
        return bundle
    end)
    local root = tree:get_root()
    hash_tree.verify_slice(tree:get_proof(LEAVES - 1))
    for i = 0, LEAVES - 1 do
        local proof = tree:get_proof(i)
        assert(proof.target_hash == base_state_hash, "expanded padding has the wrong leaf")
        assert(proof.root_hash == root, "opening a bundle changed the commitment")
        hash_tree.verify_slice(proof)
    end
    assert(calls == 1, "opening repeated bundles reran the machine")
end

-- Invalid proof queries must fail before invoking the bundle collector.
do
    local tree = hash_tree.frontier_forest(HEIGHT, "keccak256")
    local calls = 0
    tree = prt.new_tree(HEIGHT, 2, tree, function()
        calls = calls + 1
        error("invalid query reached the bundle collector")
    end)
    assert(not pcall(tree.get_proof, tree, 0), "an incomplete forest accepted a proof query")
    assert(calls == 0, "an incomplete forest invoked the bundle collector")
    local bundle_root = keccak(keccak(base_state_hash, base_state_hash), keccak(base_state_hash, base_state_hash))
    hash_tree.frontier_forest_pad_back(tree.forest, bundle_root, LEAVES >> 2, 2)
    for _, index in ipairs({ -1, LEAVES, 1 << 62, 0.5, "0" }) do
        assert(not pcall(tree.get_proof, tree, index), "an invalid leaf index accepted a proof query")
        assert(calls == 0, "an invalid leaf index invoked the bundle collector")
    end
    for _, height in ipairs({ -1, HEIGHT + 1 }) do
        assert(not pcall(tree.get_proof, tree, 0, height), "an invalid height accepted a proof query")
    end
    assert(not pcall(tree.get_proof, tree, 1, 2), "an unaligned position accepted a proof query")
    assert(calls == 0, "an invalid node invoked the bundle collector")
end

-- A failed reconstruction must leave the commitment opaque and allow a valid retry.
do
    local bundle = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_pad_back(bundle, base_state_hash, 4)
    local tree = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_push_back(tree, hash_tree.frontier_forest_get_root_hash(bundle), 2)
    local replacement = hash_tree.frontier_forest(2, "keccak256")
    hash_tree.frontier_forest_pad_back(replacement, fake_state_hash, 4)
    tree = prt.new_tree(tree.height, 2, tree, function()
        return replacement
    end)
    local root = tree:get_root()
    assert(not pcall(tree.get_proof, tree, 0), "a mismatched bundle was installed")
    assert(not pcall(tree.get_node, tree, 0, 0), "a failed expansion exposed a leaf")
    assert(tree:get_root() == root, "a failed expansion changed the commitment")
    replacement = bundle
    hash_tree.verify_slice(tree:get_proof(0))
end

for _, lie in ipairs({ 0, 1, 4, 6, 13, LEAVES - 1 }) do
    for _, bundled in ipairs({ false, true }) do
        local honest = make_synthetic_claim(base_state_hash, nil, nil, bundled)
        local liar = make_synthetic_claim(base_state_hash, lie, fake_state_hash, bundled)
        assert(honest.computation_hash ~= liar.computation_hash)
        -- honest opens first
        local divergence = walk(honest, liar)
        assert(divergence.leaf_index == lie, "walk missed the divergent state")
        assert(
            divergence.next_state_hashes[1] == base_state_hash and divergence.next_state_hashes[2] == fake_state_hash,
            "walk misattributed the states"
        )
        -- liar opens first: the same leaf, the claims swapped
        local mirrored = walk(liar, honest)
        assert(
            mirrored.leaf_index == lie
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
                        or wire_event.id
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
            end,
            server:request_block() + 10
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
    -- boundary must apply the same corruption again, so bundle collection matches an uncached build.
    local tamperer_inputs, tamperer_cache <close> = new_test_cache(dapp_contract, 64, 1)
    local tamperer = dishonest.new_tamperer(dapp_contract.geometry, tamperer_inputs, tamperer_cache, 0, 100)
    local tampered_tree = tamperer:make_mcycle_tree()
    tampered_tree:get_proof(99 << tampered_tree.bundle_height)
    tampered_tree:get_proof(100 << tampered_tree.bundle_height)
    local uncached_tamperer_inputs, uncached_tamperer_cache <close> = new_test_cache(dapp_contract, 1)
    local uncached_tamperer =
        dishonest.new_tamperer(dapp_contract.geometry, uncached_tamperer_inputs, uncached_tamperer_cache, 0, 100)
    local uncached_tampered_tree = uncached_tamperer:make_mcycle_tree()
    assert(uncached_tampered_tree:get_root() == tampered_tree:get_root(), "cache changed the tampered claim")
    uncached_tampered_tree:get_proof(100 << uncached_tampered_tree.bundle_height)
    local tampered_first_leaf = 100 << LOG2_BUNDLE_MCYCLE_COUNT
    for leaf = tampered_first_leaf, tampered_first_leaf + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1 do
        assert(
            uncached_tampered_tree:get_node(leaf, 0) == tampered_tree:get_node(leaf, 0),
            "cache changed replay out of the tamper point"
        )
    end

    -- Fabulist run can collect a bundle synchronously while the outer input is still running. Both
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
            for _, owner in pairs(self.owners) do
                active = active + (owner.backup and 1 or 0)
            end
            maximum = math.max(maximum, active)
        end
        local tree = fabulist:make_mcycle_tree()
        tree:get_proof(1 << tree.bundle_height)
        assert(maximum >= 2, "fabulist did not exercise nested snapshots")
        assert(tree:get_node(16, 0) == keccak("fabulist"), "nested bundle collection lost the fabricated leaf")
        local retained = 0
        for _, owner in pairs(cache.owners) do
            assert(not owner.backup, "nested bundle collection leaked a snapshot")
            retained = retained + 1
        end
        assert(retained == #cache.checkpoints, "nested bundle collection leaked an execution")
    end

    -- Bundle collection is a read of the committed claim. It must not replace build checkpoints with
    -- speculative machines from an input whose committed suffix is its revert state.
    local honest_inputs, honest_cache <close> = new_test_cache(dapp_contract, 1)
    local honest = prt.new_player(dapp_contract.geometry, honest_inputs, honest_cache)
    local cache = honest_cache
    local native <close> = prt.new_machine(initial_state_hash)
    assert(type(native) == "userdata", "honest machine is wrapped")
    assert(type(cache.checkpoints[1].machine) == "userdata", "honest checkpoint machine is wrapped")
    local native_builder =
        prt.make_mcycle_computation_hash_builder(dapp_contract.geometry.log2_mcycles_per_period, cache, native)
    assert(rawget(native_builder, "machine") == native, "honest computation-hash builder is wrapped")
    assert(native_builder.unbundle == nil, "honest builder exposes strategy-only bundle collection")
    assert(native_builder.pad_back == nil, "honest builder exposes strategy-only insertion")
    local native_uarch_builder =
        prt.make_uarch_cycle_computation_hash_builder(dapp_contract.geometry.log2_mcycles_per_period, native, 0)
    assert(rawget(native_uarch_builder, "machine") == native, "honest uarch builder is wrapped")
    assert(native_uarch_builder.unbundle == nil, "honest uarch builder exposes strategy-only bundle collection")
    assert(native_uarch_builder.pad_back == nil, "honest uarch builder exposes strategy-only insertion")
    local virgin_root = native:get_root_hash()
    native_uarch_builder:begin_input(0, native:read_reg("mcycle"))
    assert(native:get_root_hash() == virgin_root, "capturing the revert tail changed the virgin machine")
    assert(
        rawget(prt.make_null_computation_hash_builder(native), "machine") == native,
        "honest replay builder is wrapped"
    )

    local honest_tree = honest:make_mcycle_tree()
    local checkpoint = assert(cache.checkpoints[1], "claim build retained no machine checkpoint").input_index
    honest_tree:get_proof(dapp_contract.geometry.periods_per_input)
    assert(cache.checkpoints[1].input_index == checkpoint, "mcycle bundle collection changed the machine cache")
    local cached_inputs, cached_cache <close> = new_test_cache(dapp_contract)
    local cached = prt.new_player(dapp_contract.geometry, cached_inputs, cached_cache)
    local cached_tree = cached:make_mcycle_tree()
    for _, saved in ipairs(cached_cache.checkpoints) do
        assert(type(saved.machine) == "userdata", "checkpoint machine is wrapped")
    end
    assert(cached_tree:get_root() == honest_tree:get_root(), "cache policy changed the mcycle root")
    assert(honest_tree:get_root() == util.read_file(assert(arg[5])), "mcycle root differs from CLI")
    -- This fabricated leaf is beyond the last input, so end_epoch must insert it even when
    -- bundle collection never calls run. Opening the bundle also authenticates the returned subtree.
    do
        local fabulist_inputs, fabulist_cache <close> = new_test_cache(dapp_contract)
        local fabulist = dishonest.new_fabulist(dapp_contract.geometry, fabulist_inputs, fabulist_cache, #inputs, 16)
        local tree = fabulist:make_mcycle_tree()
        local leaf = #inputs * dapp_contract.geometry.periods_per_input + 16
        local bundle = leaf >> LOG2_BUNDLE_MCYCLE_COUNT
        tree:get_proof(bundle << tree.bundle_height)
        honest_tree:get_proof(bundle << honest_tree.bundle_height)
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
        honest_tree:get_proof(bundle_index << honest_tree.bundle_height)
        cached_tree:get_proof(bundle_index << cached_tree.bundle_height)
        local first_leaf = bundle_index << LOG2_BUNDLE_MCYCLE_COUNT
        for leaf = first_leaf, first_leaf + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1 do
            assert(honest_tree:get_node(leaf, 0) == cached_tree:get_node(leaf, 0), "cache changed bundle collection")
        end
    end
    local first_uarch = honest:make_uarch_tree(0, 0)
    assert(first_uarch:get_root() == util.read_file(assert(arg[6])), "uarch root differs from CLI")
    first_uarch:get_proof(0)
    first_uarch:get_proof(
        ((1 << (dapp_contract.geometry.uarch_height - LOG2_BUNDLE_UARCH_CYCLE_COUNT)) - 1) << first_uarch.bundle_height
    )
    local rejected_uarch = honest:make_uarch_tree(1, 60000)
    rejected_uarch:get_proof(0)
    rejected_uarch:get_proof(
        ((1 << (dapp_contract.geometry.uarch_height - LOG2_BUNDLE_UARCH_CYCLE_COUNT)) - 1)
            << rejected_uarch.bundle_height
    )
    assert(
        honest:make_uarch_tree(2, 0):get_root() == cached:make_uarch_tree(2, 0):get_root(),
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
        honest_tree:get_proof(bundle_index << honest_tree.bundle_height)
        dense_tree:get_proof(bundle_index << dense_tree.bundle_height)
        local first_leaf = bundle_index << LOG2_BUNDLE_MCYCLE_COUNT
        for leaf = first_leaf, first_leaf + (1 << LOG2_BUNDLE_MCYCLE_COUNT) - 1 do
            assert(
                honest_tree:get_node(leaf, 0) == dense_tree:get_node(leaf, 0),
                "dense cache changed bundle collection inside the rejected input"
            )
        end
    end
    assert(
        honest:make_uarch_tree(rejected_input_index + 1, 0):get_root()
            == dense:make_uarch_tree(rejected_input_index + 1, 0):get_root(),
        "dense cache changed replay past the rejected input"
    )
    assert(#saved_checkpoints == #dense_cache.checkpoints, "bundle collection changed checkpoint count")
    for i, saved in ipairs(saved_checkpoints) do
        assert(dense_cache.checkpoints[i] == saved, "bundle collection replaced a checkpoint")
    end

    -- Uarch collection and transition proofs replay from the rejected input's own boundary, both
    -- before and after its rejection, and their logs authenticate against the claims.
    for _, period in ipairs({ 16, 60000 }) do
        local uarch = dense:make_uarch_tree(1, period)
        uarch:get_proof(0)
        local logs = dense:prove_state_transition(1, period, 0)
        local preceding_leaf = dapp_contract.geometry.periods_per_input + period - 1
        dense_tree:get_proof(preceding_leaf)
        assert(
            cartesi.machine:verify_step_uarch(dense_tree:get_node(preceding_leaf, 0), logs.step_log)
                == uarch:get_node(0, 0),
            "cached transition does not match the uarch claim"
        )
        local reset_offset = cartesi.UARCH_CYCLE_MAX
        uarch:get_proof(reset_offset)
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
    local new_null = prt.make_null_computation_hash_builder
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
        { make_null_computation_hash_builder = observe_replay }
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
        chain:make_uarch_tree(target, 0)
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
    chain_tree:get_proof(chain_bundle_index << chain_tree.bundle_height)
    assert(lookups == 1, "reverted-tail bundle collection performed multiple lookups")
    assert(replay_begins == 1 and replay_ends == 1, "cache replay bypassed the epoch driver's builder lifecycle")
    assert(
        not input_runs[0] and input_runs[1] == 1 and input_runs[2] == 1,
        "reverted-tail bundle collection did not replay from the boundary before the chain"
    )
    local reference_leaf = 2 * dapp_contract.geometry.periods_per_input - 1
    assert(
        chain_tree:get_node(3 * dapp_contract.geometry.periods_per_input - 1, 0)
            == honest_tree:get_node(reference_leaf, 0),
        "rejection-chain tail differs from the reference"
    )
    lookups, input_runs = 0, {}
    local after_chain = chain:make_uarch_tree(3, 0)
    assert(lookups == 1, "post-chain boundary performed multiple lookups")
    assert(
        not input_runs[0] and input_runs[1] == 1 and input_runs[2] == 1,
        "boundary replay did not roll back each rejected input once"
    )
    assert(after_chain:get_root() == honest:make_uarch_tree(2, 0):get_root(), "chain changed next-input uarch claim")

    -- The actual input-inclusion and first-step logs must authenticate against the state that
    -- the chain resolves to, not merely produce a matching computation root.
    after_chain:get_proof(0)
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

    -- Input delivery inspects no outgoing payload. A valid waiting template can have an
    -- oversized outgoing length, which receive_cmio_request would refuse to read.
    do
        local template = prt.new_machine(initial_state_hash)
        template:write_reg("htif_tohost_data", 0xffffffff)
        local root = template:get_root_hash()
        local payload_cache <close> = prt.new_machine_cache(template)
        local player = prt.new_player(dapp_contract.geometry, { inputs[1] }, payload_cache)
        local mcycle_tree = player:make_mcycle_tree()
        mcycle_tree:get_proof(0)
        local uarch_tree = player:make_uarch_tree(0, 0)
        uarch_tree:get_proof(0)
        local payload_logs = player:prove_state_transition(0, 0, 0)
        local payload_after_send = cartesi.machine:verify_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            inputs[1],
            root,
            payload_logs.send_cmio_log,
            root
        )
        assert(
            cartesi.machine:verify_step_uarch(payload_after_send, payload_logs.step_log) == uarch_tree:get_node(0, 0),
            "outgoing length changed the reconstructed input transition"
        )
    end

    -- Puts a machine in a terminal state. Halt leaves no yield pending, overflow closes the input
    -- budget at the current cycle, and the two manual yields carry a reason no delivery applies to.
    local function force_terminal(m, terminal)
        if terminal == "halt" then
            m:write_reg("iflags_Y", 0)
            m:write_reg("iflags_H", 1)
        elseif terminal == "exception" or terminal == "unexpected" then
            local reason = terminal == "exception" and cartesi.HTIF_YIELD_MANUAL_REASON_TX_EXCEPTION or 0xffff
            m:write_reg("iflags_Y", 1)
            m:write_reg(
                "htif_tohost",
                (cartesi.HTIF_DEV_YIELD << 56) | (cartesi.HTIF_YIELD_CMD_MANUAL << 48) | (reason << 32)
            )
        elseif terminal == "overflow" or terminal == "counter_overflow" then
            m:write_reg("iflags_Y", 0)
            m:write_reg("imcyclemax", m:read_reg("mcycle"))
        end
    end

    -- A template that is not waiting for an input is a deployment error. Check it once
    -- before the forward build, independently of the sender's no-op transitions.
    for _, terminal in ipairs({ "halt", "exception", "unexpected", "overflow" }) do
        local template = prt.new_machine(initial_state_hash)
        force_terminal(template, terminal)
        local template_cache <close> = prt.new_machine_cache(template)
        local player = prt.new_player(dapp_contract.geometry, { table.unpack(inputs) }, template_cache)
        local built, failure = pcall(player.make_mcycle_tree, player)
        local message = tostring(failure)
        assert(not built, terminal .. " template built a claim")
        assert(
            message:find("initial machine is not waiting on an rx-accepted manual yield", 1, true),
            terminal .. " template was refused for the wrong reason: " .. message
        )
    end

    -- Terminal inputs and empty epochs must fill claims and reconstructed bundles from a state
    -- the physical counter cannot leave. The terminal state is forced just after delivery,
    -- identically for sampled execution and plain replay, so later logical inputs pad from it
    -- without delivery.
    for _, terminal in ipairs({ "halt", "exception", "unexpected", "overflow", "counter_overflow", "empty" }) do
        local function make_terminal_template()
            local machine = prt.new_machine(initial_state_hash)
            if terminal == "counter_overflow" then
                machine:write_reg("mcycle", cartesi.MCYCLE_MAX)
            end
            return machine
        end
        local contract = {
            initial_state_hash = initial_state_hash,
            geometry = dapp_contract.geometry,
            inputs = terminal == "empty" and {} or inputs,
        }
        local counts = { outer = 0, bundles = 0, uarch = 0 }
        local function observe_inputs(builder, m)
            local run = builder.run
            builder.run = function(self, target)
                force_terminal(m, terminal)
                return run(self, target)
            end
            return builder
        end
        local terminal_inputs = { table.unpack(contract.inputs) }
        local terminal_cache <close> = prt.new_machine_cache(make_terminal_template())
        local player = prt.new_player(contract.geometry, terminal_inputs, terminal_cache, {
            make_mcycle_computation_hash_builder = function(log2_period, machine_cache, m)
                counts.outer = counts.outer + 1
                return observe_inputs(prt.make_mcycle_computation_hash_builder(log2_period, machine_cache, m), m)
            end,
            make_uarch_cycle_computation_hash_builder = function(log2_period, m, epoch_period_index)
                counts.uarch = counts.uarch + 1
                return observe_inputs(
                    prt.make_uarch_cycle_computation_hash_builder(log2_period, m, epoch_period_index),
                    m
                )
            end,
            make_null_computation_hash_builder = function(m)
                return observe_inputs(prt.make_null_computation_hash_builder(m), m)
            end,
        })
        local collect_mcycle_bundle = player.collect_mcycle_bundle
        player.collect_mcycle_bundle = function(self, bundle_index)
            counts.bundles = counts.bundles + 1
            return collect_mcycle_bundle(self, bundle_index)
        end
        local collect_uarch_cycle_bundle = player.collect_uarch_cycle_bundle
        player.collect_uarch_cycle_bundle = function(self, input_index, period_index, bundle_index)
            counts.uarch = counts.uarch + 1
            return collect_uarch_cycle_bundle(self, input_index, period_index, bundle_index)
        end
        local reference <close> = make_terminal_template()
        if terminal ~= "empty" then
            reference:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, inputs[1], reference:get_root_hash())
            force_terminal(reference, terminal)
        end
        local terminal_root = reference:get_root_hash()
        local expected = terminal_root
        for _ = 1, contract.geometry.mcycle_height do
            expected = keccak(expected, expected)
        end
        local tree = player:make_mcycle_tree()
        assert(tree:get_root() == expected, terminal .. " has the wrong fixed-point tail")
        tree:get_proof(0)
        assert(counts.bundles == 1, "first mcycle opening bypassed the player collector")
        -- Explicit padding shares the completed first bundle when their hashes match.
        -- For both terminal inputs and empty epochs, opening the first bundle opens
        -- the whole repeated tail without another machine replay.
        local mcycle_last = (1 << contract.geometry.mcycle_height) - 1
        tree:get_proof(mcycle_last)
        assert(tree:get_node(mcycle_last, 0) == terminal_root, "last mcycle bundle has the wrong state")
        local uarch = player:make_uarch_tree(2, 60000)
        uarch:get_proof(0)
        assert(counts.uarch == 2, "uarch build or first opening bypassed the selected builder or collector")
        local uarch_last = (1 << contract.geometry.uarch_height) - 1
        uarch:get_proof(uarch_last)
        assert(counts.outer == 1, "mcycle build bypassed the selected builder factory")
        assert(counts.bundles == 1, terminal .. " opening replayed an already expanded mcycle bundle")
        -- The first uarch bundle and the reset-ending bundle in the separate padding
        -- subtree always need distinct openings, in addition to the initial tree build.
        assert(counts.uarch == 3, terminal .. " opening called the wrong number of uarch builders")
        local terminal_logs = player:prove_state_transition(2, 60000, 0)
        assert(
            cartesi.machine:verify_step_uarch(terminal_root, terminal_logs.step_log) == uarch:get_node(0, 0),
            "terminal step does not authenticate against the claim"
        )
        local reset_offset = cartesi.UARCH_CYCLE_MAX
        uarch:get_proof(reset_offset)
        local reset_logs = player:prove_state_transition(2, 60000, reset_offset)
        local after_step = cartesi.machine:verify_step_uarch(uarch:get_node(reset_offset - 1, 0), reset_logs.step_log)
        assert(
            cartesi.machine:verify_reset_uarch(after_step, reset_logs.reset_uarch_log)
                == uarch:get_node(reset_offset, 0),
            "terminal reset does not authenticate against the claim"
        )
        local boundary = player:make_uarch_tree(2, 0)
        boundary:get_proof(0)
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
