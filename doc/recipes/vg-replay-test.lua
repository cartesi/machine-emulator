-- Replay accounting and boundary regressions, run by vg-test.lua.
local socket = require("socket")
local util = require("cartesi.util")
local vg = require("vg")

local measured_machine_methods = {}
local measured_machine_meta = {
    __index = function(self, name)
        return measured_machine_methods[name] or util.forward_method(self, self.machine, name)
    end,
}

local function measured_machine(machine, counts)
    return setmetatable({ machine = machine, counts = counts }, measured_machine_meta)
end

function measured_machine_methods:fork_server()
    self.counts.forks = self.counts.forks + 1
    return measured_machine(assert(self.machine:fork_server()), self.counts)
end

function measured_machine_methods:swap(other)
    self.machine:swap(other.machine)
end

function measured_machine_methods:run(target)
    local before = self.machine:read_reg("mcycle")
    local started = socket.gettime()
    local reason = self.machine:run(target)
    local counts = self.counts
    local phase = counts.phase
    counts.seconds[phase] = counts.seconds[phase] + socket.gettime() - started
    -- Observe execution before the input driver can roll a rejection back.
    counts[phase] = counts[phase] + self.machine:read_reg("mcycle") - before
    return reason
end

local function measured_new_machine(self, initial_state_hash)
    local counts = self.replay_counts
    counts.loads = counts.loads + 1
    return measured_machine(self.unmeasured_new_machine(self, initial_state_hash), counts)
end

local function measured_prefix(self, ...)
    local counts = self.replay_counts
    local phase = counts.phase
    counts.phase = "prefix"
    vg.player_methods.run_to_epoch_input_offset(self, ...)
    counts.phase = phase
end

local measured_events = setmetatable({}, { __index = vg.event_handler })

function measured_events:input_added(index, path)
    local counts = self.replay_counts
    counts.phase = "epoch"
    local before = counts.epoch
    vg.event_handler.input_added(self, index, path)
    counts.inputs[index + 1] = counts.epoch - before
    counts.phase = "replay"
end

-- Input-level reveals cost nothing. Reveals past a fixed point create no
-- tentative pair, although the agreed pair may run forward.
function measured_events:reveal_bisection(agreed, tentative)
    local counts = self.replay_counts
    local before = { counts.loads, counts.forks, counts.prefix, counts.replay }
    local hash = vg.event_handler.reveal_bisection(self, agreed, tentative)
    local fixed = self.input_mcycle_lengths[tentative.epoch_input_offset]
    if vg.covers_at_least_one_input(agreed, tentative) then
        assert(counts.loads == before[1] and counts.forks == before[2], "input-level reveal loaded or forked a machine")
        assert(counts.prefix == before[3] and counts.replay == before[4], "input-level reveal executed mcycles")
        assert(not self.tentative_pair)
    elseif vg.is_past_fixed_point(tentative, fixed) then
        assert(counts.loads == before[1] and not self.tentative_pair, "fixed-point reveal created a tentative pair")
    end
    return hash
end

-- The closest retained checkpoint at or before the input base. Input zero is always retained.
local function closest_checkpoint_offset(player, epoch_input_offset)
    local closest
    for _, checkpoint in ipairs(player.machine_cache.checkpoints) do
        if checkpoint.epoch_input_offset > epoch_input_offset then
            break
        end
        closest = checkpoint.epoch_input_offset
    end
    return closest
end

-- Replay of the inputs between the closest retained checkpoint and the input base.
local function expected_prefix(player, epoch_input_offset)
    local counts = player.replay_counts
    local first = closest_checkpoint_offset(player, epoch_input_offset) + 1
    local prefix = 0
    for input = first, math.min(epoch_input_offset, #player.inputs) do
        prefix = prefix + counts.inputs[input]
    end
    return prefix
end

function measured_events:prove_state_transition(index, offset, cycle)
    local counts = self.replay_counts
    local prefix = expected_prefix(self, index)
    local span = counts.inputs[index + 1] or 0
    assert(counts.prefix == prefix, "agreed prefix was not reconstructed exactly once")
    assert(counts.replay <= 2 * span, "within-input replay exceeded two active spans")
    assert(counts.loads == 0, "bisection reloaded the initial machine")
    local proof = vg.event_handler.prove_state_transition(self, index, offset, cycle)
    counts.rounds = counts.rounds + 1
    print(
        string.format(
            "vg-test: %s replay prefix=%d input=%d budget=%d forks=%d prefix_s=%.3f input_s=%.3f",
            self.label,
            counts.prefix,
            counts.replay,
            prefix + 2 * span,
            counts.forks,
            counts.seconds.prefix,
            counts.seconds.replay
        )
    )
    counts.prefix, counts.replay = 0, 0
    counts.seconds.prefix, counts.seconds.replay = 0, 0
    return proof
end

-- Attach after construction so dishonest players retain their machine overrides.
-- Loads count only subsequent reloads; forks and mcycles include the epoch run.
local function measure(player)
    local counts = {
        phase = "epoch",
        loads = 0,
        forks = 0,
        epoch = 0,
        prefix = 0,
        replay = 0,
        rounds = 0,
        seconds = { epoch = 0, prefix = 0, replay = 0 },
        inputs = {},
    }
    player.replay_counts = counts
    local initial = player.machine_cache.checkpoints[1]
    initial.machine = measured_machine(initial.machine, counts)
    player.epoch_pair.machine = measured_machine(player.epoch_pair.machine, counts)
    player.unmeasured_new_machine, player.new_machine = player.new_machine, measured_new_machine
    player.run_to_epoch_input_offset = measured_prefix
    player.event_handler = measured_events
    return player
end

local function position(input, mcycle, uarch)
    return { epoch_input_offset = input, input_mcycle_offset = mcycle or 0, uarch_cycle = uarch or 0 }
end

-- The policy keeps input zero and spreads the other checkpoints across the epoch, doubling the gap
-- when none can be thinned. A pair is replaced only by a checkpoint closer to the target.
local function check_machine_cache_policy()
    local shutdowns = 0
    local function new_fake()
        return {
            fork_server = function()
                return new_fake()
            end,
            set_cleanup_call = function() end,
            get_root_hash = function()
                return "fake"
            end,
            shutdown_server = function(self)
                if not self.closed then
                    self.closed = true
                    shutdowns = shutdowns + 1
                end
            end,
        }
    end
    local fake = new_fake()
    local machine_cache <close> = vg.new_machine_cache(fake, 3, 1)
    for epoch_input_offset = 1, 10 do
        machine_cache:consider(epoch_input_offset, fake)
    end
    local retained = {}
    for _, checkpoint in ipairs(machine_cache.checkpoints) do
        retained[#retained + 1] = checkpoint.epoch_input_offset
    end
    assert(table.concat(retained, ",") == "0,4,8", "unexpected retained checkpoints " .. table.concat(retained, ","))
    assert(shutdowns == 2 and machine_cache.input_gap == 4)
    local pair <close> = machine_cache:nearest_not_past_epoch_input_offset(0)
    local machine = pair.machine
    local kept <close>, kept_offset = machine_cache:nearer_not_past_epoch_input_offset_or(pair:move(), 0, 3)
    assert(kept.machine == machine and not pair.machine and kept_offset == 0 and not machine.closed)
    local later <close>, later_offset = machine_cache:nearer_not_past_epoch_input_offset_or(kept:move(), 5, 6)
    assert(later.machine == machine and not kept.machine and later_offset == 5 and not machine.closed)
    local clone <close>, clone_offset = machine_cache:nearer_not_past_epoch_input_offset_or(later:move(), 0, 6)
    assert(clone.machine ~= machine and clone_offset == 4 and not later.machine and machine.closed)
    assert(clone.machine ~= fake and clone.revert_root_hash == "fake" and not clone.backup_machine)
    -- Fresh acquisition always clones the nearest retained checkpoint not past the input base.
    local initial <close>, initial_offset = machine_cache:nearest_not_past_epoch_input_offset(3)
    assert(initial.machine ~= fake and initial_offset == 0)
    machine_cache:close()
    assert(shutdowns == 6 and machine_cache.checkpoints == nil)
    assert(not clone.machine.closed and not initial.machine.closed, "cache closed independently owned pairs")

    -- Replay failures must close both a fork and any snapshot without waiting for GC.
    for _, replace in ipairs({ false, true }) do
        local cache <close> = vg.new_machine_cache(new_fake(), 2, 1)
        if replace then
            cache:consider(1, fake)
        end
        local original <close> = cache:nearest_not_past_epoch_input_offset(0)
        local before = shutdowns
        local player = {
            machine_cache = cache,
            run_to_epoch_input_offset = function(_, advancing)
                advancing:snapshot()
                error("injected replay failure")
            end,
        }
        local first = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
        local target = { epoch_input_offset = replace and 2 or 1, input_mcycle_offset = 0, uarch_cycle = 0 }
        local ok, err = pcall(vg.player_methods.run_to_position, player, original:move(), first, target)
        assert(not ok and tostring(err):find("injected replay failure", 1, true))
        assert(not original.machine and shutdowns == before + (replace and 3 or 2))
    end
end

local function run(initial_hash, paths)
    check_machine_cache_policy()
    local started = socket.gettime()
    -- One checkpoint besides input zero forces eviction and leaves bases that replay from input zero.
    local player <close> =
        vg.new_player(initial_hash, nil, nil, { machine_cache_capacity = 2, machine_cache_input_gap = 1 })
    print(string.format("vg-test: new_player_s=%.3f", socket.gettime() - started))
    measure(player)
    for index, path in ipairs(paths) do
        player.event_handler.input_added(player, index - 1, path)
    end
    player.event_handler.epoch_sealed(player)
    local counts = player.replay_counts
    assert(counts.inputs[1] ~= counts.inputs[2], "fixture must include unequal input costs")
    assert(closest_checkpoint_offset(player, #paths) == #paths)
    assert(closest_checkpoint_offset(player, #paths - 1) == 0, "earlier checkpoints were not evicted")
    local origin = position(0)
    player.event_handler.dispute_started(player)
    local agreed = origin
    -- Successive agreements, including the final base and unposted padding,
    -- answer from input base hashes without a tentative pair.
    for _, index in ipairs({ 1, 2, #paths, #paths + 1, (1 << 16) - 1 }) do
        local tentative = position(index)
        local expected = player.state_hashes_before_inputs[math.min(index, #paths)]
        assert(player.event_handler.reveal_bisection(player, agreed, tentative) == expected)
        assert(not player.tentative_pair)
        agreed = tentative
    end

    -- Compare all recorded posted boundaries with the ordinary input driver.
    local replay <close> = player:new_machine_pair_at_epoch_input_offset(0)
    for index = 0, #paths - 1 do
        assert(replay.machine:get_root_hash() == player.state_hashes_before_inputs[index])
        player:run_to_epoch_input_offset(replay, player.inputs, index, index + 1)
        assert(replay.machine:get_root_hash() == player.state_hashes_before_inputs[index + 1])
    end

    -- Fresh execution starts at the exact requested boundary, including an evicted
    -- boundary and an unposted input. The requested input remains undelivered.
    for index = 0, #paths + 1 do
        local pair <close> = player:new_machine_pair_at_epoch_input_offset(index)
        assert(pair.machine:get_root_hash() == player.state_hashes_before_inputs[math.min(index, #paths)])
        assert(not pair.backup_machine and counts.loads == 0, "boundary acquisition reloaded or delivered an input")
    end

    -- Check both accepted and rejected fixed points immediately before, at, and
    -- after completion. Each ordinary replay forks the same input boundary.
    local boundary <close> = player:new_machine_pair_at_epoch_input_offset(0)
    for index = 0, #paths - 1 do
        local fixed = assert(player.input_mcycle_lengths[index])
        assert(fixed > 1)
        for _, offset in ipairs({ fixed - 1, fixed, fixed + 1 }) do
            local probe <close> = boundary:fork()
            player:run_to_input_mcycle_offset(probe, player.inputs[index + 1], 0, offset)
            player:reset_bisection()
            local hash = player.event_handler.reveal_bisection(player, position(index), position(index, offset))
            assert(hash == probe.machine:get_root_hash())
            if offset < fixed then
                assert(player.tentative_pair and player.tentative_pair.backup_machine)
            else
                assert(not player.tentative_pair)
            end
        end
        player:run_to_epoch_input_offset(boundary, player.inputs, index, index + 1)
    end

    -- Cached input agreements reconstruct their prefix once, whether execution
    -- first enters mcycle bisection, uarch bisection, or the unposted tail.
    for _, target in ipairs({ position(2, 1), position(2, 0, 1), position(#paths, 0, 1) }) do
        player:reset_bisection()
        counts.prefix, counts.replay = 0, 0
        counts.seconds.prefix, counts.seconds.replay = 0, 0
        agreed = position(target.epoch_input_offset)
        player.event_handler.reveal_bisection(player, origin, agreed)
        local prefix = expected_prefix(player, target.epoch_input_offset)
        player.event_handler.reveal_bisection(player, agreed, target)
        assert(counts.prefix == prefix)
        local materialized = player.agreed_pair.machine
        player.event_handler.reveal_bisection(player, agreed, target)
        assert(counts.prefix == prefix and player.agreed_pair.machine == materialized)
    end

    -- Agree on active work and then on a recorded fixed point. Running the agreed
    -- pair forward must retain the active prefix, including when completion rolls it back.
    for index = 0, 1 do
        player:reset_bisection()
        counts.prefix, counts.replay = 0, 0
        counts.seconds.prefix, counts.seconds.replay = 0, 0
        local fixed = player.input_mcycle_lengths[index]
        local active = position(index, fixed // 2)
        local completed = position(index, fixed)
        player.event_handler.reveal_bisection(player, position(index), active)
        local candidate_machine = player.tentative_pair.machine
        player.event_handler.reveal_bisection(player, active, completed)
        assert(
            player.agreed_pair.machine == candidate_machine
                and player.agreed_pair.backup_machine
                and not player.tentative_pair
        )
        assert(counts.replay == fixed // 2)
        local after = player.event_handler.reveal_bisection(player, completed, position(index, fixed, 1))
        assert(player.agreed_pair.machine == candidate_machine and not player.agreed_pair.backup_machine)
        assert(player.agreed_pair.machine:get_root_hash() == player.state_hashes_before_inputs[index + 1])
        assert(counts.replay == fixed, "agreement on a recorded fixed point repeated active work")
        local proof = player.event_handler.prove_state_transition(player, index, fixed, 0)
        assert(
            vg.validate_state_transition_response(
                { inputs = player.inputs },
                player.state_hashes_before_inputs[index + 1],
                index,
                fixed,
                0,
                proof
            ) == after
        )
    end
    local initial_machine = player.machine_cache.checkpoints[1].machine
    assert(initial_machine:get_root_hash() == initial_hash, "initial machine was mutated")
    assert(counts.loads == 0)

    local empty <close> = measure(vg.new_player(initial_hash))
    empty.event_handler.epoch_sealed(empty)
    empty.event_handler.dispute_started(empty)
    for _, index in ipairs({ 1, (1 << 16) - 1 }) do
        assert(empty.event_handler.reveal_bisection(empty, origin, position(index)) == initial_hash)
        assert(not empty.tentative_pair)
    end
    empty.event_handler.reveal_bisection(empty, origin, position(0, 0, 1))
    assert(empty.agreed_pair and empty.tentative_pair)
    print("vg-test: recorded bases, fixed points and prefix reconstruction ok")
end

return { measure = measure, run = run }
