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

local function measured_new_machine(self)
    local counts = self.replay_counts
    counts.loads = counts.loads + 1
    return measured_machine(self.unmeasured_new_machine(self), counts)
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
    local index = tentative.epoch_input_offset
    local fixed = self.fixed_point_mcycle_offsets[index + 1]
    if agreed.epoch_input_offset ~= index then
        assert(counts.loads == before[1] and counts.forks == before[2], "input-level reveal loaded or forked a machine")
        assert(counts.prefix == before[3] and counts.replay == before[4], "input-level reveal executed mcycles")
        assert(not self.tentative_pair)
    elseif tentative.uarch_cycle == 0 and fixed and tentative.input_mcycle_offset >= fixed then
        assert(counts.loads == before[1] and not self.tentative_pair, "fixed-point reveal created a tentative pair")
    end
    return hash
end

function measured_events:prove_state_transition(index, offset, cycle)
    local counts = self.replay_counts
    local prefix = 0
    for input = 1, math.min(index, #self.inputs) do
        prefix = prefix + counts.inputs[input]
    end
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
    player.initial_machine = measured_machine(player.initial_machine, counts)
    player.epoch_pair.machine = measured_machine(player.epoch_pair.machine, counts)
    player.unmeasured_new_machine, player.new_machine = player.new_machine, measured_new_machine
    player.run_to_epoch_input_offset = measured_prefix
    player.event_handler = measured_events
    return player
end

local function position(input, mcycle, uarch)
    return { epoch_input_offset = input, input_mcycle_offset = mcycle or 0, uarch_cycle = uarch or 0 }
end

local function run(initial_hash, paths)
    local started = socket.gettime()
    local player <close> = vg.new_player(initial_hash)
    print(string.format("vg-test: new_player_s=%.3f", socket.gettime() - started))
    measure(player)
    for index, path in ipairs(paths) do
        player.event_handler.input_added(player, index - 1, path)
    end
    player.event_handler.epoch_sealed(player)
    local counts = player.replay_counts
    assert(counts.inputs[1] ~= counts.inputs[2], "fixture must include unequal input costs")
    local origin = position(0)
    player.event_handler.dispute_started(player)
    local agreed = origin
    -- Successive agreements, including the final base and unposted padding,
    -- answer from input base hashes without a tentative pair.
    for _, index in ipairs({ 1, 2, #paths, #paths + 1, (1 << 16) - 1 }) do
        local tentative = position(index)
        local expected = player.input_base_hashes[math.min(index, #paths)]
        assert(player.event_handler.reveal_bisection(player, agreed, tentative) == expected)
        assert(not player.tentative_pair)
        agreed = tentative
    end

    -- Compare all recorded posted boundaries with the ordinary input driver.
    local replay <close> = player:new_advancing_pair()
    for index = 0, #paths - 1 do
        assert(replay.machine:get_root_hash() == player.input_base_hashes[index])
        player:run_to_epoch_input_offset(replay, player.inputs, index, index + 1)
        assert(replay.machine:get_root_hash() == player.input_base_hashes[index + 1])
    end

    -- Check both accepted and rejected fixed points immediately before, at, and
    -- after completion. Each ordinary replay forks the same input boundary.
    local boundary <close> = player:new_advancing_pair()
    for index = 0, #paths - 1 do
        local fixed = assert(player.fixed_point_mcycle_offsets[index + 1])
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
        local expected_prefix = 0
        for index = 1, target.epoch_input_offset do
            expected_prefix = expected_prefix + counts.inputs[index]
        end
        player.event_handler.reveal_bisection(player, agreed, target)
        assert(counts.prefix == expected_prefix)
        local materialized = player.agreed_pair
        player.event_handler.reveal_bisection(player, agreed, target)
        assert(counts.prefix == expected_prefix and player.agreed_pair == materialized)
    end

    -- Agree on active work and then on a recorded fixed point. Running the agreed
    -- pair forward must retain the active prefix, including when completion rolls it back.
    for index = 0, 1 do
        player:reset_bisection()
        counts.prefix, counts.replay = 0, 0
        counts.seconds.prefix, counts.seconds.replay = 0, 0
        local fixed = player.fixed_point_mcycle_offsets[index + 1]
        local active = position(index, fixed // 2)
        local completed = position(index, fixed)
        player.event_handler.reveal_bisection(player, position(index), active)
        local candidate = player.tentative_pair
        player.event_handler.reveal_bisection(player, active, completed)
        assert(player.agreed_pair == candidate and candidate.backup_machine and not player.tentative_pair)
        assert(counts.replay == fixed // 2)
        local after = player.event_handler.reveal_bisection(player, completed, position(index, fixed, 1))
        assert(player.agreed_pair == candidate and not candidate.backup_machine)
        assert(candidate.machine:get_root_hash() == player.input_base_hashes[index + 1])
        assert(counts.replay == fixed, "agreement on a recorded fixed point repeated active work")
        local proof = player.event_handler.prove_state_transition(player, index, fixed, 0)
        assert(
            vg.validate_state_transition_response(
                { inputs = player.inputs },
                player.input_base_hashes[index + 1],
                index,
                fixed,
                0,
                proof
            ) == after
        )
    end
    assert(player.initial_machine:get_root_hash() == initial_hash, "initial machine was mutated")
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
