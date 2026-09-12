-- Dishonest players use the same driver, claims, and protocol handlers as the honest
-- player. Their private inputs, machines, or computation hashes tell a different history.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local prtu = require("prtu")
local util = require("cartesi.util")
local keccak = cartesi.keccak256
local umin = prt.umin
local usaturating_add = prt.usaturating_add
local is_target_mcycle = prt.is_target_mcycle
local is_at_fixed_point = prt.is_at_fixed_point

-- Machine and computation-hash wrappers belong to the strategies, not the honest
-- implementation. A native machine never carries this private input bookkeeping.
local machine_methods = {}
local machine_meta = {
    __close = function(self)
        self.snapshot_state = false
        local machine <close> = self.machine -- luacheck: ignore 211
    end,
    __index = function(self, name)
        return self.overrides[name] or machine_methods[name] or util.forward_method(self, self.machine, name)
    end,
}

local function wrap_machine(machine, overrides)
    return setmetatable({ machine = machine, overrides = overrides, state = {}, snapshot_state = false }, machine_meta)
end

-- Call the original collector methods with the wrapper as self, so internal
-- calls pass through its overrides too. Collector state stays on the original.
local function wrap_computation_hash(claim, overrides)
    return setmetatable({}, {
        __index = function(_, name)
            local value = overrides[name]
            if value ~= nil then
                return value
            end
            return claim[name]
        end,
        __newindex = function(_, name, value)
            claim[name] = value
        end,
    })
end

local function begin_input(machine, input_index, input_base)
    if machine.state.input_index ~= input_index or machine.state.input_base ~= input_base then
        machine.state = { input_index = input_index, input_base = input_base }
    end
end

local function observe_input(claim, machine)
    return wrap_computation_hash(claim, {
        begin_input = function(self, input_index, input_base)
            begin_input(machine, input_index, input_base)
            return claim.begin_input(self, input_index, input_base)
        end,
    })
end

-- Wrap each execution before replay. The cache retains native checkpoints and owners,
-- while the strategy keeps its private state alongside the borrowed execution machine.
local function use_machine(geometry, inputs, cache, options, overrides)
    local clone = cache.clone_at_input_boundary
    cache.clone_at_input_boundary = function(self, input_index, replay)
        local wrapped
        local _, owner <close> = clone(self, input_index, function(machine, first, last)
            wrapped = wrap_machine(machine, overrides)
            return replay(wrapped, first, last)
        end)
        return wrapped, owner:move()
    end
    local consider, snapshot, commit, revert = cache.consider, cache.snapshot, cache.commit, cache.revert
    cache.consider = function(self, input_index, machine)
        return consider(self, input_index, machine.machine)
    end
    cache.snapshot = function(self, machine)
        snapshot(self, machine.machine)
        local state = {}
        for key, value in pairs(machine.state) do
            state[key] = value
        end
        machine.snapshot_state = state
    end
    cache.commit = function(self, machine)
        commit(self, machine.machine)
        machine.snapshot_state = false
    end
    cache.revert = function(self, machine)
        local state = assert(machine.snapshot_state, "no strategy snapshot to revert to")
        revert(self, machine.machine)
        machine.state, machine.snapshot_state = state, false
    end
    local make_mcycle = options.new_mcycle_computation_hash or prt.new_mcycle_computation_hash
    options.new_mcycle_computation_hash = function(log2_period, c, machine, bundle_index)
        return observe_input(make_mcycle(log2_period, c, machine, bundle_index), machine)
    end
    local make_uarch = options.new_uarch_computation_hash or prt.new_uarch_computation_hash
    options.new_uarch_computation_hash = function(log2_period, machine, epoch_period_index, bundle_index)
        return observe_input(make_uarch(log2_period, machine, epoch_period_index, bundle_index), machine)
    end
    local make_null = options.new_null_computation_hash or prt.new_null_computation_hash
    options.new_null_computation_hash = function(machine)
        return observe_input(make_null(machine), machine)
    end
    return prt.new_player(geometry, inputs, cache, options)
end

local function role_options(label, options)
    local result = {}
    for key, value in pairs(options or {}) do
        result[key] = value
    end
    result.label = label
    return result
end

-- Change only the caller's private input list. The referee still verifies input
-- inclusion against the original contract inputs.
local function new_forger(geometry, inputs, cache, input_index, forged_data, options)
    inputs[input_index + 1] = forged_data
    return prt.new_player(geometry, inputs, cache, role_options("forger", options))
end

-- A checkpoint exactly at the corruption point still holds the agreed state.
-- Corruption happens only when executing or collecting the transition out of it.
-- Each execution has private strategy state, which the cache restores on rollback.
local function new_tamperer(geometry, inputs, cache, input_index, bundle_offset, options)
    local offset = bundle_offset << (prt.LOG2_BUNDLE_MCYCLE_COUNT + geometry.log2_mcycles_per_period)
    local function tamper_point(machine)
        local context = machine.state
        if context.input_index ~= input_index or context.tampered then
            return nil
        end
        if math.ult(cartesi.MCYCLE_MAX - context.input_base, offset) then
            return nil
        end
        return context.input_base + offset
    end
    local function apply(machine)
        local point = tamper_point(machine)
        if
            point
            and machine:read_reg("mcycle") == point
            and machine:read_reg("iflags_Y") == 0
            and machine:read_reg("iflags_H") == 0
        then
            local ram_length = machine:get_initial_config().ram.length
            machine:write_memory(cartesi.AR_RAM_START + ram_length - 8, "CORRUPT!")
            machine.state.tampered = true
        end
    end
    local function collection_target(machine, target)
        apply(machine)
        local point = tamper_point(machine)
        if point and math.ult(machine:read_reg("mcycle"), point) and math.ult(point, target) then
            return point
        end
        return target
    end
    return use_machine(geometry, inputs, cache, role_options("tamperer", options), {
        run = function(machine, target)
            local point = tamper_point(machine)
            if point and math.ult(machine:read_reg("mcycle"), point) and math.ult(point, target) then
                local reason = machine.machine:run(point)
                if reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                    return reason
                end
            end
            if point and math.ult(point, target) then
                apply(machine)
            end
            return machine.machine:run(target)
        end,
        collect_mcycle_root_hashes = function(machine, target, ...)
            return machine.machine:collect_mcycle_root_hashes(collection_target(machine, target), ...)
        end,
        collect_uarch_cycle_root_hashes = function(machine, target, ...)
            return machine.machine:collect_uarch_cycle_root_hashes(collection_target(machine, target), ...)
        end,
        run_uarch = function(machine, ...)
            apply(machine)
            return machine.machine:run_uarch(...)
        end,
        log_step_uarch = function(machine, ...)
            apply(machine)
            return machine.machine:log_step_uarch(...)
        end,
    })
end

-- Private insertion helpers for the fabricated stream. Honest collectors use the forest API
-- directly. Only the affected group is split, preserving its neighbors' compressed trees.
local function pad_back(claim, value, count, height)
    hash_tree.frontier_forest_pad_back(claim.frontier, value, count, height)
    claim.next_leaf = claim.next_leaf + (count << height)
end

local function lie_about_leaf(leaf, fake_hash, unbundle)
    local function pad_back_lie(self, value, count, height)
        if count == 0 or leaf < self.next_leaf or leaf >= self.next_leaf + (count << height) then
            return pad_back(self, value, count, height)
        end
        local prefix = (leaf - self.next_leaf) >> height
        pad_back(self, value, prefix, height)
        if height == 0 then
            pad_back(self, fake_hash, 1, 0)
        elseif height == self.bundle_height then
            -- Unbundling uses the selected factory again, now with individual
            -- leaves. Its replacement is authenticated by the ordinary tree.
            local forest = unbundle(self, self.next_leaf, height)
            pad_back(self, hash_tree.frontier_forest_get_root_hash(forest), 1, height)
        else
            for i = 0, (1 << (height - self.bundle_height)) - 1 do
                pad_back_lie(
                    self,
                    hash_tree.frontier_forest_get_node(value, i << self.bundle_height, self.bundle_height),
                    1,
                    self.bundle_height
                )
            end
        end
        pad_back(self, value, count - prefix - 1, height)
    end
    return pad_back_lie
end

-- Collect the same execution samples as the honest run, then assemble the fabricated stream.
-- Final epoch padding needs its own override because a refinement at a fixed point may never run.
local function new_mcycle_liar(claim, insert)
    return wrap_computation_hash(claim, {
        run = function(self, mcycle_end)
            mcycle_end = umin(mcycle_end, self.input_mcycle_end)
            local collected = { mcycle_phase = self.mcycle_phase, partial_bundle = self.partial_bundle }
            repeat
                local chunk_end = usaturating_add(self.machine:read_reg("mcycle"), self.chunk_size, mcycle_end)
                collected = self.machine:collect_mcycle_root_hashes(
                    chunk_end,
                    self.log2_period,
                    collected.mcycle_phase,
                    self.bundle_height,
                    collected.partial_bundle
                )
                local count = math.min(#collected.hashes, self.input_entry_capacity - self.input_entry_count)
                for i = 1, count do
                    insert(self, collected.hashes[i], 1, self.bundle_height)
                end
                self.input_entry_count = self.input_entry_count + count
                if is_at_fixed_point(collected.break_reason) then
                    self.pad_bundle = assert(collected.hashes[#collected.hashes], "fixed point has no padding bundle")
                    insert(
                        self,
                        self.pad_bundle,
                        self.input_entry_capacity - self.input_entry_count,
                        self.bundle_height
                    )
                    self.input_entry_count = self.input_entry_capacity
                end
                prt.consider_mcycle_machine(self, collected)
            until not is_target_mcycle(collected.break_reason) or self.machine:read_reg("mcycle") == mcycle_end
            self.mcycle_phase, self.partial_bundle = collected.mcycle_phase, collected.partial_bundle
            return collected.break_reason
        end,
        end_epoch = function(self)
            self:end_input()
            local end_leaf = self.end_leaf
            if self.next_leaf < end_leaf then
                if not self.pad_bundle then
                    local collected = self.machine:collect_mcycle_root_hashes(
                        self.machine:read_reg("mcycle"),
                        self.log2_period,
                        0,
                        self.bundle_height
                    )
                    assert(is_at_fixed_point(collected.break_reason), "epoch ended outside a fixed point")
                    self.pad_bundle = assert(collected.hashes[#collected.hashes], "fixed point has no padding bundle")
                end
                insert(self, self.pad_bundle, (end_leaf - self.next_leaf) >> self.bundle_height, self.bundle_height)
            end
            return self.frontier
        end,
    })
end

-- The inherited end_input also calls this run for leaves reached only through padding.
local function new_uarch_liar(claim, insert)
    return wrap_computation_hash(claim, {
        run = function(self, mcycle_end)
            local machine = self.machine
            if math.ult(machine:read_reg("mcycle"), self.target_start) then
                local reason = machine:run(umin(mcycle_end, self.target_start))
                if not is_target_mcycle(reason) or math.ult(mcycle_end, self.target_start) then
                    return reason
                end
            end
            local reason
            local log2_cycles = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
            local capacity = 1 << log2_cycles
            repeat
                local target =
                    usaturating_add(machine:read_reg("mcycle"), self.chunk_size, umin(mcycle_end, self.target_end))
                local collected =
                    machine:collect_uarch_cycle_root_hashes(target, self.bundle_height, self.revert_uarch_tail)
                local offsets = collected.mcycle_hash_offsets
                local available = #offsets - 1
                if self.bundle_height == 0 then
                    if available > 0 then
                        local first, last = offsets[1], offsets[2] - 1
                        local real = last - first - 1
                        assert(real >= 0 and real <= capacity - 1, "too many uarch cycles in an instruction")
                        local start = self.first_leaf & (capacity - 1)
                        local stop = start + (1 << self.height)
                        for i = start, math.min(stop, real) - 1 do
                            insert(self, collected.hashes[first + i], 1, 0)
                        end
                        local halt_start, halt_end = math.max(start, real), math.min(stop, capacity - 1)
                        if halt_start < halt_end then
                            insert(self, collected.hashes[last - 1], halt_end - halt_start, 0)
                        end
                        if stop == capacity then
                            insert(self, collected.hashes[last], 1, 0)
                        end
                    end
                else
                    local wanted = math.min(available, (self.end_leaf - self.next_leaf) >> log2_cycles)
                    local group
                    for i = 1, wanted do
                        group = hash_tree.frontier_forest(log2_cycles, "keccak256")
                        prt.uarch_computation_hash_push_mcycle(
                            self,
                            group,
                            collected.hashes,
                            offsets[i],
                            offsets[i + 1] - 1
                        )
                        insert(self, group, 1, log2_cycles)
                    end
                    if is_at_fixed_point(collected.break_reason) and self.next_leaf < self.end_leaf then
                        assert(group, "fixed-point collection has no padding period")
                        insert(self, group, (self.end_leaf - self.next_leaf) >> log2_cycles, log2_cycles)
                    end
                end
                reason = collected.break_reason
            until not is_target_mcycle(reason)
                or self.next_leaf == self.end_leaf
                or machine:read_reg("mcycle") == mcycle_end
            return reason
        end,
    })
end

local function new_fabulist(geometry, inputs, cache, input_index, leaf_offset, options)
    options = role_options("fabulist", options)
    local player
    local target_epoch_period_index = input_index * geometry.periods_per_input + leaf_offset
    local fake_hash = keccak("fabulist")
    local make_mcycle = options.new_mcycle_computation_hash or prt.new_mcycle_computation_hash
    options.new_mcycle_computation_hash = function(log2_period, c, machine, bundle_index)
        local claim = make_mcycle(log2_period, c, machine, bundle_index)
        return new_mcycle_liar(
            claim,
            lie_about_leaf(target_epoch_period_index, fake_hash, function(_, first_leaf)
                return player:refine_mcycle_claim(first_leaf >> prt.LOG2_BUNDLE_MCYCLE_COUNT)
            end)
        )
    end
    local make_uarch = options.new_uarch_computation_hash or prt.new_uarch_computation_hash
    options.new_uarch_computation_hash = function(log2_period, machine, epoch_period_index, bundle_index)
        local claim = make_uarch(log2_period, machine, epoch_period_index, bundle_index)
        if epoch_period_index == target_epoch_period_index then
            return new_uarch_liar(
                claim,
                lie_about_leaf((1 << geometry.uarch_height) - 1, fake_hash, function(_, first_leaf)
                    return player:refine_uarch_claim(
                        input_index + 1,
                        leaf_offset,
                        first_leaf >> prt.LOG2_BUNDLE_UARCH_CYCLE_COUNT
                    )
                end)
            )
        end
        return claim
    end
    player = prt.new_player(geometry, inputs, cache, options)
    return player
end

-- The quitter never executes the guest. Its machine stays at the initial yield,
-- its collector substitutes a made-up state at every position, and it disconnects
-- after posting that claim. The disconnect is its only protocol-level deviation.
local function new_quitter(geometry, inputs, cache, options)
    options = role_options("quitter", options)
    local make = options.new_mcycle_computation_hash or prt.new_mcycle_computation_hash
    options.new_mcycle_computation_hash = function(log2_period, c, machine, bundle_index)
        local claim = make(log2_period, c, machine, bundle_index)
        claim.cache_machine = false
        return new_mcycle_liar(claim, function(collector, _, count, height)
            local fake_hash = keccak(options.seed or "quitter")
            for _ = 1, height do
                fake_hash = keccak(fake_hash, fake_hash)
            end
            return pad_back(collector, fake_hash, count, height)
        end)
    end
    local player = use_machine(geometry, inputs, cache, options, { send_cmio_response = function() end })
    local commit = player.commit_mcycle_claim
    player.commit_mcycle_claim = function(self)
        self.done = true
        return commit(self)
    end
    return player
end

if ... == "prt-dishonest" then
    return {
        new_forger = new_forger,
        new_tamperer = new_tamperer,
        new_fabulist = new_fabulist,
        new_quitter = new_quitter,
    }
end

-- The dishonest demonstration roles have their own entry point.
-- prt-dishonest.lua <role> <address> <initial-state-hash> [role arguments] <inputs...>
local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
assert(#initial_state_hash == 32, "invalid initial state hash")
local next_argument = 4
local function take_argument(message)
    local value = assert(arg[next_argument], message)
    next_argument = next_argument + 1
    return value
end
local make_player
if role == "quitter" then
    local seed = arg[next_argument] and arg[next_argument]:match("^%-%-seed=(.+)$")
    if seed then
        next_argument = next_argument + 1
    end
    make_player = function(geometry, inputs, cache)
        return new_quitter(geometry, inputs, cache, { seed = seed })
    end
elseif role == "forger" then
    local index = assert(tonumber(take_argument("missing forged input index")), "invalid forged input index")
    local data = util.read_file(take_argument("missing forged input file"))
    make_player = function(geometry, inputs, cache)
        return new_forger(geometry, inputs, cache, index, data)
    end
elseif role == "tamperer" or role == "fabulist" then
    local input_index = assert(tonumber(take_argument("missing input index")), "invalid input index")
    local offset = assert(tonumber(take_argument("missing offset")), "invalid offset")
    local make = role == "tamperer" and new_tamperer or new_fabulist
    make_player = function(geometry, inputs, cache)
        return make(geometry, inputs, cache, input_index, offset)
    end
else
    error("unknown role: " .. role)
end
local inputs = {}
for i = next_argument, #arg do
    inputs[#inputs + 1] = util.read_file(arg[i])
end
local cache <close> = prt.new_machine_cache(prt.new_machine(initial_state_hash))
local player = make_player(prt.new_geometry(10), inputs, cache)
prtu.run_client(player, server_address)
