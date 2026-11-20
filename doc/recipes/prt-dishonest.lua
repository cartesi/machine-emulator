-- Dishonest players use the same driver, claims, and protocol handlers as the honest
-- player. Their private inputs, machines, or computation hashes tell a different history.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local fs = require("cartesi.filesystem")
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
        local machine <close> = self.machine -- luacheck: ignore 211
    end,
    __index = function(self, name)
        return machine_methods[name] or self.overrides[name] or util.forward_method(self, self.machine, name)
    end,
}

local function wrap_machine(machine, overrides, state)
    return setmetatable({ machine = machine, overrides = overrides, state = state or {} }, machine_meta)
end

function machine_methods:fork_server()
    local state = {}
    for name, value in pairs(self.state) do
        state[name] = value
    end
    return wrap_machine(assert(self.machine:fork_server()), self.overrides, state)
end

function machine_methods:swap(other)
    self.machine:swap(other.machine)
    self.state, other.state = other.state, self.state
end

-- Call the original builder methods with the wrapper as self, so internal
-- calls pass through its overrides too. Builder state stays on the original.
local function wrap_computation_hash(builder, overrides)
    return setmetatable({}, {
        __index = function(_, name)
            local value = overrides[name]
            if value ~= nil then
                return value
            end
            return builder[name]
        end,
        __newindex = function(_, name, value)
            builder[name] = value
        end,
    })
end

local function clone_handlers(player)
    local handlers = {}
    for name, handler in pairs(player.event_handler) do
        handlers[name] = handler
    end
    player.event_handler = handlers
end

local function begin_input(machine, epoch_input_offset, input_mcycle_base)
    if
        machine.state.epoch_input_offset ~= epoch_input_offset
        or machine.state.input_mcycle_base ~= input_mcycle_base
    then
        machine.state = { epoch_input_offset = epoch_input_offset, input_mcycle_base = input_mcycle_base }
    end
end

local function observe_input(builder)
    return wrap_computation_hash(builder, {
        begin_input = function(self, machine, epoch_input_offset, input_mcycle_base)
            begin_input(machine, epoch_input_offset, input_mcycle_base)
            return builder.begin_input(self, machine, epoch_input_offset, input_mcycle_base)
        end,
    })
end

-- Wrap the existing epoch pair and initial entry before any input executes.
-- Forks and rollback preserve strategy state through the machine wrapper itself.
local function use_machine(player, overrides)
    player.epoch_pair.machine = wrap_machine(player.epoch_pair.machine, overrides)
    for _, entry in ipairs(player.machine_cache.entries) do
        entry.machine = wrap_machine(entry.machine, overrides)
    end
    player.epoch_builder = observe_input(player.epoch_builder)
    local new_mcycle = player.new_mcycle_computation_hash_builder
    function player:new_mcycle_computation_hash_builder()
        return observe_input(new_mcycle(self))
    end
    local new_uarch = player.new_uarch_cycle_computation_hash_builder
    function player:new_uarch_cycle_computation_hash_builder(epoch_period_offset)
        return observe_input(new_uarch(self, epoch_period_offset))
    end
    local new_null = player.new_null_computation_hash_builder
    function player:new_null_computation_hash_builder()
        return observe_input(new_null(self))
    end
    return player
end

-- Substitute an input filename as it arrives. Replay reads the forged file, while the
-- referee still verifies input inclusion against the original contract inputs.
local function new_forger(
    dapp_contract,
    epoch_input_offset,
    forged_path,
    label,
    previous_outputs_frontier,
    anomaly_handler
)
    local player = prt.new_forked_player(dapp_contract, label or "forger", previous_outputs_frontier, anomaly_handler)
    clone_handlers(player)
    local input_added = player.event_handler.input_added
    player.event_handler.input_added = function(self, index, path)
        input_added(self, index, index == epoch_input_offset and forged_path or path)
    end
    return player
end

local NOTICE = "Notice(bytes payload)"

-- Replaces the notice the machine is emitting, and its length in htif.tohost, with a notice
-- that holds the forged answer.
local function forge_notice(machine, answer)
    local notice = evmu.encode_calldata(NOTICE, { payload = evmu.raw(answer) })
    machine:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, notice)
    local tohost = machine:read_reg("htif_tohost")
    machine:write_reg("htif_tohost", (tohost & ~cartesi.HTIF_DATA_MASK) | (#notice << cartesi.HTIF_DATA_SHIFT))
end

-- A player whose outputs differ from those the guest hashed cannot match its outputs Merkle root or
-- prove its outputs. It reports neither.
local OUTPUT_ANOMALIES = { outputs_merkle_root_mismatch = true, unprovable_output = true }
local function ignore_output_anomalies(player)
    local report_anomaly = player.report_anomaly
    function player:report_anomaly(anomaly, ...)
        if not OUTPUT_ANOMALIES[anomaly] then
            return report_anomaly(self, anomaly, ...)
        end
    end
    return player
end

-- Converts the raw hashes of one mcycle (one per uarch cycle up to the halt, then the reset) to the
-- format the native uarch collector returns for the given bundle height.
local function bundle_uarch_cycles(hashes, bundle_height)
    local count = #hashes
    if bundle_height == 0 then
        return hashes
    end
    assert(bundle_height == prt.LOG2_BUNDLE_UARCH_CYCLE_COUNT, "unsupported uarch bundle height")
    local halt = hash_tree.frontier_forest(bundle_height, "keccak256")
    hash_tree.frontier_forest_pad_back(halt, hashes[count - 1])
    local bundle = hash_tree.frontier_forest(bundle_height, "keccak256")
    hash_tree.frontier_forest_append(bundle, hashes, 1, count - 1)
    hash_tree.frontier_forest_pad_back(bundle, hashes[count - 1], (1 << bundle_height) - (count - 1))
    hash_tree.frontier_forest_push_back(bundle, hashes[count])
    return { hash_tree.frontier_forest_get_root_hash(halt), hash_tree.frontier_forest_get_root_hash(bundle) }
end

-- Runs the current instruction one uarch cycle at a time up to the halt, then resets the uarch,
-- calling after_reset before hashing the reset state. Returns the raw hashes.
local function collect_instruction_uarch_cycles(machine, after_reset)
    local hashes = {}
    repeat
        machine:run_uarch(machine:read_reg("uarch_cycle") + 1)
        hashes[#hashes + 1] = machine:get_root_hash()
    until machine:read_reg("uarch_halt") ~= 0
    machine:reset_uarch()
    if after_reset then
        after_reset(machine)
    end
    hashes[#hashes + 1] = machine:get_root_hash()
    return hashes
end

-- Forges the notice right after the uarch step at the given uarch cycle of the notice instruction.
-- Finishing that instruction reaches the same state as running it on the main processor and
-- forging after it, so runs and mcycle collections forge when the instruction completes.
-- Each execution has private strategy state, which its snapshot restores on rollback.
local function new_tamperer(
    dapp_contract,
    epoch_input_offset,
    input_mcycle_offset,
    uarch_cycle,
    answer,
    label,
    previous_outputs_frontier,
    anomaly_handler
)
    local geometry = dapp_contract.geometry
    assert((input_mcycle_offset + 1) % geometry.mcycles_per_period ~= 0, "the forged state falls on a sample")
    -- The mcycle of the notice instruction, until the notice is forged
    local function get_notice_mcycle(machine)
        local context = machine.state
        if context.epoch_input_offset ~= epoch_input_offset or context.tampered then
            return nil
        end
        if math.ult(cartesi.MCYCLE_MAX - context.input_mcycle_base, input_mcycle_offset + 1) then
            return nil
        end
        return context.input_mcycle_base + input_mcycle_offset
    end
    local function forge(machine)
        forge_notice(machine.machine, answer)
        machine.state.tampered = true
    end
    -- Forges once the main processor has completed the notice instruction
    local function forge_after_notice(machine)
        local notice_mcycle = get_notice_mcycle(machine)
        if notice_mcycle and machine:read_reg("mcycle") == notice_mcycle + 1 then
            forge(machine)
        end
    end
    -- Stops a run of the main processor where it completes the notice instruction
    local function get_stop(machine, target)
        forge_after_notice(machine)
        local notice_mcycle = get_notice_mcycle(machine)
        if notice_mcycle and math.ult(machine:read_reg("mcycle"), notice_mcycle + 1) then
            if math.ult(notice_mcycle + 1, target) then
                return notice_mcycle + 1
            end
        end
        return target
    end
    local player = prt.new_forked_player(dapp_contract, label or "tamperer", previous_outputs_frontier, anomaly_handler)
    ignore_output_anomalies(player)
    return use_machine(player, {
        run = function(machine, target)
            local stop = get_stop(machine, target)
            local break_reason = machine.machine:run(stop)
            forge_after_notice(machine)
            if stop ~= target and is_target_mcycle(break_reason) then
                return machine.machine:run(target)
            end
            return break_reason
        end,
        collect_mcycle_root_hashes = function(machine, target, ...)
            local stop = get_stop(machine, target)
            local collected = machine.machine:collect_mcycle_root_hashes(stop, ...)
            forge_after_notice(machine)
            -- The strategy stopped early to forge; the caller's target is still pending.
            if stop ~= target and is_target_mcycle(collected.break_reason) then
                collected.break_reason = cartesi.BREAK_REASON_YIELDED_SOFTLY
            end
            return collected
        end,
        collect_mcycle_bundle = function(machine, bundle_offset, log2_period, height)
            if not get_notice_mcycle(machine) then
                return machine.machine:collect_mcycle_bundle(bundle_offset, log2_period, height)
            end
            -- Run to the bundle and sample it through the strategy, which forges on the way.
            local span = 1 << (log2_period + height)
            local bundle_begin = usaturating_add(machine:read_reg("mcycle"), bundle_offset * span)
            local break_reason
            repeat
                break_reason = machine:run(bundle_begin)
            until is_target_mcycle(break_reason) or is_at_fixed_point(break_reason)
            local hashes, collected = {}, { mcycle_phase = 0 }
            repeat
                collected = machine:collect_mcycle_root_hashes(
                    usaturating_add(bundle_begin, span),
                    log2_period,
                    collected.mcycle_phase,
                    0
                )
                table.move(collected.hashes, 1, #collected.hashes, #hashes + 1, hashes)
            until is_at_fixed_point(collected.break_reason) or #hashes >= (1 << height)
            -- A fixed point repeats its state hash at every later sample.
            for i = #hashes + 1, 1 << height do
                hashes[i] = hashes[i - 1]
            end
            return hashes
        end,
        collect_uarch_cycle_root_hashes = function(machine, target, bundle_height, ...)
            local notice_mcycle = get_notice_mcycle(machine)
            local mcycle = machine:read_reg("mcycle")
            if not notice_mcycle or not math.ult(mcycle, target) or math.ult(notice_mcycle, mcycle) then
                return machine.machine:collect_uarch_cycle_root_hashes(target, bundle_height, ...)
            end
            if mcycle ~= notice_mcycle then
                local collected =
                    machine.machine:collect_uarch_cycle_root_hashes(umin(target, notice_mcycle), bundle_height, ...)
                -- The strategy stopped early to forge; the caller's target is still pending.
                if math.ult(notice_mcycle, target) and is_target_mcycle(collected.break_reason) then
                    collected.break_reason = cartesi.BREAK_REASON_YIELDED_SOFTLY
                end
                return collected
            end
            -- The uarch steps of the instruction go through run_uarch, which forges. An instruction that
            -- halts before the given uarch cycle is forged after the reset, as a main processor run does.
            local hashes =
                bundle_uarch_cycles(collect_instruction_uarch_cycles(machine, forge_after_notice), bundle_height)
            local break_reason = cartesi.BREAK_REASON_YIELDED_SOFTLY
            if machine:read_reg("iflags_X") ~= 0 then
                break_reason = cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
            elseif notice_mcycle + 1 == target then
                break_reason = cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
            end
            return { hashes = hashes, mcycle_hash_offsets = { 1, #hashes + 1 }, break_reason = break_reason }
        end,
        run_uarch = function(machine, uarch_cycle_end)
            local notice_mcycle = get_notice_mcycle(machine)
            if
                notice_mcycle
                and machine:read_reg("mcycle") == notice_mcycle
                and machine:read_reg("uarch_cycle") <= uarch_cycle
                and math.ult(uarch_cycle, uarch_cycle_end)
            then
                machine.machine:run_uarch(uarch_cycle + 1)
                forge(machine)
            end
            return machine.machine:run_uarch(uarch_cycle_end)
        end,
    })
end

local function is_rejected(machine)
    return machine:read_reg("iflags_Y") ~= 0
        and machine:read_reg("htif_tohost_dev") == cartesi.HTIF_DEV_YIELD
        and machine:read_reg("htif_tohost_cmd") == cartesi.HTIF_YIELD_CMD_MANUAL
        and machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
end

-- Rewrites the reason of a manual yield to accept the input.
local function accept_input(machine)
    local tohost = machine:read_reg("htif_tohost")
    machine:write_reg(
        "htif_tohost",
        (tohost & ~cartesi.HTIF_REASON_MASK)
            | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED << cartesi.HTIF_REASON_SHIFT)
    )
end

-- Replaces the leaves of a bundle, from the given one on, with one hash.
local function replace_leaves_from(forest, height, first, hash)
    local replacement = hash_tree.frontier_forest(height, "keccak256")
    for i = 0, first - 1 do
        hash_tree.frontier_forest_push_back(replacement, hash_tree.frontier_forest_get_node_hash(forest, i, 0))
    end
    hash_tree.frontier_forest_pad_back(replacement, hash)
    return replacement
end

-- Keeps the state a rejected input left, as the no-rollback player of vg-dishonest.lua ignores the
-- rollback. The machine defines a rejected input as reverted, so the player rewrites each rejecting
-- yield to accept the input. A collector that reached the yield already used the reverted state,
-- so the player rebuilds those hashes from the accepted state.
local function new_no_rollback(dapp_contract, label, previous_outputs_frontier, anomaly_handler)
    local log2_period = dapp_contract.geometry.log2_mcycles_per_period
    local player =
        prt.new_forked_player(dapp_contract, label or "no-rollback", previous_outputs_frontier, anomaly_handler)
    ignore_output_anomalies(player)
    -- The mcycle offset of the rejecting yield instruction and the accepted state hash, by input
    local rejections = {}
    local function accept_rejection(machine)
        if not is_rejected(machine) then
            return nil
        end
        accept_input(machine.machine)
        local context = machine.state
        local rejection = rejections[context.epoch_input_offset]
        if not rejection then
            rejection = {
                mcycle_offset = machine:read_reg("mcycle") - context.input_mcycle_base - 1,
                state_hash = machine:get_root_hash(),
            }
            rejections[context.epoch_input_offset] = rejection
        end
        return rejection
    end
    -- The first leaf of a rejected input that repeats its final state
    local function get_fixed_point_leaf(rejection)
        return (rejection.mcycle_offset + 1) >> log2_period
    end
    local collect_mcycle_bundle = player.collect_mcycle_bundle
    function player:collect_mcycle_bundle(epoch_input_offset, input_bundle_offset)
        local forest = collect_mcycle_bundle(self, epoch_input_offset, input_bundle_offset)
        local rejection = rejections[epoch_input_offset]
        if not rejection then
            return forest
        end
        local first = get_fixed_point_leaf(rejection) - (input_bundle_offset << prt.LOG2_BUNDLE_MCYCLE_COUNT)
        if first >= 1 << prt.LOG2_BUNDLE_MCYCLE_COUNT then
            return forest
        end
        return replace_leaves_from(forest, prt.LOG2_BUNDLE_MCYCLE_COUNT, math.max(first, 0), rejection.state_hash)
    end
    return use_machine(player, {
        run = function(machine, target)
            local break_reason = machine.machine:run(target)
            accept_rejection(machine)
            return break_reason
        end,
        collect_mcycle_root_hashes = function(machine, target, log2_mcycle_period, mcycle_phase, height, ...)
            local collected =
                machine.machine:collect_mcycle_root_hashes(target, log2_mcycle_period, mcycle_phase, height, ...)
            local rejection = accept_rejection(machine)
            if not rejection then
                return collected
            end
            local hashes = collected.hashes
            local count = #hashes
            if height == 0 then
                hashes[count] = rejection.state_hash
                return collected
            end
            assert(height == prt.LOG2_BUNDLE_MCYCLE_COUNT, "unsupported mcycle bundle height")
            local pad = hash_tree.frontier_forest(height, "keccak256")
            hash_tree.frontier_forest_pad_back(pad, rejection.state_hash)
            hashes[count] = hash_tree.frontier_forest_get_root_hash(pad)
            if collected.final_bundle_sibling_hashes then
                local bundle = player:collect_mcycle_bundle(
                    machine.state.epoch_input_offset,
                    get_fixed_point_leaf(rejection) >> height
                )
                hashes[count - 1] = hash_tree.frontier_forest_get_root_hash(bundle)
                collected.final_bundle_sibling_hashes =
                    hash_tree.frontier_forest_get_siblings(bundle, (1 << height) - 1, 0)
            end
            return collected
        end,
        collect_uarch_cycle_root_hashes = function(machine, target, bundle_height, revert_uarch_tail)
            local context = machine.state
            local rejection = rejections[context.epoch_input_offset]
            local yield_mcycle = rejection and context.input_mcycle_base + rejection.mcycle_offset
            local mcycle = machine:read_reg("mcycle")
            if not yield_mcycle or not math.ult(mcycle, target) or math.ult(yield_mcycle, mcycle) then
                return machine.machine:collect_uarch_cycle_root_hashes(target, bundle_height, revert_uarch_tail)
            end
            if mcycle ~= yield_mcycle then
                local collected = machine.machine:collect_uarch_cycle_root_hashes(
                    umin(target, yield_mcycle),
                    bundle_height,
                    revert_uarch_tail
                )
                -- The strategy stopped early at the yield; the caller's target is still pending.
                if math.ult(yield_mcycle, target) and is_target_mcycle(collected.break_reason) then
                    collected.break_reason = cartesi.BREAK_REASON_YIELDED_SOFTLY
                end
                return collected
            end
            -- The reset of the yield instruction reaches the accepted state, which repeats afterwards
            local hashes =
                bundle_uarch_cycles(collect_instruction_uarch_cycles(machine, accept_rejection), bundle_height)
            local tail = bundle_uarch_cycles(
                machine.machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0).hashes,
                bundle_height
            )
            local count = #hashes
            table.move(tail, 1, #tail, count + 1, hashes)
            return {
                hashes = hashes,
                mcycle_hash_offsets = { 1, count + 1, #hashes + 1 },
                break_reason = cartesi.BREAK_REASON_YIELDED_MANUALLY,
            }
        end,
    })
end

-- Private insertion helpers for the fabricated stream. Honest builders use the forest API
-- directly. Only the affected group is split, preserving its neighbors' compressed trees.
local function lie_about_leaf(leaf, unbundle)
    local function pad_back_lie(self, value, count, height)
        local next_leaf = hash_tree.frontier_forest_get_leaf_count(self.frontier)
        count = count or (((1 << self.frontier.height) - next_leaf) >> height)
        if count == 0 or leaf < next_leaf or leaf >= next_leaf + (count << height) then
            return hash_tree.frontier_forest_pad_back(self.frontier, value, count, height)
        end
        local prefix = (leaf - next_leaf) >> height
        hash_tree.frontier_forest_pad_back(self.frontier, value, prefix, height)
        if height == self.bundle_height then
            -- The selected bundle factory reconstructs the fabricated leaves.
            -- Its replacement is authenticated by the ordinary tree.
            local forest = unbundle(self, hash_tree.frontier_forest_get_leaf_count(self.frontier), height)
            hash_tree.frontier_forest_pad_back(
                self.frontier,
                hash_tree.frontier_forest_get_root_hash(forest),
                1,
                height
            )
        else
            for i = 0, (1 << (height - self.bundle_height)) - 1 do
                pad_back_lie(
                    self,
                    hash_tree.frontier_forest_get_node_hash(value, i << self.bundle_height, self.bundle_height),
                    1,
                    self.bundle_height
                )
            end
        end
        hash_tree.frontier_forest_pad_back(self.frontier, value, count - prefix - 1, height)
    end
    return pad_back_lie
end

-- Collect the same execution samples as the honest run, then assemble the fabricated stream.
-- Final epoch padding needs its own override because an empty epoch never runs an input.
local function new_mcycle_liar(builder, insert)
    return wrap_computation_hash(builder, {
        run = function(self, machine, mcycle_end)
            local collected = { mcycle_phase = self.mcycle_phase, partial_bundle = self.partial_bundle }
            repeat
                local collection_end =
                    usaturating_add(machine:read_reg("mcycle"), self.collection_chunk_size, mcycle_end)
                collected = machine:collect_mcycle_root_hashes(
                    collection_end,
                    self.log2_period,
                    collected.mcycle_phase,
                    self.bundle_height,
                    collected.partial_bundle
                )
                local count = #collected.hashes
                if is_at_fixed_point(collected.break_reason) then
                    self.pad_bundle = collected.hashes[count]
                    count = count - 1
                end
                assert(
                    count <= self.max_bundles_per_input - self.input_bundle_count,
                    "mcycle collection exceeds the input's bundle capacity"
                )
                for i = 1, count do
                    insert(self, collected.hashes[i], 1, self.bundle_height)
                end
                self.input_bundle_count = self.input_bundle_count + count
                if is_at_fixed_point(collected.break_reason) then
                    insert(
                        self,
                        self.pad_bundle,
                        self.max_bundles_per_input - self.input_bundle_count,
                        self.bundle_height
                    )
                    self.input_bundle_count = self.max_bundles_per_input
                end
            until not is_target_mcycle(collected.break_reason) or machine:read_reg("mcycle") == mcycle_end
            self.mcycle_phase, self.partial_bundle = collected.mcycle_phase, collected.partial_bundle
            return collected.break_reason
        end,
        end_epoch = function(self)
            assert(self.input_bundle_count == 0, "mcycle computation hash input was not closed")
            insert(self, self.pad_bundle, nil, self.bundle_height)
            return self.frontier
        end,
    })
end

-- Reuse the honest run and input lifecycle, replacing only how collected groups are inserted.
local function new_uarch_liar(builder, insert)
    local log2_cycles = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local function push_mcycles(self, collected)
        local offsets = collected.mcycle_hash_offsets
        local available = #offsets - 1
        local remaining = self.mcycles_per_period - self.mcycle_count
        local count = available
        local at_fixed_point = is_at_fixed_point(collected.break_reason)
        if at_fixed_point then
            count = count - 1
        end
        assert(count <= remaining, "uarch collection exceeds the claim's mcycle capacity")
        for i = 1, count do
            local group = hash_tree.frontier_forest(log2_cycles, "keccak256")
            prt.uarch_computation_hash_push_mcycle(self, group, collected.hashes, offsets[i], offsets[i + 1])
            insert(self, group, 1, log2_cycles)
        end
        self.mcycle_count = self.mcycle_count + count
        if at_fixed_point and self.mcycle_count < self.mcycles_per_period then
            local pad_frontier = hash_tree.frontier_forest(log2_cycles, "keccak256")
            prt.uarch_computation_hash_push_mcycle(
                self,
                pad_frontier,
                collected.hashes,
                offsets[available],
                offsets[available + 1]
            )
            insert(self, pad_frontier, remaining - count, log2_cycles)
            self.mcycle_count = self.mcycles_per_period
        end
    end
    return wrap_computation_hash(builder, {
        push_collected = push_mcycles,
    })
end

-- Replace one leaf in a collected bundle, retaining compression of repeated hashes.
-- The ordinary hash tree still authenticates this fabricated forest against its bundle root.
local function falsify_bundle(forest, height, leaf, fake_hash)
    local leaf_count = 1 << height
    if leaf < 0 or leaf >= leaf_count then
        return forest
    end
    local replacement = hash_tree.frontier_forest(height, "keccak256")
    local previous, count = nil, 0
    for i = 0, leaf_count - 1 do
        local hash = i == leaf and fake_hash or hash_tree.frontier_forest_get_node_hash(forest, i, 0)
        if hash ~= previous then
            hash_tree.frontier_forest_pad_back(replacement, previous, count)
            previous, count = hash, 0
        end
        count = count + 1
    end
    hash_tree.frontier_forest_pad_back(replacement, previous, count)
    return replacement
end

-- Posts the honest mcycle claim, as the fabulist of vg-dishonest.lua copies the honest final state
-- hash. In each uarch tournament of that claim, it posts a uarch claim that follows the forger's
-- computation, except for its last leaf, the honest state hash the period ends at.
local function new_fabulist(
    dapp_contract,
    forged_epoch_input_offset,
    forged_path,
    label,
    previous_outputs_frontier,
    anomaly_handler
)
    local geometry = dapp_contract.geometry
    local player = prt.new_forked_player(dapp_contract, label or "fabulist", previous_outputs_frontier, anomaly_handler)
    local forging = false
    local read_input = player.read_input
    function player:read_input(epoch_input_offset)
        if forging and epoch_input_offset == forged_epoch_input_offset then
            return fs.read_file(forged_path)
        end
        return read_input(self, epoch_input_offset)
    end
    -- Calls f with the forged input in place of the posted one
    local function forge(f, ...)
        local previous = forging
        forging = true
        local results = table.pack(pcall(f, ...))
        forging = previous
        assert(results[1], results[2])
        return table.unpack(results, 2, results.n)
    end
    -- The honest state hash each disputed period ends at, by epoch period offset
    local honest_leaves = {}
    local function get_honest_leaf(epoch_input_offset, input_period_offset)
        local epoch_period_offset =
            prt.combine_epoch_period_offset(geometry.periods_per_input, epoch_input_offset, input_period_offset)
        local hash = honest_leaves[epoch_period_offset]
        if not hash then
            assert(not forging, "the honest state hash must be read before forging")
            hash = player:new_mcycle_tree():get_node_hash(player, epoch_period_offset, 0)
            honest_leaves[epoch_period_offset] = hash
        end
        return hash
    end
    local last_leaf = (1 << geometry.uarch_height) - 1
    local new_uarch = player.new_uarch_cycle_computation_hash_builder
    function player:new_uarch_cycle_computation_hash_builder(epoch_period_offset)
        local epoch_input_offset, input_period_offset =
            prt.split_epoch_period_offset(geometry.periods_per_input, epoch_period_offset)
        return new_uarch_liar(
            new_uarch(self, epoch_period_offset),
            lie_about_leaf(last_leaf, function(_, first_leaf)
                return player:collect_uarch_cycle_bundle(
                    epoch_input_offset,
                    input_period_offset,
                    first_leaf >> prt.LOG2_BUNDLE_UARCH_CYCLE_COUNT
                )
            end)
        )
    end
    local new_uarch_tree = player.new_uarch_tree
    function player:new_uarch_tree(epoch_input_offset, input_period_offset, forest)
        get_honest_leaf(epoch_input_offset, input_period_offset)
        return forge(new_uarch_tree, self, epoch_input_offset, input_period_offset, forest)
    end
    local collect_uarch_cycle_bundle = player.collect_uarch_cycle_bundle
    function player:collect_uarch_cycle_bundle(epoch_input_offset, input_period_offset, period_mcycle_offset)
        local honest_leaf = get_honest_leaf(epoch_input_offset, input_period_offset)
        local forest =
            forge(collect_uarch_cycle_bundle, self, epoch_input_offset, input_period_offset, period_mcycle_offset)
        local leaf = last_leaf - (period_mcycle_offset << prt.LOG2_BUNDLE_UARCH_CYCLE_COUNT)
        return falsify_bundle(forest, prt.LOG2_BUNDLE_UARCH_CYCLE_COUNT, leaf, honest_leaf)
    end
    return player
end

-- The vandal never executes the guest. Its machine stays at the initial yield,
-- its builder substitutes a made-up state at every position, and it disconnects
-- after posting that claim. The disconnect is its only protocol-level deviation. The made-up
-- state derives from the label, so vandals with different labels post different claims.
local function leave()
    return "done"
end

-- Having posted its claim, the player leaves at the next event.
local function leave_after_claim(player)
    clone_handlers(player)
    local commit = player.event_handler.commit_mcycle_claim
    player.event_handler.commit_mcycle_claim = function(self)
        local claim = commit(self)
        self.event_handler = setmetatable({}, {
            __index = function()
                return leave
            end,
        })
        return claim
    end
    return player
end

local function new_vandal(dapp_contract, label, previous_outputs_frontier, anomaly_handler)
    label = label or "vandal"
    local player = prt.new_forked_player(dapp_contract, label, previous_outputs_frontier, anomaly_handler)
    use_machine(player, { send_cmio_response = function() end })
    local function insert(liar, _, count, height)
        local fake_hash = keccak(label)
        for _ = 1, height do
            fake_hash = keccak(fake_hash, fake_hash)
        end
        return hash_tree.frontier_forest_pad_back(liar.frontier, fake_hash, count, height)
    end
    player.epoch_builder = new_mcycle_liar(player.epoch_builder, insert)
    local new_mcycle = player.new_mcycle_computation_hash_builder
    function player:new_mcycle_computation_hash_builder()
        return new_mcycle_liar(new_mcycle(self), insert)
    end
    player.collect_mcycle_bundle = function()
        local forest = hash_tree.frontier_forest(prt.LOG2_BUNDLE_MCYCLE_COUNT, "keccak256")
        hash_tree.frontier_forest_pad_back(forest, keccak(label), 1 << prt.LOG2_BUNDLE_MCYCLE_COUNT)
        return forest
    end
    return leave_after_claim(player)
end

-- Computes and claims honestly, then leaves, as the idle player of vg-dishonest.lua lets its
-- defense time out. Its claim is the honest claim, which others defend.
local function new_idle(dapp_contract, label, previous_outputs_frontier, anomaly_handler)
    return leave_after_claim(
        prt.new_forked_player(dapp_contract, label or "idle", previous_outputs_frontier, anomaly_handler)
    )
end

if ... == "prt-dishonest" then
    return {
        new_forger = new_forger,
        new_tamperer = new_tamperer,
        new_fabulist = new_fabulist,
        new_vandal = new_vandal,
        new_idle = new_idle,
        new_no_rollback = new_no_rollback,
    }
end

-- The dishonest demonstration roles have their own entry point. A player's label names it in
-- the story and defaults to its role.
-- prt-dishonest.lua <role> <address> <initial-state-hash> [role arguments] [<label>]
--   forger and fabulist take <input-index> <private-file>, tamperer takes <input-index> <mcycle-offset>
--   <uarch-cycle> <answer>, and vandal, idle, and no-rollback take none, as in vg-dishonest.lua
local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
assert(#initial_state_hash == 32, "invalid initial state hash")
local next_argument = 4
-- Takes the next argument. It is required when a message says what is missing.
local function take_argument(message)
    local value = arg[next_argument]
    assert(value or not message, message)
    next_argument = next_argument + 1
    return value
end
local new_player
if role == "vandal" then
    new_player = new_vandal
elseif role == "idle" then
    new_player = new_idle
elseif role == "no-rollback" then
    new_player = new_no_rollback
elseif role == "forger" or role == "fabulist" then
    local index =
        assert(tonumber(take_argument("missing forged epoch input offset")), "invalid forged epoch input offset")
    local path = take_argument("missing forged input file")
    local new = role == "forger" and new_forger or new_fabulist
    new_player = function(dapp_contract, label)
        return new(dapp_contract, index, path, label)
    end
elseif role == "tamperer" then
    local epoch_input_offset =
        assert(tonumber(take_argument("missing epoch input offset")), "invalid epoch input offset")
    local mcycle_offset = assert(tonumber(take_argument("missing mcycle offset")), "invalid mcycle offset")
    local uarch_cycle = assert(tonumber(take_argument("missing uarch cycle")), "invalid uarch cycle")
    local answer = take_argument("missing answer")
    new_player = function(dapp_contract, label)
        return new_tamperer(dapp_contract, epoch_input_offset, mcycle_offset, uarch_cycle, answer, label)
    end
else
    error("unknown role: " .. role)
end
local label = take_argument()
assert(next_argument > #arg, "only the referee takes input files")
local dapp_contract = prt.new_dapp_contract(initial_state_hash, {})
local player <close> = new_player(dapp_contract, label)
prtu.run_client(player, server_address)
