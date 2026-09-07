-- The player side of the PRT game: the machines, the claim builds, the event handlers the
-- referee invokes, and the dishonest strategies. The whole geometry follows from the
-- mcycle period the dapp contract publishes.

local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local hash_tree = require("cartesi.hash-tree")
local prtu = require("prtu")

local keccak = cartesi.keccak256
local format_short_hash = prtu.format_short_hash
local new_tree = prtu.new_tree

local function write_stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

--------------------------------------------------------------------------------
-- Geometry
--
-- The epoch spans 2^24 inputs of 2^48 mcycles each, and every mcycle expands into 2^20
-- uarch transitions, the same three coordinates as the rolling verification game. The mcycle
-- claim samples the epoch every 2^LOG2_MCYCLES_PER_PERIOD mcycles. The uarch claim expands one mcycle
-- period into its uarch transitions. Each claim is stored bundled: the machine delivers one
-- subtree root per 2^bundle leaves, so the stored tree is that much shallower, and queries
-- below a bundle are answered by refining it.
--------------------------------------------------------------------------------

local LOG2_MCYCLE_BUNDLE = 4
local LOG2_UARCH_BUNDLE = 16
local LOG2_HASHES_PER_CHUNK = 8
local DEFAULT_MACHINE_CACHE_CAPACITY = 8
local DEFAULT_MACHINE_CACHE_GAP = 1 << (LOG2_MCYCLE_BUNDLE + LOG2_HASHES_PER_CHUNK)
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
local WORD_MASK = WORD_SIZE - 1
local IFLAGS_Y_ADDRESS = cartesi.machine:get_reg_address("iflags_Y")
local HTIF_TOHOST_ADDRESS = cartesi.machine:get_reg_address("htif_tohost")
local CMIO_TX_BUFFER_ADDRESS = cartesi.AR_CMIO_TX_BUFFER_START

local M = {}

-- The mcycle offset at which a tamperer corrupts its machine, bundle-aligned.
local function tamper_offset(player)
    local tamper = player.tamper
    return tamper.bundle_offset << (LOG2_MCYCLE_BUNDLE + player.geometry.log2_mcycles_per_period)
end

-- A machine stopped at a manual yield, halt, or mcycle overflow no longer advances on its own.
local function is_at_fixed_point(break_reason)
    return break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY
        or break_reason == cartesi.BREAK_REASON_HALTED
        or break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW
end

local function is_target_mcycle(break_reason)
    return break_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
end

local function mcycle_hashes_chunk_size(log2_period, log2_bundle)
    local log2_chunk_size = log2_period + log2_bundle + LOG2_HASHES_PER_CHUNK
    if log2_chunk_size >= 64 then
        return cartesi.MCYCLE_MAX
    end
    return 1 << log2_chunk_size
end

-- Forks a machine's server. The fork is shut down when the object holding it is closed or
-- collected, so a player leaves no server behind when it exits, even on an error.
local function fork_server(machine)
    local fork = assert(machine:fork_server())
    fork:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    return fork
end

-- Loads the initial machine snapshot from content-addressed local storage on its own freshly
-- spawned server, and verifies that the stored machine actually has the requested state hash.
-- The machine lives on a fork of the spawned server, and shuts down with its object too.
local function load_remote_machine(initial_state_hash)
    local server <close> = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    server:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    local machine = server(cartesi.tohex(initial_state_hash))
    machine:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    assert(machine:get_root_hash() == initial_state_hash, "initial machine snapshot hash mismatch")
    return machine
end

--------------------------------------------------------------------------------
-- Machine checkpoint cache
--
-- A checkpoint is indexed by the computation hash's epoch period index, the same integer prt.lua
-- uses to locate an input and a period within it. An input's first period is its virgin boundary,
-- before delivery. This distinguishes inputs that begin at the same physical mcycle after earlier
-- inputs reject and revert.
--
-- The cache is only an optimization. Its first checkpoint is the content-addressed initial
-- machine at position zero. Cached machines are immutable: callers receive fresh forks, and the
-- cache owns and eventually shuts down the originals. Replacing this object with another policy
-- changes only which checkpoints survive.
--------------------------------------------------------------------------------

local machine_cache_meta = { __index = {} }

-- Only the forward claim build offers checkpoints, so the list remains ordered.
-- Retains suitably spaced offers until the cache fills. It then doubles the gap and replaces the
-- first checkpoint whose predecessor is too close whenever a new offer extends that spacing. Once
-- no such checkpoint remains, the gap doubles again.
function machine_cache_meta.__index:consider(epoch_period_index, machine)
    local checkpoints = self.checkpoints
    local latest = checkpoints[#checkpoints]
    assert(epoch_period_index > latest.epoch_period_index, "machine checkpoints are not ordered")
    -- Ignore offers that are not far enough from the previous checkpoint.
    if epoch_period_index - latest.epoch_period_index < self.gap then
        return
    end
    -- Evict the next checkpoint that is too close to its predecessor.
    if #checkpoints == self.capacity then
        local replace_index = self.replace_cursor
        while replace_index <= #checkpoints do
            local previous = checkpoints[replace_index - 1].epoch_period_index
            if checkpoints[replace_index].epoch_period_index - previous < self.gap then
                break
            end
            replace_index = replace_index + 1
        end
        -- Every retained gap is large enough. Double the gap and restart the search.
        if replace_index > #checkpoints then
            self.gap = self.gap << 1
            self.replace_cursor = 2
            return
        end
        local replaced = table.remove(checkpoints, replace_index)
        replaced.machine:shutdown_server()
        self.replace_cursor = replace_index
    end
    -- Add the new checkpoint.
    checkpoints[#checkpoints + 1] = {
        epoch_period_index = epoch_period_index,
        machine = fork_server(machine),
    }
end

-- Removes checkpoints produced while an input was executing. This is needed when the input later
-- rejects: its computation-hash entries contain the revert state, not those speculative machines.
function machine_cache_meta.__index:discard_input(input_index, periods_per_input)
    local first = input_index * periods_per_input
    local last = first + periods_per_input
    for i = #self.checkpoints, 1, -1 do
        local checkpoint = self.checkpoints[i]
        if checkpoint.epoch_period_index > first and checkpoint.epoch_period_index < last then
            table.remove(self.checkpoints, i)
            checkpoint.machine:shutdown_server()
        end
    end
end

-- Returns a working fork of the closest retained checkpoint not after target.
function machine_cache_meta.__index:fork_closest(epoch_period_index)
    local closest = self.checkpoints[1]
    for i = 2, #self.checkpoints do
        if self.checkpoints[i].epoch_period_index > epoch_period_index then
            break
        end
        closest = self.checkpoints[i]
    end
    return fork_server(closest.machine), closest.epoch_period_index
end

local function new_machine_cache(initial_state_hash, capacity, initial_gap, initial_machine)
    capacity = capacity or DEFAULT_MACHINE_CACHE_CAPACITY
    assert(capacity > 0, "machine cache capacity must include its initial checkpoint")
    local gap = initial_gap or DEFAULT_MACHINE_CACHE_GAP
    return setmetatable({
        capacity = capacity,
        checkpoints = {
            {
                epoch_period_index = 0,
                machine = initial_machine or load_remote_machine(initial_state_hash),
            },
        },
        gap = gap,
        replace_cursor = 2,
    }, machine_cache_meta)
end

-- Runs a machine toward the target mcycle, resuming through automatic yields until it reaches
-- the target, yields manual, or halts. Each output an automatic yield carries is collected into
-- `sink` when one is given, and dropped otherwise.
local function run_to(machine, target, sink)
    while true do
        local break_reason = machine:run(target)
        if break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            return break_reason
        end
        local _, request_reason, data = machine:receive_cmio_request()
        if sink and request_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
            sink[#sink + 1] = data
        end
    end
end

-- The reason of a valid HTIF manual yield a machine stands at, or nil when the machine
-- stands at no such request.
local function manual_yield(machine)
    if machine:read_reg("iflags_Y") == 0 then
        return nil
    end
    if
        machine:read_reg("htif_tohost_dev") ~= cartesi.HTIF_DEV_YIELD
        or machine:read_reg("htif_tohost_cmd") ~= cartesi.HTIF_YIELD_CMD_MANUAL
    then
        return nil
    end
    return machine:read_reg("htif_tohost_reason")
end

-- Feeds an input to a machine waiting for one at an rx-accepted manual yield, recording the
-- state a rejection reverts to. A machine at any other fixed point takes no input, since the
-- verified transition treats the feed as a no-op there, and idles through the input's span.
local function feed_input(machine, data)
    if manual_yield(machine) ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
        return
    end
    local revert_state_hash = machine:get_root_hash()
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_state_hash)
end

--------------------------------------------------------------------------------
-- Player: building the mcycle claim
--
-- The player advances the whole epoch once, collecting the machine state hash every period
-- as bundle roots, one per 2^LOG2_MCYCLE_BUNDLE samples. A machine stopped at a
-- manual yield, halt, or mcycle overflow repeats its state hash to the end of its input's span, and
-- the machine pads the stream accordingly, so each input contributes a short prefix of real bundles
-- followed by one enormous repetition. A machine that halted, overflowed, or yielded with an
-- exception takes no later input, so it repeats its state hash through every later span as
-- well. Every return from hash collection offers the machine to a bounded cache. Later re-runs
-- start from the closest epoch period index its replaceable policy retained.
--------------------------------------------------------------------------------

-- Advances a machine standing at input index's boundary through the feed (when the epoch
-- has an input there) and on to `offset` mcycles past the post-feed boundary. A player
-- whose `tamper` hook names this input and an offset on the way corrupts the machine there,
-- so every re-run repeats the corrupted history. The tamper offset is bundle-aligned, so
-- collection windows never straddle it. A temporary fork restores the virgin boundary when
-- the guest rejects, and is discarded before this function returns. Returns the boundary
-- mcycle.
local function advance_fork(player, machine, index, offset)
    local data = player.inputs[index]
    local boundary <close> = data and fork_server(machine) or nil
    if data then
        feed_input(machine, data)
    end
    local base = machine:read_reg("mcycle")
    local tamper = player.tamper
    if tamper and tamper.input == index and offset >= tamper_offset(player) then
        run_to(machine, base + tamper_offset(player))
        if machine:read_reg("mcycle") == base + tamper_offset(player) then
            tamper.apply(machine)
        end
    end
    run_to(machine, base + offset)
    if manual_yield(machine) == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
        assert(boundary, "machine rejected outside a posted input")
        machine:shutdown_server()
        machine:swap(fork_server(boundary))
    end
    return base
end

-- Continues a machine whose input was already delivered from one period boundary to another.
local function advance_from_period(player, machine, input_index, period_index, target_period_index)
    local period_count = target_period_index - period_index
    local tamper = player.tamper
    local tamper_period = tamper and tamper_offset(player) >> player.geometry.log2_mcycles_per_period
    if
        tamper
        and tamper.input == input_index
        and period_index <= tamper_period
        and target_period_index >= tamper_period
    then
        local tamper_mcycle = machine:read_reg("mcycle")
            + (tamper_period - period_index) * player.geometry.mcycles_per_period
        run_to(machine, tamper_mcycle)
        if machine:read_reg("mcycle") ~= tamper_mcycle then
            return
        end
        tamper.apply(machine)
        period_count = target_period_index - tamper_period
    end
    run_to(machine, machine:read_reg("mcycle") + period_count * player.geometry.mcycles_per_period)
end

-- Forks the closest cached machine and deterministically replays to a virgin input boundary.
local function replay_to_input_boundary(player, input_index)
    local target_input_index = input_index - 1
    local machine, cached_epoch_period_index =
        player.machine_cache:fork_closest(target_input_index * player.geometry.periods_per_input)
    local cached_input_index = cached_epoch_period_index // player.geometry.periods_per_input
    local cached_period_index = cached_epoch_period_index % player.geometry.periods_per_input
    if cached_period_index > 0 then
        advance_from_period(
            player,
            machine,
            cached_input_index + 1,
            cached_period_index,
            player.geometry.periods_per_input
        )
        if manual_yield(machine) ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            return machine
        end
        cached_input_index = cached_input_index + 1
    end
    local last_input = math.min(target_input_index, #player.inputs)
    for index = cached_input_index + 1, last_input do
        advance_fork(player, machine, index, 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE)
        if manual_yield(machine) ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            break
        end
    end
    return machine
end

-- Forks the closest checkpoint in an input and advances it to the requested period. If the cache
-- has no checkpoint in that input, replay starts at its virgin boundary and includes delivery.
local function fork_mcycle_position(player, input_index, period_index)
    local input_index_0 = input_index - 1
    local machine, cached_epoch_period_index =
        player.machine_cache:fork_closest(input_index_0 * player.geometry.periods_per_input + period_index)
    local cached_input_index = cached_epoch_period_index // player.geometry.periods_per_input
    local cached_period_index = cached_epoch_period_index % player.geometry.periods_per_input
    if cached_input_index ~= input_index_0 or cached_period_index == 0 then
        machine:shutdown_server()
        machine = replay_to_input_boundary(player, input_index)
        advance_fork(player, machine, input_index, period_index * player.geometry.mcycles_per_period)
        return machine
    end
    advance_from_period(player, machine, input_index, cached_period_index, period_index)
    return machine
end

-- Adds a collection's bundle roots to one reserved segment of the claim. As in cartesi-machine's
-- computation-hash builder, roots beyond the segment capacity are ignored, and the final root
-- returned at a fixed point fills every position that remains. The only difference is the sink:
-- PRT appends to a frontier forest, which retains the nodes a later match walk needs, while
-- cartesi-machine appends to a plain frontier.
local function mcycle_computation_hash_push_collected(claim, collected)
    local count = math.min(#collected.hashes, claim.input_entry_capacity - claim.input_entry_count)
    hash_tree.frontier_forest_append(claim.frontier, collected.hashes, 1, count)
    claim.input_entry_count = claim.input_entry_count + count
    if not is_at_fixed_point(collected.break_reason) then
        return
    end
    assert(#collected.hashes > 0, "fixed-point mcycle collection has no final bundle")
    claim.pad_bundle = collected.hashes[#collected.hashes]
    hash_tree.frontier_forest_pad_back(
        claim.frontier,
        claim.pad_bundle,
        claim.input_entry_capacity - claim.input_entry_count
    )
    claim.input_entry_count = claim.input_entry_capacity
end

-- Opens an epoch computation hash. Its frontier is a forest so the player can later descend to
-- any retained bundle; otherwise this is the same lifecycle used by cartesi-machine.lua.
local function mcycle_computation_hash_begin_epoch(claim)
    claim.epoch_entry_count = 0
    claim.pad_bundle = nil
end

-- Input delivery does not advance mcycle. Open at the virgin boundary, exclude that boundary from
-- the samples, and limit collection to this input's mcycle budget.
local function mcycle_computation_hash_begin_input(claim, input_index)
    claim.input_index = input_index
    claim.input_entry_count = 0
    claim.mcycle_phase = 0
    claim.partial_bundle = nil
    claim.input_base = claim.machine:read_reg("mcycle")
    claim.input_mcycle_end = claim.input_base + (1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE)
end

-- Offers the machine after every collect call. Only exact period boundaries are useful as
-- checkpoints; an accepted yield is the next input's virgin period zero, while a rejected yield
-- is deliberately not cached because its claim entries use the revert state.
local function consider_mcycle_machine(claim, collected)
    if not claim.cache_machine then
        return
    end
    local epoch_period_index
    local period_index
    if collected.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY and collected.mcycle_phase == 0 then
        period_index = (claim.machine:read_reg("mcycle") - claim.input_base) >> claim.log2_period
        epoch_period_index = claim.input_index * claim.player.geometry.periods_per_input + period_index
    end
    if collected.break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY then
        local reason = manual_yield(claim.machine)
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            epoch_period_index = (claim.input_index + 1) * claim.player.geometry.periods_per_input
        elseif reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            epoch_period_index = nil
        end
    end
    if epoch_period_index then
        claim.player.machine_cache:consider(epoch_period_index, claim.machine)
    end
end

-- Samples this input in the same bounded chunks as cartesi-machine.lua. The phase and partial
-- bundle cross calls, so tamper points and automatic yields do not disturb the hash stream.
local function mcycle_computation_hash_run(claim, mcycle_end)
    mcycle_end = math.min(mcycle_end, claim.input_mcycle_end)
    local collected = {
        mcycle_phase = claim.mcycle_phase,
        partial_bundle = claim.partial_bundle,
    }
    local chunk_end = claim.machine:read_reg("mcycle")
    repeat
        chunk_end = math.min(chunk_end + claim.chunk_size, mcycle_end)
        collected = claim.machine:collect_mcycle_root_hashes(
            chunk_end,
            claim.log2_period,
            collected.mcycle_phase,
            claim.log2_bundle,
            collected.partial_bundle
        )
        mcycle_computation_hash_push_collected(claim, collected)
        consider_mcycle_machine(claim, collected)
    until not is_target_mcycle(collected.break_reason) or chunk_end == mcycle_end
    claim.mcycle_phase = collected.mcycle_phase
    claim.partial_bundle = collected.partial_bundle
    return collected.break_reason
end

local function mcycle_computation_hash_end_input(claim)
    assert(claim.input_entry_count == claim.input_entry_capacity, "mcycle computation hash input is incomplete")
    claim.epoch_entry_count = claim.epoch_entry_count + claim.input_entry_capacity
    claim.input_entry_count = nil
end

-- Unprocessed inputs repeat the last fixed-point bundle, exactly as in cartesi-machine.lua. With
-- no processed input, obtain that bundle directly from the initial fixed-point machine.
local function mcycle_computation_hash_end_epoch(claim)
    local pad_bundle = claim.pad_bundle
    if not pad_bundle then
        local collected = claim.machine:collect_mcycle_root_hashes(
            claim.machine:read_reg("mcycle"),
            claim.log2_period,
            0,
            claim.log2_bundle
        )
        assert(is_at_fixed_point(collected.break_reason), "mcycle computation hash ended outside a fixed point")
        pad_bundle = collected.hashes[#collected.hashes]
        assert(pad_bundle, "fixed-point mcycle collection has no final bundle")
    end
    hash_tree.frontier_forest_pad_back(
        claim.frontier,
        pad_bundle,
        claim.player.mcycle_bundles - claim.epoch_entry_count
    )
    return claim.frontier
end

local function new_mcycle_computation_hash(player, machine, frontier, input_entry_capacity, log2_bundle, cache_machine)
    local log2_period = player.geometry.log2_mcycles_per_period
    return {
        player = player,
        machine = machine,
        frontier = frontier,
        input_entry_capacity = input_entry_capacity,
        chunk_size = mcycle_hashes_chunk_size(log2_period, log2_bundle),
        log2_period = log2_period,
        log2_bundle = log2_bundle,
        cache_machine = cache_machine,
        begin_epoch = mcycle_computation_hash_begin_epoch,
        begin_input = mcycle_computation_hash_begin_input,
        run = mcycle_computation_hash_run,
        end_input = mcycle_computation_hash_end_input,
        end_epoch = mcycle_computation_hash_end_epoch,
    }
end

-- Runs a computation-hash runner through automatic yields until it reaches the requested mcycle or
-- a fixed point. The terminal manual yield remains available to the epoch driver.
local function run_computation_hash_to_stop(claim, mcycle_end)
    while true do
        local break_reason = claim:run(mcycle_end)
        if break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            return break_reason
        end
        claim.machine:receive_cmio_request()
    end
end

-- Builds the mcycle claim's outer forest by advancing the epoch. Each input is fed and
-- collected until its fixed point (splitting the collection at the player's tamper point,
-- where the machine is corrupted mid-flight), then padded to its full span with its last
-- bundle, the all-repetition bundle the machine emits at the stop. A rejecting machine
-- trades places with a fresh fork of its boundary, the recorded revert state, exactly as a
-- Cartesi Node rolls back. A machine that halted, overflowed, or threw an exception takes no
-- later input and repeats its state through every later span.
-- docs:begin build_mcycle_claim
local function build_mcycle_claim(player)
    local machine <close> = load_remote_machine(player.initial_state_hash)
    local frontier = hash_tree.frontier_forest(player.geometry.mcycle_height - LOG2_MCYCLE_BUNDLE, "keccak256")
    local claim =
        new_mcycle_computation_hash(player, machine, frontier, player.bundles_per_input, LOG2_MCYCLE_BUNDLE, true)
    claim:begin_epoch()
    for index, data in ipairs(player.inputs) do
        local boundary <close> = fork_server(machine)
        claim:begin_input(index - 1)
        feed_input(machine, data)
        local tamper = player.tamper
        if tamper and tamper.input == index then
            local break_reason = run_computation_hash_to_stop(claim, claim.input_base + tamper_offset(player))
            assert(not is_at_fixed_point(break_reason), "the machine stopped before the tamper point")
            tamper.apply(machine)
        end
        run_computation_hash_to_stop(claim, claim.input_mcycle_end)
        claim:end_input()
        local yield_reason = manual_yield(machine)
        if yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            player.machine_cache:discard_input(index - 1, player.geometry.periods_per_input)
            machine:shutdown_server()
            machine:swap(fork_server(boundary))
        elseif yield_reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            break
        end
    end
    return claim:end_epoch()
end
-- docs:end build_mcycle_claim

--------------------------------------------------------------------------------
-- Player: refining an mcycle bundle
--
-- A walk that descends below a stored bundle asks the tree to refine it. The player forks
-- the input's boundary, re-runs the fork to the bundle's window, and collects the window's
-- samples unbundled. Samples past the guest's stop repeat the input's fixed leaf (the
-- reverted state hash when the input was rejected), so the window is padded with it.
--------------------------------------------------------------------------------

-- docs:begin refine_mcycle_claim
local function refine_mcycle_claim(player, bundle)
    local bundle_size = 1 << LOG2_MCYCLE_BUNDLE
    local bundle_forest = hash_tree.frontier_forest(LOG2_MCYCLE_BUNDLE, "keccak256")
    local input_index = bundle // player.bundles_per_input + 1
    local bundle_period = (bundle % player.bundles_per_input) * bundle_size
    if input_index > #player.inputs then -- epoch tail: repetitions of the last fixed point
        local machine <close> = replay_to_input_boundary(player, input_index)
        hash_tree.frontier_forest_pad_back(bundle_forest, machine:get_root_hash(), bundle_size)
        return bundle_forest
    end
    local machine <close> = fork_mcycle_position(player, input_index, bundle_period)
    local start = machine:read_reg("mcycle")
    local claim = new_mcycle_computation_hash(player, machine, bundle_forest, bundle_size, 0, false)
    claim:begin_input(input_index - 1)
    run_computation_hash_to_stop(claim, start + bundle_size * player.geometry.mcycles_per_period)
    assert(claim.input_entry_count == claim.input_entry_capacity, "mcycle refinement did not fill its bundle")
    return bundle_forest
end
-- docs:end refine_mcycle_claim

--------------------------------------------------------------------------------
-- Player: building a uarch claim
--
-- A uarch claim expands the mcycle period ending at the disputed leaf: the state hash
-- after every uarch transition of its 2^LOG2_MCYCLES_PER_PERIOD instructions, delivered as one bundle
-- root per 2^LOG2_UARCH_BUNDLE transitions. Each instruction contributes its real uarch
-- cycles, repetitions of the uarch halt state filling its span, and the reset that closes
-- it. An input stopped at a manual yield, halt, or mcycle overflow no longer advances, so
-- instructions past the stop repeat the no-op uarch period of the stopped state.
--------------------------------------------------------------------------------

-- Pushes the stream of one instruction (hashes first..last, ending at its reset hash) into
-- a claim segment: the real bundles, the halt bundle repeated to fill the instruction's
-- transitions, and the reset bundle that closes it.
local function push_uarch_mcycle(target, hashes, first, last, log2_bundle)
    local capacity = 1 << (cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - log2_bundle)
    local real = last - first - 1
    assert(real >= 0 and real <= capacity - 1, "too many uarch cycles in an instruction")
    hash_tree.frontier_forest_append(target, hashes, first, last - 2)
    hash_tree.frontier_forest_pad_back(target, hashes[last - 1], capacity - 1 - real)
    hash_tree.frontier_forest_push_back(target, hashes[last])
end

-- Adds each returned mcycle group to a uarch claim segment. A fixed-point collection ends in
-- one repeatable group; after adding it once, build that group as its own complete forest,
-- repeated to fill the segment, so its bundle roots stay reachable for a later match walk.
-- This is the forest counterpart of cartesi-machine's
-- uarch_cycle_computation_hash_push_collected.
local function push_uarch_collection(target, collected, count, capacity, log2_bundle)
    local offsets = collected.mcycle_hash_offsets
    local wanted = math.min(#offsets - 1, capacity - count)
    for i = 1, wanted do
        push_uarch_mcycle(target, collected.hashes, offsets[i], offsets[i + 1] - 1, log2_bundle)
    end
    count = count + wanted
    if count < capacity and is_at_fixed_point(collected.break_reason) then
        assert(wanted > 0, "fixed-point collection has no padding period")
        local group =
            hash_tree.frontier_forest(cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - log2_bundle, "keccak256")
        push_uarch_mcycle(group, collected.hashes, offsets[wanted], offsets[wanted + 1] - 1, log2_bundle)
        hash_tree.frontier_forest_pad_back(target, group, capacity - count)
        count = capacity
    end
    return count
end

-- Builds the uarch claim's outer forest for one mcycle period, `period_index` periods past
-- input `input_index`'s boundary. The span covering an input's first period opens with the
-- feed, whose transition also executes the first uarch step. The revert tail, captured at
-- the boundary before the feed, lets the collection cross a rejected yield inside the span.
-- docs:begin build_uarch_claim
local function build_uarch_claim(player, input_index, period_index)
    local machine <close> = replay_to_input_boundary(player, input_index)
    local revert_uarch_tail = machine:collect_uarch_cycle_root_hashes(math.maxinteger, 0).hashes
    local base = advance_fork(player, machine, input_index, period_index * player.geometry.mcycles_per_period)
    local start = base + period_index * player.geometry.mcycles_per_period
    local outer = hash_tree.frontier_forest(player.geometry.uarch_height - LOG2_UARCH_BUNDLE, "keccak256")
    local mcycles = 0
    while mcycles < player.geometry.mcycles_per_period do
        local collected = machine:collect_uarch_cycle_root_hashes(
            start + player.geometry.mcycles_per_period,
            LOG2_UARCH_BUNDLE,
            revert_uarch_tail
        )
        mcycles =
            push_uarch_collection(outer, collected, mcycles, player.geometry.mcycles_per_period, LOG2_UARCH_BUNDLE)
        if collected.break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            machine:receive_cmio_request()
        end
    end
    return outer
end
-- docs:end build_uarch_claim

-- Positions a fresh fork at one instruction of the period and collects that single
-- instruction's uarch cycles unbundled. A fork that stops before the instruction stands at
-- the span's fixed point, whose no-op period expands the same way.
local function collect_uarch_instruction(player, input_index, period_index, mcycle_offset)
    local machine <close> = replay_to_input_boundary(player, input_index)
    local revert_uarch_tail = machine:collect_uarch_cycle_root_hashes(math.maxinteger, 0).hashes
    local base =
        advance_fork(player, machine, input_index, period_index * player.geometry.mcycles_per_period + mcycle_offset)
    local target = base + period_index * player.geometry.mcycles_per_period + mcycle_offset
    local mcycle_end = math.min(target + 1, machine:read_reg("mcycle") + 1)
    local collected = machine:collect_uarch_cycle_root_hashes(mcycle_end, 0, revert_uarch_tail)
    local offsets = collected.mcycle_hash_offsets
    assert(#offsets >= 2, "uarch collection returned no mcycle period")
    return collected.hashes, offsets[1], offsets[2] - 1
end

-- The forest of one uarch bundle: positions [window_start, window_start + bundle_size) of
-- the instruction's expanded transitions, the real cycles first, then the halt state
-- repeated to fill the span, and the reset that closes it.
local function slice_uarch_window(hashes, first, last, window_start, bundle_size)
    local capacity = 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local real = last - first - 1
    assert(real >= 0 and real <= capacity - 1, "too many uarch cycles in an instruction")
    local window_forest = hash_tree.frontier_forest(LOG2_UARCH_BUNDLE, "keccak256")
    local window_end = window_start + bundle_size
    local real_end = math.min(window_end, real)
    if window_start < real_end then
        hash_tree.frontier_forest_append(window_forest, hashes, first + window_start, first + real_end - 1)
    end
    local halt_start = math.max(window_start, real)
    local halt_end = math.min(window_end, capacity - 1)
    if halt_start < halt_end then
        hash_tree.frontier_forest_pad_back(window_forest, hashes[last - 1], halt_end - halt_start)
    end
    if window_end == capacity then -- the reset closing the instruction
        hash_tree.frontier_forest_push_back(window_forest, hashes[last])
    end
    return window_forest
end

-- Refines one uarch bundle: collects the bundle's instruction unbundled, expands it into
-- the instruction's 2^ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE transitions, and keeps the
-- bundle's window of them.
-- docs:begin refine_uarch_claim
local function refine_uarch_claim(player, input_index, period_index, bundle)
    local bundle_size = 1 << LOG2_UARCH_BUNDLE
    local bundles_per_mcycle = 1 << (cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - LOG2_UARCH_BUNDLE)
    local mcycle_offset = bundle // bundles_per_mcycle
    local window_start = (bundle % bundles_per_mcycle) * bundle_size
    local hashes, first, last = collect_uarch_instruction(player, input_index, period_index, mcycle_offset)
    return slice_uarch_window(hashes, first, last, window_start, bundle_size)
end
-- docs:end refine_uarch_claim

--------------------------------------------------------------------------------
-- Player: event responses
--
-- The handlers below produce responses to events emitted by the referee. A player follows one
-- claim lineage: its mcycle claim, and, while that claim's match is suspended in a uarch
-- tournament, the uarch claim it committed there. The referee emits an event only to holders
-- of the claim it concerns, so an event about any other claim is a bug, and the player dies on it.
--------------------------------------------------------------------------------

local handlers = {}

-- The claim in the player's lineage with the given root.
local function get_claim_tree(player, computation_hash)
    for _, tree in ipairs({ player.mcycle_claim, player.uarch_claim }) do
        if tree:get_root() == computation_hash then
            return tree
        end
    end
    error("event concerns a claim this player does not hold: " .. format_short_hash(computation_hash))
end

-- A claim: the computation hash's two children and the standard proof of its final state,
-- the last leaf. Producing the proof explicitly opens the last stored bundle.
local function make_claim(tree)
    local final_state_index = (1 << tree.height) - 1
    if tree.bundle_height > 0 then
        tree:open_bundle(final_state_index >> tree.bundle_height)
    end
    local computation_hash_left, computation_hash_right = tree:get_children(0, tree.height)
    return {
        computation_hash_left = computation_hash_left,
        computation_hash_right = computation_hash_right,
        final_state_hash_proof = tree:prove(final_state_index),
    }
end

-- The player's opening mcycle claim. The player announces its root, so a transcript can be
-- read against the players, without the referee ever narrating who holds what.
function handlers.commit_mcycle_claim(player)
    write_stderr("%s: building mcycle claim\n", player.label)
    player.mcycle_claim = player:make_mcycle_tree()
    local claim = make_claim(player.mcycle_claim)
    write_stderr(
        "%s: posted claim %s with final state %s\n",
        player.label,
        format_short_hash(player.mcycle_claim:get_root()),
        format_short_hash(claim.final_state_hash_proof.target_hash)
    )
    return claim
end

-- Reveals the nodes the referee needs for one bisection advance: the claim's node at
-- (position, height), and the children of the node the walk descends into. Either node can
-- cross into a stored bundle here because the claims alternate turns; crossing reconstructs
-- and authenticates that complete bundle before the walk continues through it.
function handlers.reveal_bisection(player, computation_hash, position, height, other_left_node)
    assert(height > 1)
    local tree = get_claim_tree(player, computation_hash)
    if height == tree.bundle_height then
        tree:open_bundle(position >> tree.bundle_height)
    end
    local turn_left_node, turn_right_node = tree:get_children(position, height)
    local descend_left = turn_left_node ~= other_left_node
    local child_position = descend_left and position or position + (1 << (height - 1))
    if height - 1 == tree.bundle_height then
        tree:open_bundle(child_position >> tree.bundle_height)
    end
    local turn_next_left_node, turn_next_right_node = tree:get_children(child_position, height - 1)
    return {
        turn_left_node = turn_left_node,
        turn_right_node = turn_right_node,
        turn_next_left_node = turn_next_left_node,
        turn_next_right_node = turn_next_right_node,
    }
end

-- Seals the leftmost divergence: exposes the final leaves and proves the agreed state
-- immediately before them, except at state zero where the referee already knows that state.
-- At the first leaf of a bundle, the proof explicitly opens the preceding bundle too.
function handlers.seal_divergence(player, computation_hash, position, other_left_node)
    local tree = get_claim_tree(player, computation_hash)
    local turn_left_node, turn_right_node = tree:get_children(position, 1)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= other_left_node
    local state_index = position + (descend_left and 0 or 1)
    if state_index ~= 0 then
        local agreed_state_index = state_index - 1
        if tree.bundle_height > 0 then
            tree:open_bundle(agreed_state_index >> tree.bundle_height)
        end
        response.agreed_state_hash_proof = tree:prove(agreed_state_index)
        assert(
            descend_left or response.agreed_state_hash_proof.target_hash == turn_left_node,
            "right divergence has the wrong agreed state"
        )
    end
    return response
end

-- Joins the uarch tournament over one mcycle period that the player's mcycle claim is
-- disputed in, with a uarch claim whose final state must be one of the two contested values.
-- The uarch claim becomes the nested claim of the player's lineage, replacing any earlier
-- one, since the parent match is suspended until the uarch tournament ends. The input index
-- and the period index are 0-based, as the referee counts them. A holder whose uarch claim
-- ends in neither contested value cannot defend its parent claim, and dies on the
-- contradiction.
function handlers.commit_uarch_claim(player, input_index, period_index, next_state_hashes)
    write_stderr("%s: building uarch claim for input %d, period %d\n", player.label, input_index, period_index)
    player.uarch_claim = player:make_uarch_tree(input_index + 1, period_index)
    local claim = make_claim(player.uarch_claim)
    local final_state_hash = claim.final_state_hash_proof.target_hash
    assert(
        final_state_hash == next_state_hashes[1] or final_state_hash == next_state_hashes[2],
        string.format(
            "%s: uarch final %s matches neither contested final %s nor %s",
            player.label,
            format_short_hash(final_state_hash),
            format_short_hash(next_state_hashes[1]),
            format_short_hash(next_state_hashes[2])
        )
    )
    write_stderr("%s: uarch claim ready\n", player.label)
    return claim
end

-- The disputed transition's access logs, produced by positioning a fresh fork at the
-- transition and logging it, whatever claim is under dispute. The transition out of an
-- input boundary includes the input, when the epoch has one, before the first uarch step.
-- The transition closing an instruction executes one more step, by then a fixed point, and
-- the reset. Every other transition is an ordinary uarch step.
-- docs:begin prove_state_transition
function handlers.prove_state_transition(player, input_index, period_index, state_transition_offset)
    local mcycle_offset = state_transition_offset >> cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local uarch_cycle = state_transition_offset & cartesi.UARCH_CYCLE_MAX
    local machine <close> = replay_to_input_boundary(player, input_index + 1)
    local data = player.inputs[input_index + 1]
    if state_transition_offset == 0 and period_index == 0 and data then
        local revert_state_hash = machine:get_root_hash()
        local send_cmio_log =
            machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_state_hash)
        return { send_cmio_log = send_cmio_log, step_log = machine:log_step_uarch() }
    end
    advance_fork(player, machine, input_index + 1, period_index * player.geometry.mcycles_per_period + mcycle_offset)
    machine:run_uarch(uarch_cycle)
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        local step_log = machine:log_step_uarch()
        return { step_log = step_log, reset_uarch_log = machine:log_reset_uarch() }
    end
    return { step_log = machine:log_step_uarch() }
end
-- docs:end prove_state_transition

-- A machine leaf proof includes the complete target data, separately from the standard proof
-- that authenticates its hash. Machine registers may sit within a word, so the proof starts at
-- the containing word boundary.
local function get_machine_leaf(machine, address)
    local target_address = address & ~WORD_MASK
    return machine:read_memory(target_address, WORD_SIZE),
        machine:get_proof(target_address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
end

-- Re-runs the whole epoch on a fresh machine, collecting its outputs separately from the three
-- final-machine leaves Dave uses to validate an epoch result. A rejected input reverts to the
-- pre-feed snapshot, exactly as a Cartesi Node rolls back. A machine that halted, overflowed,
-- or threw an exception takes no later input, and its terminal state is the one Dave checks.
local function compute_epoch_results(player)
    if player.outputs_merkle_root_result then
        return
    end
    local machine = load_remote_machine(player.initial_state_hash)
    local genesis_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local frontier = hash_tree.frontier_copy(genesis_frontier)
    local outputs, leaves = {}, {}
    for _, data in ipairs(player.inputs) do
        local snapshot = fork_server(machine)
        local sink = {}
        feed_input(machine, data)
        run_to(machine, math.maxinteger, sink)
        local reason = manual_yield(machine)
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            local _, _, reported_root = machine:receive_cmio_request()
            for _, output in ipairs(sink) do
                outputs[#outputs + 1] = output
                leaves[#leaves + 1] = keccak(output)
                hash_tree.frontier_push_back(frontier, leaves[#leaves])
            end
            assert(hash_tree.frontier_get_root_hash(frontier) == reported_root, "outputs Merkle root mismatch")
        elseif reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            machine:shutdown_server()
            machine:swap(fork_server(snapshot))
        end
        snapshot:shutdown_server()
    end
    local iflags_y_data, iflags_y_proof = get_machine_leaf(machine, IFLAGS_Y_ADDRESS)
    local htif_tohost_data, htif_tohost_proof = get_machine_leaf(machine, HTIF_TOHOST_ADDRESS)
    local tx_buffer_data, tx_buffer_proof = get_machine_leaf(machine, CMIO_TX_BUFFER_ADDRESS)
    machine:shutdown_server()
    local output_index = #outputs - 1
    player.outputs_merkle_root_result = {
        iflags_y_data = iflags_y_data,
        iflags_y_proof = iflags_y_proof,
        htif_tohost_data = htif_tohost_data,
        htif_tohost_proof = htif_tohost_proof,
        tx_buffer_data = tx_buffer_data,
        tx_buffer_proof = tx_buffer_proof,
    }
    player.output_result = {
        output_index = output_index >= 0 and output_index or nil,
        output = outputs[#outputs],
        output_proof = hash_tree.frontier_next_proofs(genesis_frontier, leaves)[#leaves],
    }
end

-- Proves that the settled final state is yielded manually with RX_ACCEPTED and authenticates
-- the word whose data is the outputs Merkle root.
-- docs:begin prove_outputs_merkle_root
function handlers.prove_outputs_merkle_root(player)
    compute_epoch_results(player)
    return player.outputs_merkle_root_result
end
-- docs:end prove_outputs_merkle_root

-- Separately offers the last output, when there is one, after the referee has established the
-- outputs Merkle root from a winning final state. An empty table is no offer.
function handlers.prove_output(player)
    compute_epoch_results(player)
    local result = player.output_result
    if not result.output then
        return {}
    end
    return result
end

-- A player reads the epoch inputs and geometry off the dapp contract, and finds its own
-- snapshot of the initial machine stored under the contract's initial state hash.
local function new_player(label, dapp_contract, machine_cache)
    local geometry = dapp_contract.geometry
    local bundles_per_input = geometry.periods_per_input >> LOG2_MCYCLE_BUNDLE
    local player = {
        label = label,
        inputs = dapp_contract.inputs,
        geometry = geometry,
        bundles_per_input = bundles_per_input,
        mcycle_bundles = bundles_per_input << cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH,
        initial_state_hash = dapp_contract.initial_state_hash,
        machine_cache = machine_cache or new_machine_cache(dapp_contract.initial_state_hash),
        make_mcycle_tree = function(self)
            return new_tree(
                self.geometry.mcycle_height,
                LOG2_MCYCLE_BUNDLE,
                build_mcycle_claim(self),
                function(_, bundle)
                    return refine_mcycle_claim(self, bundle)
                end
            )
        end,
        make_uarch_tree = function(self, input_index, period_index)
            return new_tree(
                self.geometry.uarch_height,
                LOG2_UARCH_BUNDLE,
                build_uarch_claim(self, input_index, period_index),
                function(_, bundle)
                    return refine_uarch_claim(self, input_index, period_index, bundle)
                end
            )
        end,
    }
    for name, handler in pairs(handlers) do
        player[name] = handler
    end
    return player
end

--------------------------------------------------------------------------------
-- Player roles
--------------------------------------------------------------------------------

-- The honest player uses the common claim builders and handlers unchanged.
local function new_honest(dapp_contract, machine_cache)
    return new_player("honest", dapp_contract, machine_cache)
end

-- The quitter posts a claim fabricated out of thin air, every leaf the same made-up state hash,
-- and walks away: it closes its connection right after joining, so the first event about
-- its claim finds no holder and eliminates it. The claim is one repeated leaf, so it never
-- needs a machine, and it reads nothing off the contract but the geometry.
local function new_quitter(dapp_contract, machine_cache)
    local player = new_player("quitter", dapp_contract, machine_cache)
    player.make_mcycle_tree = function(self)
        local outer = hash_tree.frontier_forest(self.geometry.mcycle_height, "keccak256")
        hash_tree.frontier_forest_pad_back(outer, keccak("quitter"), 1 << self.geometry.mcycle_height)
        return new_tree(self.geometry.mcycle_height, 0, outer, nil)
    end
    player.commit_mcycle_claim = function(self)
        self.done = true
        return handlers.commit_mcycle_claim(self)
    end
    return player
end

-- The forger runs the honest code over a forged input: it reads the dapp contract with the
-- epoch's input at `index` swapped for its own. Its claims are self-consistent everywhere,
-- and it defends them faithfully, but the dispute converges on the transition that includes
-- the input, and no log of feeding the forged input replays against the input the referee
-- holds.
local function new_forger(dapp_contract, index, forged_data, machine_cache)
    local player = new_player("forger", dapp_contract, machine_cache)
    player.inputs = { table.unpack(dapp_contract.inputs) }
    player.inputs[index + 1] = forged_data
    return player
end

-- The tamperer corrupts its machine mid-computation, writing over a word of RAM the guest
-- never reads, and honestly commits to the corrupted history. Every re-run repeats the
-- corruption, so its claims are self-consistent, but the true transition out of the last
-- agreed state does not lead to its next sample, and the dispute converges there.
local function new_tamperer(dapp_contract, input_index, bundle_offset, machine_cache)
    local player = new_player("tamperer", dapp_contract, machine_cache)
    player.tamper = {
        input = input_index + 1,
        bundle_offset = bundle_offset,
        apply = function(machine)
            local ram_length = machine:get_initial_config().ram.length
            machine:write_memory(cartesi.AR_RAM_START + ram_length - 8, "CORRUPT!")
        end,
    }
    return player
end

-- The fabulist computes the whole epoch honestly and then lies about a single sample: its
-- claim is the honest claim with one leaf overwritten by a made-up state hash. It can defend
-- every event with honest data, and other claims' disputes it can even settle with
-- honest proofs, but the dispute against its own claim converges on the overwritten leaf,
-- where the true reset that closes the last instruction of the span contradicts it.

-- A patched claim delegates every unaffected node and sibling to the honest claim tree;
-- only the patched bundle's forest and the ancestor path from its root to the claim root
-- are rebuilt.
local patched_meta = { __index = {} }

local function new_patched_tree(honest, patched_bundle, patched_forest)
    local tree = setmetatable({
        height = honest.height,
        bundle_height = honest.bundle_height,
        honest = honest,
        patched_bundle = patched_bundle,
        patched_forest = patched_forest,
        path = { [0] = hash_tree.frontier_forest_get_root_hash(patched_forest) },
    }, patched_meta)
    for level = 0, tree.height - tree.bundle_height - 1 do
        local index = patched_bundle >> level
        local height = tree.bundle_height + level
        local sibling = honest:get_node((index ~ 1) << height, height)
        local node = tree.path[level]
        tree.path[level + 1] = index & 1 == 0 and keccak(node, sibling) or keccak(sibling, node)
    end
    return tree
end

function patched_meta.__index.get_root(tree)
    return tree.path[tree.height - tree.bundle_height]
end

function patched_meta.__index.open_bundle(tree, bundle)
    if bundle ~= tree.patched_bundle then
        tree.honest:open_bundle(bundle)
    end
end

function patched_meta.__index.get_node(tree, position, height)
    if height >= tree.bundle_height then
        local level = height - tree.bundle_height
        if position >> height == tree.patched_bundle >> level then
            return tree.path[level]
        end
        return tree.honest:get_node(position, height)
    end
    if position >> tree.bundle_height == tree.patched_bundle then
        return hash_tree.frontier_forest_get_node(
            tree.patched_forest,
            position & ((1 << tree.bundle_height) - 1),
            height
        )
    end
    return tree.honest:get_node(position, height)
end

function patched_meta.__index.get_children(tree, position, height)
    local child_height = height - 1
    return tree:get_node(position, child_height), tree:get_node(position + (1 << child_height), child_height)
end

-- Inside the patched bundle, the patched forest supplies the low siblings and the honest
-- claim the high ones (an ancestor's sibling never stands on the patched path). Outside it,
-- the honest proof serves, with the siblings standing on the patched path replaced.
function patched_meta.__index.prove(tree, index)
    local bundle_height = tree.bundle_height
    local siblings
    if index >> bundle_height == tree.patched_bundle then
        siblings = hash_tree.frontier_forest_get_siblings(tree.patched_forest, index & ((1 << bundle_height) - 1), 0)
        for level = 0, tree.height - bundle_height - 1 do
            local height = bundle_height + level
            siblings[#siblings + 1] = tree.honest:get_node(((index >> height) ~ 1) << height, height)
        end
    else
        siblings = tree.honest:prove(index).sibling_hashes
        for level = 0, tree.height - bundle_height - 1 do
            if (index >> (bundle_height + level)) ~ 1 == tree.patched_bundle >> level then
                siblings[bundle_height + level + 1] = tree.path[level]
            end
        end
    end
    return {
        target_address = index,
        log2_target_size = 0,
        target_hash = tree:get_node(index, 0),
        log2_root_size = tree.height,
        root_hash = tree:get_root(),
        sibling_hashes = siblings,
    }
end

local function new_fabulist(dapp_contract, input_index, leaf_offset, machine_cache)
    local player = new_player("fabulist", dapp_contract, machine_cache)
    local fake_state_hash = keccak("fabulist")
    -- mcycle claim: the lied-about leaf's bundle, and its position within it, follow the
    -- announced period
    local function lie_bundle(self)
        local global_leaf = input_index * self.geometry.periods_per_input + leaf_offset
        return global_leaf >> LOG2_MCYCLE_BUNDLE, global_leaf & ((1 << LOG2_MCYCLE_BUNDLE) - 1)
    end
    -- the patched bundle forest holds the honest window with the one leaf overwritten
    local function refine_patched_mcycle_claim(self)
        local bundle, leaf_in_bundle = lie_bundle(self)
        local honest_bundle = refine_mcycle_claim(self, bundle)
        local leaves = {}
        for i = 1, 1 << LOG2_MCYCLE_BUNDLE do
            leaves[i] = hash_tree.frontier_forest_get_node(honest_bundle, i - 1, 0)
        end
        leaves[leaf_in_bundle + 1] = fake_state_hash
        local patched = hash_tree.frontier_forest(LOG2_MCYCLE_BUNDLE, "keccak256")
        hash_tree.frontier_forest_append(patched, leaves)
        return patched
    end
    local honest_make_mcycle_tree = player.make_mcycle_tree
    player.make_mcycle_tree = function(self)
        return new_patched_tree(honest_make_mcycle_tree(self), (lie_bundle(self)), refine_patched_mcycle_claim(self))
    end
    -- uarch claim: the period ending at the lied-about sample gets its last leaf, the reset
    -- that closes the span, overwritten the same way
    local lie_input, lie_period = input_index + 1, leaf_offset
    local function last_bundle(self)
        return (1 << (self.geometry.uarch_height - LOG2_UARCH_BUNDLE)) - 1
    end
    local function refine_patched_uarch_claim(self)
        local bundles_per_mcycle = 1 << (cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - LOG2_UARCH_BUNDLE)
        local hashes, first, last =
            collect_uarch_instruction(self, lie_input, lie_period, last_bundle(self) // bundles_per_mcycle)
        hashes[last] = fake_state_hash
        local window_start = (last_bundle(self) % bundles_per_mcycle) << LOG2_UARCH_BUNDLE
        return slice_uarch_window(hashes, first, last, window_start, 1 << LOG2_UARCH_BUNDLE)
    end
    local honest_make_uarch_tree = player.make_uarch_tree
    player.make_uarch_tree = function(self, input_index_1, period_index)
        if input_index_1 ~= lie_input or period_index ~= lie_period then
            return honest_make_uarch_tree(self, input_index_1, period_index)
        end
        return new_patched_tree(
            honest_make_uarch_tree(self, input_index_1, period_index),
            last_bundle(self),
            refine_patched_uarch_claim(self)
        )
    end
    return player
end

M.new_honest = new_honest
M.new_quitter = new_quitter
M.new_forger = new_forger
M.new_tamperer = new_tamperer
M.new_fabulist = new_fabulist
M.new_machine_cache = new_machine_cache

return M
