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

-- The root of a complete subtree whose leaves are all the same state hash.
local function repeat_state_hash(state_hash, height)
    for _ = 1, height do
        state_hash = keccak(state_hash, state_hash)
    end
    return state_hash
end

-- Loads the initial machine snapshot from content-addressed local storage on its own freshly
-- spawned server, and verifies that the stored machine actually has the requested state hash.
local function load_remote_machine(initial_state_hash)
    local server = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    server:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    local machine = server(cartesi.tohex(initial_state_hash))
    assert(machine:get_root_hash() == initial_state_hash, "initial machine snapshot hash mismatch")
    return machine
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

--------------------------------------------------------------------------------
-- Player: building the mcycle claim
--
-- The player advances the whole epoch once, collecting the machine state hash every period
-- as bundle roots, one per 2^LOG2_MCYCLE_BUNDLE samples. A machine stopped at a
-- manual yield, halt, or mcycle overflow repeats its state hash to the end of its input's span, and
-- the machine pads the stream accordingly, so each input contributes a short prefix of real bundles
-- followed by one enormous repetition. The player keeps a fork at each input boundary, which
-- anchors every later re-run: refining a bundle, building a uarch claim, or producing the
-- disputed transition's logs.
--------------------------------------------------------------------------------

-- Advances a machine standing at input index's boundary through the feed (when the epoch
-- has an input there) and on to `offset` mcycles past the post-feed boundary. A player
-- whose `tamper` hook names this input and an offset on the way corrupts the machine there,
-- so every re-run repeats the corrupted history. The tamper offset is bundle-aligned, so
-- collection windows never straddle it. Returns the boundary mcycle.
local function advance_fork(player, machine, index, offset)
    local data = player.inputs[index]
    if data then
        local revert_state_hash = machine:get_root_hash()
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_state_hash)
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
    return base
end

-- Adds a collection's bundle roots to one reserved segment of the claim. As in cartesi-machine's
-- computation-hash builder, roots beyond the segment capacity are ignored, and the final root
-- returned at a fixed point fills every position that remains. The only difference is the sink:
-- PRT appends to a frontier forest, which retains the nodes a later match walk needs, while
-- cartesi-machine appends to a plain frontier.
local function push_mcycle_collection(collection, collected)
    local count = math.min(#collected.hashes, collection.capacity - collection.count)
    hash_tree.frontier_forest_append(collection.forest, collected.hashes, 1, count)
    if count > 0 then
        collection.last_bundle = collected.hashes[count]
    end
    collection.count = collection.count + count
    if not is_at_fixed_point(collected.break_reason) then
        return
    end
    assert(#collected.hashes > 0, "fixed-point mcycle collection has no final bundle")
    collection.pad_bundle = collected.hashes[#collected.hashes]
    hash_tree.frontier_forest_pad_back(collection.forest, collection.pad_bundle, collection.capacity - collection.count)
    collection.count = collection.capacity
end

local function new_mcycle_collection(player, machine, forest, capacity, log2_bundle)
    return {
        machine = machine,
        forest = forest,
        capacity = capacity,
        count = 0,
        mcycle_phase = 0,
        log2_mcycles_per_period = player.geometry.log2_mcycles_per_period,
        log2_bundle = log2_bundle,
    }
end

-- Collects into one claim segment up to mcycle_end. The phase and partial bundle live in the
-- segment, so a tamper split and automatic yields continue the same sampling stream.
local function collect_mcycle_bundles(collection, mcycle_end)
    local collected
    repeat
        collected = collection.machine:collect_mcycle_root_hashes(
            mcycle_end,
            collection.log2_mcycles_per_period,
            collection.mcycle_phase,
            collection.log2_bundle,
            collection.partial_bundle
        )
        push_mcycle_collection(collection, collected)
        collection.mcycle_phase = collected.mcycle_phase
        collection.partial_bundle = collected.partial_bundle
        if collected.break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            collection.machine:receive_cmio_request()
        end
    until collected.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
        or collection.count == collection.capacity
    return collected.break_reason
end

-- Builds the mcycle claim's outer forest by advancing the epoch. Each input is fed and
-- collected until its fixed point (splitting the collection at the player's tamper point,
-- where the machine is corrupted mid-flight), then padded to its full span with its last
-- bundle, the all-repetition bundle the machine emits at the stop. A rejecting machine
-- trades places with a fresh fork of its boundary, the recorded revert state, exactly as a
-- Cartesi Node rolls back.
-- docs:begin build_mcycle_claim
local function build_mcycle_claim(player)
    local machine = load_remote_machine(player.initial_state_hash)
    local outer = hash_tree.frontier_forest(player.geometry.mcycle_height - LOG2_MCYCLE_BUNDLE, "keccak256")
    local filled = 0
    local initial_state_hash = machine:get_root_hash()
    local epoch_pad_bundle = repeat_state_hash(initial_state_hash, LOG2_MCYCLE_BUNDLE)
    player.fixed_state_hashes[0] = initial_state_hash
    for index, data in ipairs(player.inputs) do
        player.boundaries[index] = assert(machine:fork_server())
        local revert_state_hash = machine:get_root_hash()
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_state_hash)
        local base = machine:read_reg("mcycle")
        local collection = new_mcycle_collection(player, machine, outer, player.bundles_per_input, LOG2_MCYCLE_BUNDLE)
        local tamper = player.tamper
        if tamper and tamper.input == index then
            local break_reason = collect_mcycle_bundles(collection, base + tamper_offset(player))
            assert(not is_at_fixed_point(break_reason), "the machine stopped before the tamper point")
            tamper.apply(machine)
        end
        collect_mcycle_bundles(collection, base + (1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE))
        assert(collection.count == collection.capacity, "mcycle computation hash input is incomplete")
        epoch_pad_bundle = collection.pad_bundle or collection.last_bundle
        filled = filled + player.bundles_per_input
        local _, reason = machine:receive_cmio_request()
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            player.fixed_state_hashes[index] = player.boundaries[index]:get_root_hash()
            machine:shutdown_server()
            machine:swap(assert(player.boundaries[index]:fork_server()))
        else
            player.fixed_state_hashes[index] = machine:get_root_hash()
        end
    end
    -- the rest of the epoch repeats the last input's fixed point
    hash_tree.frontier_forest_pad_back(outer, epoch_pad_bundle, player.mcycle_bundles - filled)
    player.epoch_machine = machine
    return outer
end
-- docs:end build_mcycle_claim

-- Forks the boundary of a posted input, or the final fixed-point machine for an epoch-tail
-- input that does not exist. The latter also covers an empty epoch.
local function fork_input_boundary(player, input_index)
    local boundary = player.boundaries[input_index]
    if not boundary then
        assert(input_index > #player.inputs, "missing posted input boundary")
        boundary = assert(player.epoch_machine, "mcycle claim has not been built")
    end
    return assert(boundary:fork_server())
end

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
    if input_index > #player.inputs then -- epoch tail: repetitions of the last fixed point
        hash_tree.frontier_forest_pad_back(bundle_forest, player.fixed_state_hashes[#player.inputs], bundle_size)
        return bundle_forest
    end
    local window_start = (bundle % player.bundles_per_input) * bundle_size * player.geometry.mcycles_per_period
    local machine <close> = fork_input_boundary(player, input_index)
    local base = advance_fork(player, machine, input_index, window_start)
    local collection = new_mcycle_collection(player, machine, bundle_forest, bundle_size, 0)
    collect_mcycle_bundles(collection, base + window_start + bundle_size * player.geometry.mcycles_per_period)
    assert(collection.count == collection.capacity, "mcycle refinement did not fill its bundle")
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
    local machine <close> = fork_input_boundary(player, input_index)
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
    local machine <close> = fork_input_boundary(player, input_index)
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
-- the last leaf.
local function make_claim(tree)
    local computation_hash_left, computation_hash_right = tree:get_children(tree.height, 0)
    return {
        computation_hash_left = computation_hash_left,
        computation_hash_right = computation_hash_right,
        final_state_hash_proof = tree:prove((1 << tree.height) - 1),
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
-- (height, node_index), and the children of the node the walk descends into.
function handlers.reveal_bisection(player, computation_hash, height, node_index, other_left_node)
    assert(height > 1)
    local tree = get_claim_tree(player, computation_hash)
    local turn_left_node, turn_right_node = tree:get_children(height, node_index)
    local descend_left = turn_left_node ~= other_left_node
    local child_index = descend_left and 2 * node_index or 2 * node_index + 1
    local turn_next_left_node, turn_next_right_node = tree:get_children(height - 1, child_index)
    return {
        turn_left_node = turn_left_node,
        turn_right_node = turn_right_node,
        turn_next_left_node = turn_next_left_node,
        turn_next_right_node = turn_next_right_node,
    }
end

-- Seals the leftmost divergence: exposes the final leaves and proves the agreed state
-- immediately before them, except at state zero where the referee already knows that state.
function handlers.seal_divergence(player, computation_hash, node_index, other_left_node)
    local tree = get_claim_tree(player, computation_hash)
    local turn_left_node, turn_right_node = tree:get_children(1, node_index)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= other_left_node
    local state_index = 2 * node_index + (descend_left and 0 or 1)
    if state_index ~= 0 then
        response.agreed_state_hash_proof = tree:prove(state_index - 1)
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
    local machine <close> = fork_input_boundary(player, input_index + 1)
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

-- The epoch result first proves the outputs Merkle root against the final state a claim commits
-- to. The player re-runs the whole epoch on a fresh machine, adding each accepted input's outputs
-- to the outputs Merkle tree frontier, checking it against the root the guest reports, and keeping
-- the accepting state's tx-buffer word proof, which ties that root into the state hash. A rejected
-- input reverts to the pre-feed snapshot, exactly as a Cartesi Node rolls back. When the epoch has
-- an output, the same response may also offer its index, value, and proof against that root.
-- docs:begin prove_outputs_merkle_root
function handlers.prove_outputs_merkle_root(player)
    if player.result then
        return player.result
    end
    local machine = load_remote_machine(player.initial_state_hash)
    local genesis_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local frontier = hash_tree.frontier_copy(genesis_frontier)
    local outputs, leaves = {}, {}
    local state_hash_proof = machine:get_proof(cartesi.AR_CMIO_TX_BUFFER_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
    for _, data in ipairs(player.inputs) do
        local snapshot = assert(machine:fork_server())
        local sink = {}
        local revert_state_hash = machine:get_root_hash()
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_state_hash)
        run_to(machine, math.maxinteger, sink)
        local _, reason, reported_root = machine:receive_cmio_request()
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            for _, output in ipairs(sink) do
                outputs[#outputs + 1] = output
                leaves[#leaves + 1] = keccak(output)
                hash_tree.frontier_push_back(frontier, leaves[#leaves])
            end
            assert(hash_tree.frontier_get_root_hash(frontier) == reported_root, "outputs Merkle root mismatch")
            state_hash_proof = machine:get_proof(cartesi.AR_CMIO_TX_BUFFER_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
        else
            machine:shutdown_server()
            machine:swap(assert(snapshot:fork_server()))
        end
        snapshot:shutdown_server()
    end
    machine:shutdown_server()
    local output_index = #outputs - 1
    player.result = {
        outputs_merkle_root = hash_tree.frontier_get_root_hash(frontier),
        outputs_merkle_root_proof = state_hash_proof,
        output_index = output_index >= 0 and output_index or nil,
        output = outputs[#outputs],
        output_proof = hash_tree.frontier_next_proofs(genesis_frontier, leaves)[#leaves],
    }
    return player.result
end
-- docs:end prove_outputs_merkle_root

-- Offers the last output, when there is one, after the referee has established the outputs
-- Merkle root from a winning final state. An empty table is no offer.
function handlers.prove_output(player)
    local result = handlers.prove_outputs_merkle_root(player)
    if not result.output then
        return {}
    end
    return {
        output_index = result.output_index,
        output = result.output,
        output_proof = result.output_proof,
    }
end

-- A player reads the epoch inputs and geometry off the dapp contract, and finds its own
-- snapshot of the initial machine stored under the contract's initial state hash.
local function new_player(label, dapp_contract)
    local geometry = dapp_contract.geometry
    local bundles_per_input = geometry.periods_per_input >> LOG2_MCYCLE_BUNDLE
    local player = {
        label = label,
        inputs = dapp_contract.inputs,
        geometry = geometry,
        bundles_per_input = bundles_per_input,
        mcycle_bundles = bundles_per_input << cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH,
        initial_state_hash = dapp_contract.initial_state_hash,
        boundaries = {},
        fixed_state_hashes = {},
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
local function new_honest(dapp_contract)
    return new_player("honest", dapp_contract)
end

-- The quitter posts a claim fabricated out of thin air, every leaf the same made-up state hash,
-- and walks away: it closes its connection right after joining, so the first event about
-- its claim finds no holder and eliminates it. The claim is one repeated leaf, so it never
-- needs a machine, and it reads nothing off the contract but the geometry.
local function new_quitter(dapp_contract)
    local player = new_player("quitter", dapp_contract)
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
local function new_forger(dapp_contract, index, forged_data)
    local player = new_player("forger", dapp_contract)
    player.inputs = { table.unpack(dapp_contract.inputs) }
    player.inputs[index + 1] = forged_data
    return player
end

-- The tamperer corrupts its machine mid-computation, writing over a word of RAM the guest
-- never reads, and honestly commits to the corrupted history. Every re-run repeats the
-- corruption, so its claims are self-consistent, but the true transition out of the last
-- agreed state does not lead to its next sample, and the dispute converges there.
local function new_tamperer(dapp_contract, input_index, bundle_offset)
    local player = new_player("tamperer", dapp_contract)
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
        local sibling = honest:get_node(tree.bundle_height + level, index ~ 1)
        local node = tree.path[level]
        tree.path[level + 1] = index & 1 == 0 and keccak(node, sibling) or keccak(sibling, node)
    end
    return tree
end

function patched_meta.__index.get_root(tree)
    return tree.path[tree.height - tree.bundle_height]
end

function patched_meta.__index.get_node(tree, h, q)
    if h >= tree.bundle_height then
        local level = h - tree.bundle_height
        if q == tree.patched_bundle >> level then
            return tree.path[level]
        end
        return tree.honest:get_node(h, q)
    end
    local span = tree.bundle_height - h
    if q >> span == tree.patched_bundle then
        return hash_tree.frontier_forest_get_node(tree.patched_forest, q & ((1 << span) - 1), h)
    end
    return tree.honest:get_node(h, q)
end

function patched_meta.__index.get_children(tree, h, q)
    return tree:get_node(h - 1, 2 * q), tree:get_node(h - 1, 2 * q + 1)
end

-- Inside the patched bundle, the patched forest supplies the low siblings and the honest
-- claim the high ones (an ancestor's sibling never stands on the patched path). Outside it,
-- the honest proof serves, with the siblings standing on the patched path replaced.
function patched_meta.__index.prove(tree, index)
    local bundle_height = tree.bundle_height
    local siblings
    if index >> bundle_height == tree.patched_bundle then
        siblings = hash_tree.frontier_forest_get_siblings(tree.patched_forest, index & ((1 << bundle_height) - 1))
        for level = 0, tree.height - bundle_height - 1 do
            siblings[#siblings + 1] =
                tree.honest:get_node(bundle_height + level, (index >> (bundle_height + level)) ~ 1)
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
        target_hash = tree:get_node(0, index),
        log2_root_size = tree.height,
        root_hash = tree:get_root(),
        sibling_hashes = siblings,
    }
end

local function new_fabulist(dapp_contract, input_index, leaf_offset)
    local player = new_player("fabulist", dapp_contract)
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

return M
