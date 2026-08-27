-- The player side of the PRT game: the machines, the claim builds, the operations the
-- referee invokes, and the dishonest strategies. The whole geometry follows from the
-- log2 of the mcycle period, so the module is configured with it before use, and publishes
-- the geometry along with the player constructors so the referee shares the same numbers.

local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local hash_tree = require("cartesi.hash-tree")
local prtu = require("prtu")

local keccak = cartesi.keccak256
local short_hash = prtu.short_hash
local push_run, slice_runs = prtu.push_run, prtu.slice_runs
local new_tree = prtu.new_tree

-- The request and response schemas this game adds to the shared dictionary.
prtu.SCHEMA_DICT.JoinRequest = { items = {} }
prtu.SCHEMA_DICT.JoinResponse = {
    left = "Base64",
    right = "Base64",
    proof = "Proof",
}
prtu.SCHEMA_DICT.AdvanceRequest = { items = { "Base64", "Default", "Default", "Base64" } }
prtu.SCHEMA_DICT.AdvanceResponse = { l = "Base64", r = "Base64", nl = "Base64", nr = "Base64" }
prtu.SCHEMA_DICT.ProveRequest = { items = { "Base64", "Default" } }
prtu.SCHEMA_DICT.ProveResponse = "Proof"
prtu.SCHEMA_DICT.CommitUarchClaimRequest = {
    items = { "Default", "Default", "Base64", "Base64" },
}
prtu.SCHEMA_DICT.CommitUarchClaimResponse = "JoinResponse"
prtu.SCHEMA_DICT.TransitionLogsRequest = { items = { "Default", "Default", "Default" } }
prtu.SCHEMA_DICT.TransitionLogsResponse = {
    send_cmio_log = "AccessLog",
    step_log = "AccessLog",
    reset_log = "AccessLog",
}
-- The epoch result: an output, its proof in the outputs Merkle tree, and the proof tying that
-- tree's root into the winning final state.
prtu.SCHEMA_DICT.ProveResultRequest = { items = {} }
prtu.SCHEMA_DICT.ProveResultResponse = {
    output = "Base64",
    output_proof = "Proof",
    outputs_merkle_root_proof = "Proof",
}
prtu.SCHEMA_DICT.FinishRequest = { items = {} }
prtu.SCHEMA_DICT.FinishResponse = "Default"

local OPERATIONS = {
    join = prtu.operation("join", "JoinRequest", "JoinResponse"),
    advance = prtu.operation("advance", "AdvanceRequest", "AdvanceResponse"),
    prove = prtu.operation("prove", "ProveRequest", "ProveResponse"),
    commit_uarch_claim = prtu.operation("commit_uarch_claim", "CommitUarchClaimRequest", "CommitUarchClaimResponse"),
    transition_logs = prtu.operation("transition_logs", "TransitionLogsRequest", "TransitionLogsResponse"),
    prove_result = prtu.operation("prove_result", "ProveResultRequest", "ProveResultResponse"),
    finish = prtu.operation("finish", "FinishRequest", "FinishResponse"),
}

local function stderrf(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local TEMPLATE = "rolling-calculator-template"

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

local ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
local LOG2_MCYCLE_BUNDLE = 4
local LOG2_UARCH_BUNDLE = 16

local LOG2_MCYCLES_PER_PERIOD, MCYCLES_PER_PERIOD, UARCH_CYCLES_PER_MCYCLE
local MCYCLE_HEIGHT, UARCH_HEIGHT, PERIODS_PER_INPUT, ENTRIES_PER_INPUT, MCYCLE_ENTRIES

-- Fixes the geometry from the log2 of the mcycle period, before any player is built. The
-- referee reads the same numbers back from the module table.
local M = {}
function M.configure(log2_mcycles_per_period)
    LOG2_MCYCLES_PER_PERIOD = log2_mcycles_per_period
    MCYCLES_PER_PERIOD = 1 << LOG2_MCYCLES_PER_PERIOD
    UARCH_CYCLES_PER_MCYCLE = 1 << ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    assert(UARCH_CYCLES_PER_MCYCLE - 1 == cartesi.UARCH_CYCLE_MAX, "uarch cycles per mcycle do not match the emulator")

    MCYCLE_HEIGHT = ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
        + ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
        - LOG2_MCYCLES_PER_PERIOD
    UARCH_HEIGHT = LOG2_MCYCLES_PER_PERIOD + ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    PERIODS_PER_INPUT = 1 << (ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - LOG2_MCYCLES_PER_PERIOD)
    ENTRIES_PER_INPUT = PERIODS_PER_INPUT >> LOG2_MCYCLE_BUNDLE
    MCYCLE_ENTRIES = ENTRIES_PER_INPUT << ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
    M.MCYCLE_HEIGHT, M.UARCH_HEIGHT = MCYCLE_HEIGHT, UARCH_HEIGHT
    M.PERIODS_PER_INPUT, M.UARCH_CYCLES_PER_MCYCLE = PERIODS_PER_INPUT, UARCH_CYCLES_PER_MCYCLE
end

-- A machine stopped at a manual yield, halt, or mcycle overflow no longer advances on its own.
local function is_at_fixed_point(break_reason)
    return break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY
        or break_reason == cartesi.BREAK_REASON_HALTED
        or break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW
end

-- Instantiates the rolling calculator template on its own freshly spawned server. The
-- template is stored at its first manual yield, standing ready for the epoch's first input.
local function new_remote_machine()
    local server = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    server:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    return server(TEMPLATE)
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
-- as bundle roots, one entry per 2^LOG2_MCYCLE_BUNDLE samples. A machine stopped at a
-- manual yield, halt, or mcycle overflow repeats its hash to the end of its input's span, and
-- the machine pads the stream accordingly, so each input contributes a short prefix of real entries
-- followed by one enormous run. The player keeps a fork at each input boundary, which
-- anchors every later re-run: refining an entry, building a uarch claim, or producing the
-- disputed transition's logs.
--------------------------------------------------------------------------------

-- Advances a machine standing at input index's boundary through the feed (when the epoch
-- has an input there) and on to `offset` mcycles past the post-feed boundary. A player
-- whose `tamper` hook names this input and an offset on the way corrupts the machine there,
-- so every re-run repeats the corrupted history. The tamper offset is entry-aligned, so
-- collection windows never straddle it. Returns the boundary mcycle.
local function advance_fork(player, machine, index, offset)
    local data = player.inputs[index]
    if data then
        local revert_root_hash = machine:get_root_hash()
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
    end
    local base = machine:read_reg("mcycle")
    local tamper = player.tamper
    if tamper and tamper.input == index and offset >= tamper.offset then
        run_to(machine, base + tamper.offset)
        if machine:read_reg("mcycle") == base + tamper.offset then
            tamper.apply(machine)
        end
    end
    run_to(machine, base + offset)
    return base
end

-- Adds a collection's entries to one reserved segment of the claim. As in cartesi-machine's
-- computation-hash builder, entries beyond the segment capacity are ignored, and the final entry
-- returned at a fixed point fills every position that remains. The only difference is the sink:
-- PRT appends run-compressed entries, while cartesi-machine appends to a Merkle frontier.
local function push_mcycle_collection(collection, collected)
    local count = math.min(#collected.hashes, collection.capacity - collection.count)
    for i = 1, count do
        push_run(collection.runs, collected.hashes[i], 1)
    end
    collection.count = collection.count + count
    if not is_at_fixed_point(collected.break_reason) then
        return
    end
    assert(#collected.hashes > 0, "fixed-point mcycle collection has no final entry")
    collection.pad_entry = collected.hashes[#collected.hashes]
    push_run(collection.runs, collection.pad_entry, collection.capacity - collection.count)
    collection.count = collection.capacity
end

local function new_mcycle_collection(machine, runs, capacity, log2_bundle)
    return {
        machine = machine,
        runs = runs,
        capacity = capacity,
        count = 0,
        mcycle_phase = 0,
        log2_bundle = log2_bundle,
    }
end

-- Collects into one claim segment up to mcycle_end. The phase and partial bundle live in the
-- segment, so a tamper split and automatic yields continue the same sampling stream.
local function collect_mcycle_entries(collection, mcycle_end)
    local collected
    repeat
        collected = collection.machine:collect_mcycle_root_hashes(
            mcycle_end,
            LOG2_MCYCLES_PER_PERIOD,
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

-- Builds the mcycle runs by advancing the epoch. Each input is fed and collected until its
-- fixed point (splitting the collection at the player's tamper point, where the machine is
-- corrupted mid-flight), then padded to its full span with its last entry, the all-repetition
-- bundle the machine emits at the stop. A rejecting machine trades places with a fresh fork
-- of its boundary, the recorded revert state, exactly as a Cartesi Node rolls back.
-- docs:begin build_mcycle_claim
local function build_mcycle_claim(player)
    local machine = new_remote_machine()
    local runs = {}
    local filled = 0
    local epoch_pad_entry
    for index, data in ipairs(player.inputs) do
        player.boundaries[index] = assert(machine:fork_server())
        local revert_root_hash = machine:get_root_hash()
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
        local base = machine:read_reg("mcycle")
        local collection = new_mcycle_collection(machine, runs, ENTRIES_PER_INPUT, LOG2_MCYCLE_BUNDLE)
        local tamper = player.tamper
        if tamper and tamper.input == index then
            local break_reason = collect_mcycle_entries(collection, base + tamper.offset)
            assert(not is_at_fixed_point(break_reason), "the machine stopped before the tamper point")
            tamper.apply(machine)
        end
        collect_mcycle_entries(collection, base + (1 << ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE))
        assert(collection.count == collection.capacity, "mcycle computation hash input is incomplete")
        epoch_pad_entry = collection.pad_entry or runs[#runs].hash
        filled = filled + ENTRIES_PER_INPUT
        local _, reason = machine:receive_cmio_request()
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
            player.fixed_leaves[index] = player.boundaries[index]:get_root_hash()
            machine:shutdown_server()
            machine:swap(assert(player.boundaries[index]:fork_server()))
        else
            player.fixed_leaves[index] = machine:get_root_hash()
        end
    end
    -- the rest of the epoch repeats the last input's fixed point
    push_run(runs, epoch_pad_entry, MCYCLE_ENTRIES - filled)
    player.epoch_machine = machine
    return runs
end
-- docs:end build_mcycle_claim

--------------------------------------------------------------------------------
-- Player: refining an mcycle entry
--
-- A walk that descends below a stored bundle asks the tree to refine it. The player forks
-- the input's boundary, re-runs the fork to the bundle's window, and collects the window's
-- samples unbundled. Samples past the guest's stop repeat the input's fixed leaf (the
-- reverted state hash when the input was rejected), so the window is padded with it.
--------------------------------------------------------------------------------

-- docs:begin refine_mcycle_claim
local function refine_mcycle_claim(player, entry)
    local bundle = 1 << LOG2_MCYCLE_BUNDLE
    local input_index = entry // ENTRIES_PER_INPUT + 1
    if input_index > #player.inputs then -- epoch tail: repetitions of the last fixed point
        return { { hash = player.fixed_leaves[#player.inputs], count = bundle } }
    end
    local window_start = (entry % ENTRIES_PER_INPUT) * bundle * MCYCLES_PER_PERIOD
    local machine <close> = assert(player.boundaries[input_index]:fork_server())
    local base = advance_fork(player, machine, input_index, window_start)
    local runs = {}
    local collection = new_mcycle_collection(machine, runs, bundle, 0)
    collect_mcycle_entries(collection, base + window_start + bundle * MCYCLES_PER_PERIOD)
    assert(collection.count == collection.capacity, "mcycle refinement did not fill its entry")
    return runs
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

-- Pushes the stream entries of one instruction (entries first..last, ending at its reset
-- entry): the real bundles, the halt bundle repeated to fill the instruction's transitions,
-- and the reset bundle that closes it.
local function push_uarch_mcycle(runs, hashes, first, last, log2_bundle)
    local capacity = 1 << (ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - log2_bundle)
    local real = last - first - 1
    assert(real >= 0 and real <= capacity - 1, "too many uarch cycles in an instruction")
    for i = first, last - 2 do
        push_run(runs, hashes[i], 1)
    end
    push_run(runs, hashes[last - 1], capacity - 1 - real)
    push_run(runs, hashes[last], 1)
end

-- Adds each returned mcycle group to a uarch claim segment. A fixed-point collection ends in one
-- repeatable group; after adding it once, repeat that same group to fill the segment. This is the
-- run-compressed counterpart of cartesi-machine's uarch_cycle_computation_hash_push_collected.
local function push_uarch_collection(runs, collected, count, capacity, log2_bundle)
    local offsets = collected.mcycle_hash_offsets
    local wanted = math.min(#offsets - 1, capacity - count)
    for i = 1, wanted do
        push_uarch_mcycle(runs, collected.hashes, offsets[i], offsets[i + 1] - 1, log2_bundle)
    end
    count = count + wanted
    if count < capacity and is_at_fixed_point(collected.break_reason) then
        assert(wanted > 0, "fixed-point collection has no padding period")
        for _ = count + 1, capacity do
            push_uarch_mcycle(runs, collected.hashes, offsets[wanted], offsets[wanted + 1] - 1, log2_bundle)
        end
        count = capacity
    end
    return count
end

-- Builds the uarch runs for one mcycle period, `period_index` periods past input
-- `input_index`'s boundary. The span covering an input's first period opens with the feed,
-- whose transition also executes the first uarch step. The revert tail, captured at the
-- boundary before the feed, lets the collection cross a rejected yield inside the span.
-- docs:begin build_uarch_claim
local function build_uarch_claim(player, input_index, period_index)
    local machine <close> = assert(player.boundaries[input_index]:fork_server())
    local revert_uarch_tail = machine:collect_uarch_cycle_root_hashes(math.maxinteger, 0).hashes
    local base = advance_fork(player, machine, input_index, period_index * MCYCLES_PER_PERIOD)
    local start = base + period_index * MCYCLES_PER_PERIOD
    local runs = {}
    local mcycles = 0
    while mcycles < MCYCLES_PER_PERIOD do
        local collected =
            machine:collect_uarch_cycle_root_hashes(start + MCYCLES_PER_PERIOD, LOG2_UARCH_BUNDLE, revert_uarch_tail)
        mcycles = push_uarch_collection(runs, collected, mcycles, MCYCLES_PER_PERIOD, LOG2_UARCH_BUNDLE)
        if collected.break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            machine:receive_cmio_request()
        end
    end
    return runs
end
-- docs:end build_uarch_claim

-- Refines one uarch entry: positions a fork at the entry's instruction, collects that
-- single instruction's uarch cycles unbundled, expands them into the instruction's
-- 2^ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE transitions, and slices the entry's window. A
-- fork that stops before the instruction stands at the span's fixed point, whose no-op period
-- expands the same way.
-- docs:begin refine_uarch_claim
local function refine_uarch_claim(player, input_index, period_index, entry)
    local bundle = 1 << LOG2_UARCH_BUNDLE
    local entries_per_mcycle = UARCH_CYCLES_PER_MCYCLE >> LOG2_UARCH_BUNDLE
    local mcycle_offset = entry // entries_per_mcycle
    local window_start = (entry % entries_per_mcycle) * bundle
    local machine <close> = assert(player.boundaries[input_index]:fork_server())
    local revert_uarch_tail = machine:collect_uarch_cycle_root_hashes(math.maxinteger, 0).hashes
    local base = advance_fork(player, machine, input_index, period_index * MCYCLES_PER_PERIOD + mcycle_offset)
    local target = base + period_index * MCYCLES_PER_PERIOD + mcycle_offset
    local mcycle_end = math.min(target + 1, machine:read_reg("mcycle") + 1)
    local collected = machine:collect_uarch_cycle_root_hashes(mcycle_end, 0, revert_uarch_tail)
    local runs = {}
    assert(push_uarch_collection(runs, collected, 0, 1, 0) == 1, "uarch collection returned no mcycle period")
    return slice_runs(runs, window_start, bundle)
end
-- docs:end refine_uarch_claim

--------------------------------------------------------------------------------
-- Player: operations
--
-- The handlers below are the operations the referee invokes. Each returns the value to
-- answer with. A player follows one claim lineage: its mcycle claim, and, while that claim's
-- match is suspended in a uarch tournament, the uarch claim it committed there. The referee
-- only asks a player about claims it holds, so a request about any other claim is a bug, and
-- the player dies on it.
--------------------------------------------------------------------------------

local ops = {}

-- The claim in the player's lineage with the given root.
local function held(player, root)
    for _, tree in ipairs({ player.mcycle_claim, player.uarch_claim }) do
        if tree:root() == root then
            return tree
        end
    end
    error("asked about a claim this player does not hold: " .. short_hash(root))
end

-- The witness for joining with a claim: the root's two children and the standard proof of its
-- final state, the last leaf.
local function join_witness(tree)
    local left, right = tree:children(tree.height, 0)
    return { left = left, right = right, proof = tree:prove((1 << tree.height) - 1) }
end

-- The opening commitment: the player's mcycle claim. The player announces its root, so a
-- transcript can be read against the players, without the referee ever narrating who holds
-- what.
function ops.join(player)
    stderrf("%s: building mcycle claim\n", player.label)
    player.mcycle_claim = player.make_mcycle_tree(player)
    local witness = join_witness(player.mcycle_claim)
    stderrf(
        "%s: posted claim %s with final state %s\n",
        player.label,
        short_hash(player.mcycle_claim:root()),
        short_hash(witness.proof.target_hash)
    )
    return witness
end

-- One alternating step of the walk down a claim: opens the claim's node at (h, index),
-- returning its two children l and r, and, above the leaves, the two children nl and nr of
-- the child the walk descends into. The descent goes left when l differs from the opponent's
-- exposed left child, which the referee passes as opp_left.
function ops.advance(player, root, height, index, opponent_left)
    local tree = held(player, root)
    local l, r = tree:children(height, index)
    local move = { l = l, r = r }
    if height > 1 then
        local descend_left = l ~= opponent_left
        local child_index = descend_left and 2 * index or 2 * index + 1
        move.nl, move.nr = tree:children(height - 1, child_index)
    end
    return move
end

-- The proof of one leaf of one of the player's claims.
function ops.prove(player, root, leaf_index)
    return held(player, root):prove(leaf_index)
end

-- Joins the uarch tournament over one mcycle period that the player's mcycle claim is
-- disputed in, with a uarch claim whose final state must be one of the two contested values.
-- The uarch claim becomes the nested claim of the player's lineage, replacing any earlier
-- one, since the parent match is suspended until the uarch tournament ends. The input index
-- and the period index are 0-based, as the referee counts them. A holder whose uarch claim
-- ends in neither contested value cannot defend its parent claim, and dies on the
-- contradiction.
function ops.commit_uarch_claim(player, input_index, period_index, d1, d2)
    stderrf("%s: building uarch claim for input %d, period %d\n", player.label, input_index, period_index)
    player.uarch_claim = player.make_uarch_tree(player, input_index + 1, period_index)
    local witness = join_witness(player.uarch_claim)
    local final_state = witness.proof.target_hash
    assert(
        final_state == d1 or final_state == d2,
        string.format(
            "%s: uarch final %s matches neither contested final %s nor %s",
            player.label,
            short_hash(final_state),
            short_hash(d1),
            short_hash(d2)
        )
    )
    stderrf("%s: uarch claim ready\n", player.label)
    return witness
end

-- The disputed transition's access logs, produced by positioning a fresh fork at the
-- transition and logging it, whatever claim is under dispute. The transition out of an
-- input boundary includes the input, when the epoch has one, before the first uarch step.
-- The transition closing an instruction executes one more step, by then a fixed point, and
-- the reset. Every other transition is an ordinary uarch step.
-- docs:begin transition_logs
function ops.transition_logs(player, input_index, period_index, transition_index)
    local mcycle_offset = transition_index >> ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local uarch_cycle = transition_index & (UARCH_CYCLES_PER_MCYCLE - 1)
    local machine <close> = assert(player.boundaries[input_index + 1]:fork_server())
    local data = player.inputs[input_index + 1]
    if transition_index == 0 and period_index == 0 and data then
        local revert_root_hash = machine:get_root_hash()
        local send_cmio_log =
            machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
        return { send_cmio_log = send_cmio_log, step_log = machine:log_step_uarch() }
    end
    advance_fork(player, machine, input_index + 1, period_index * MCYCLES_PER_PERIOD + mcycle_offset)
    machine:run_uarch(uarch_cycle)
    if uarch_cycle == UARCH_CYCLES_PER_MCYCLE - 1 then
        local step_log = machine:log_step_uarch()
        return { step_log = step_log, reset_log = machine:log_reset_uarch() }
    end
    return { step_log = machine:log_step_uarch() }
end
-- docs:end transition_logs

-- The epoch result, proving the epoch's output against the final state a claim commits to. The
-- player re-runs the whole epoch on a fresh machine, folding each accepted input's outputs into
-- the outputs Merkle tree frontier, checking it against the root the guest reports, and keeping
-- the accepting state's tx-buffer word proof, which ties that root into the state
-- hash. A rejected input reverts to the pre-feed snapshot, exactly as a Cartesi Node rolls back.
-- Once the epoch closes, the frontier proves the last output against the final state.
-- docs:begin prove_result
function ops.prove_result(player)
    local machine = new_remote_machine()
    local genesis_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local frontier = hash_tree.frontier_copy(genesis_frontier)
    local outputs, leaves, root_hash_proof = {}, {}, nil
    for _, data in ipairs(player.inputs) do
        local snapshot = assert(machine:fork_server())
        local sink = {}
        local revert_root_hash = machine:get_root_hash()
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
        run_to(machine, math.maxinteger, sink)
        local _, reason, reported_root = machine:receive_cmio_request()
        if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            for _, output in ipairs(sink) do
                outputs[#outputs + 1] = output
                leaves[#leaves + 1] = keccak(output)
                hash_tree.frontier_push_back(frontier, leaves[#leaves])
            end
            assert(hash_tree.frontier_get_root_hash(frontier) == reported_root, "outputs Merkle root mismatch")
            root_hash_proof = machine:get_proof(cartesi.AR_CMIO_TX_BUFFER_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
        else
            machine:shutdown_server()
            machine:swap(assert(snapshot:fork_server()))
        end
        snapshot:shutdown_server()
    end
    machine:shutdown_server()
    return {
        output = outputs[#outputs],
        output_proof = hash_tree.frontier_next_proofs(genesis_frontier, leaves)[#leaves],
        outputs_merkle_root_proof = root_hash_proof,
    }
end
-- docs:end prove_result

-- The end of the tournament releases the player.
function ops.finish(player)
    player.done = true
    return true
end

-- A player bundles the game's operations and their schemas with the machines it builds along
-- the way.
local function new_player(label, inputs)
    local player = {
        label = label,
        inputs = inputs,
        operations = OPERATIONS,
        boundaries = {},
        fixed_leaves = {},
        make_mcycle_tree = function(self)
            return new_tree(MCYCLE_HEIGHT, LOG2_MCYCLE_BUNDLE, build_mcycle_claim(self), function(_, entry)
                return refine_mcycle_claim(self, entry)
            end)
        end,
        make_uarch_tree = function(self, input_index, period_index)
            return new_tree(
                UARCH_HEIGHT,
                LOG2_UARCH_BUNDLE,
                build_uarch_claim(self, input_index, period_index),
                function(_, entry)
                    return refine_uarch_claim(self, input_index, period_index, entry)
                end
            )
        end,
    }
    for name, handler in pairs(ops) do
        player[name] = handler
    end
    return player
end

--------------------------------------------------------------------------------
-- The dishonest players
--------------------------------------------------------------------------------

-- The quitter posts a claim fabricated out of thin air, every leaf the same made-up hash,
-- and walks away: it closes its connection right after joining, so the first request about
-- its claim finds no holder and eliminates it. The claim is built straight from leaf runs, so
-- it never needs a machine, or even the inputs.
local function make_quitter(player)
    player.make_mcycle_tree = function()
        local fake = keccak("quitter")
        return new_tree(MCYCLE_HEIGHT, 0, { { hash = fake, count = 1 << MCYCLE_HEIGHT } }, nil)
    end
    player.join = function(self)
        self.done = true
        return ops.join(self)
    end
end

-- The forger runs the honest code over a forged input: it swaps the epoch's input at
-- `index` for its own. Its claims are self-consistent everywhere, and it defends them
-- faithfully, but the dispute converges on the transition that includes the input, and no
-- log of feeding the forged input replays against the input the referee holds.
local function make_forger(player, index, forged_data)
    player.inputs[index + 1] = forged_data
end

-- The tamperer corrupts its machine mid-computation, writing over a word of RAM the guest
-- never reads, and honestly commits to the corrupted history. Every re-run repeats the
-- corruption, so its claims are self-consistent, but the true transition out of the last
-- agreed state does not lead to its next sample, and the dispute converges there.
local function make_tamperer(player, input_index, entry_offset)
    player.tamper = {
        input = input_index + 1,
        offset = entry_offset << (LOG2_MCYCLE_BUNDLE + LOG2_MCYCLES_PER_PERIOD),
        apply = function(machine)
            local ram_length = machine:get_initial_config().ram.length
            machine:write_memory(cartesi.AR_RAM_START + ram_length - 8, "CORRUPT!")
        end,
    }
end

-- The fabulist computes the whole epoch honestly and then lies about a single sample: its
-- claim is the honest claim with one leaf overwritten by a made-up hash. It can defend
-- every request with honest data, and other claims' disputes it can even settle with
-- honest proofs, but the dispute against its own claim converges on the overwritten leaf,
-- where the true reset that closes the last instruction of the span contradicts it.
local function make_fabulist(player, input_index, leaf_offset)
    local fake = keccak("fabulist")
    local global_leaf = input_index * PERIODS_PER_INPUT + leaf_offset
    -- mcycle claim: splice the patched entry into the honest runs and patch its refinement
    local entry = global_leaf >> LOG2_MCYCLE_BUNDLE
    local leaf_in_entry = global_leaf & ((1 << LOG2_MCYCLE_BUNDLE) - 1)
    local function patched_refine_mcycle(self)
        local runs = slice_runs(refine_mcycle_claim(self, entry), 0, 1 << LOG2_MCYCLE_BUNDLE)
        local before = slice_runs(runs, 0, leaf_in_entry)
        push_run(before, fake, 1)
        for _, run in ipairs(slice_runs(runs, leaf_in_entry + 1, (1 << LOG2_MCYCLE_BUNDLE) - leaf_in_entry - 1)) do
            push_run(before, run.hash, run.count)
        end
        return before
    end
    player.make_mcycle_tree = function(self)
        local runs = build_mcycle_claim(self)
        local patched_entry = new_tree(LOG2_MCYCLE_BUNDLE, 0, patched_refine_mcycle(self), nil):root()
        local spliced = slice_runs(runs, 0, entry)
        push_run(spliced, patched_entry, 1)
        for _, run in ipairs(slice_runs(runs, entry + 1, MCYCLE_ENTRIES - entry - 1)) do
            push_run(spliced, run.hash, run.count)
        end
        return new_tree(MCYCLE_HEIGHT, LOG2_MCYCLE_BUNDLE, spliced, function(_, e)
            if e == entry then
                return patched_refine_mcycle(self)
            end
            return refine_mcycle_claim(self, e)
        end)
    end
    -- uarch claim: the period ending at the lied-about sample gets its last leaf patched the same way
    local lie_input, lie_period = input_index + 1, leaf_offset
    local last_entry = (1 << (UARCH_HEIGHT - LOG2_UARCH_BUNDLE)) - 1
    local last_in_entry = (1 << LOG2_UARCH_BUNDLE) - 1
    local function patched_refine_uarch(self)
        local runs = refine_uarch_claim(self, lie_input, lie_period, last_entry)
        local before = slice_runs(runs, 0, last_in_entry)
        push_run(before, fake, 1)
        return before
    end
    local honest_make_uarch_tree = player.make_uarch_tree
    player.make_uarch_tree = function(self, input_index_1, period_index)
        if input_index_1 ~= lie_input or period_index ~= lie_period then
            return honest_make_uarch_tree(self, input_index_1, period_index)
        end
        local runs = build_uarch_claim(self, lie_input, lie_period)
        local patched_entry = new_tree(LOG2_UARCH_BUNDLE, 0, patched_refine_uarch(self), nil):root()
        local total = 1 << (UARCH_HEIGHT - LOG2_UARCH_BUNDLE)
        local spliced = slice_runs(runs, 0, last_entry)
        push_run(spliced, patched_entry, 1)
        assert(#spliced > 0 and total == last_entry + 1)
        return new_tree(UARCH_HEIGHT, LOG2_UARCH_BUNDLE, spliced, function(_, e)
            if e == last_entry then
                return patched_refine_uarch(self)
            end
            return refine_uarch_claim(self, lie_input, lie_period, e)
        end)
    end
end

M.TEMPLATE = TEMPLATE
M.new_player = new_player
M.OPERATIONS = OPERATIONS
M.make_quitter = make_quitter
M.make_forger = make_forger
M.make_tamperer = make_tamperer
M.make_fabulist = make_fabulist

return M
