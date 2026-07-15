-- A model of a Permissionless Refereed Tournament (PRT) over an epoch of a Rolling Cartesi
-- Machine.
--
-- A referee, standing in for the Dave contracts on the blockchain, resolves a dispute among
-- any number of players over the epoch's history. Where the verification game bisected live,
-- PRT has each player commit upfront to a computation hash, the root of a Merkle tree of
-- machine state hashes sampled along the whole computation, and the dispute walks down the
-- two trees. Claims are what matter, not players: any player may answer any request about
-- any claim, every answer carries its own proof, and the referee takes the first answer that
-- verifies. An unanswered request eliminates the claim it was about, never a player.
--
-- The dispute has two levels, one per cycle counter. An mcycle claim commits to the machine
-- state hash every 2^p mcycles across the epoch (the mcycle computation hash of
-- cartesi-machine.lua). When two mcycle claims diverge at a leaf, each side commits to a
-- uarch claim over that one period, the state hash after every uarch transition of its 2^p
-- instructions (the uarch cycle computation hash), and the walk repeats. The uarch leaf it
-- isolates is a single state transition, settled by verifying access logs, exactly as in the
-- verification games.
--
-- Roles, selected by the first argument. Every game role takes the referee address and log2 of
-- the mcycle period, and every machine-holding role takes the epoch's input files. The referee
-- is never told how many players to expect: it gathers claims until a seal connection closes the
-- join phase. The referee sorts the claims it gathers, so the bracket and the whole narration are
-- a pure function of the claim set, not of the order in which players connect.
--   prt.lua referee  <address> <log2-period> <input> [<input> ...]
--   prt.lua honest   <address> <log2-period> <input> [<input> ...]
--   prt.lua quitter  <address> <log2-period>
--   prt.lua forger   <address> <log2-period> <index> <forged-input> <input> [<input> ...]
--   prt.lua tamperer <address> <log2-period> <input-index> <entry-offset> <input> [<input> ...]
--   prt.lua fabulist <address> <log2-period> <input-index> <leaf-offset> <input> [<input> ...]
--   prt.lua seal     <address>

local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local socket = require("socket")
local hash_tree = require("cartesi.hash-tree")
local evmu = require("cartesi.evmu")
local prtu = require("prtu")

local keccak = cartesi.keccak256
local short_hash, hex, unhex = prtu.short_hash, prtu.hex, prtu.unhex
local narrate = prtu.narrate
local push_run, slice_runs = prtu.push_run, prtu.slice_runs
local new_tree, fold_proof = prtu.new_tree, prtu.fold_proof

-- The seal role carries no dispute: it just tells a running referee that the last player has
-- connected, so the join phase closes. It needs none of the game geometry defined below.
if arg[1] == "seal" then
    return prtu.seal(assert(arg[2], "missing referee address"))
end

-- The reply schemas this game adds to the shared dictionary.
prtu.SCHEMA_DICT.Join = {
    left = "Base64",
    right = "Base64",
    final_state = "Base64",
    siblings = "Base64Array",
}
prtu.SCHEMA_DICT.Advance = { l = "Base64", r = "Base64", nl = "Base64", nr = "Base64" }
prtu.SCHEMA_DICT.LeafProof = { leaf = "Base64", siblings = "Base64Array" }
prtu.SCHEMA_DICT.Logs = {
    send_cmio_log = "AccessLog",
    step_log = "AccessLog",
    reset_log = "AccessLog",
}
-- The epoch result: an output, its proof in the outputs Merkle tree, and the proof tying that
-- tree's root into the winning final state.
prtu.SCHEMA_DICT.EpochResult = {
    output = "Base64",
    output_proof = "Proof",
    outputs_merkle_root_proof = "Proof",
}

local TEMPLATE = "rolling-calculator-template"
local NOTICE = "Notice(bytes payload)"

--------------------------------------------------------------------------------
-- Geometry
--
-- The epoch spans 2^24 inputs of 2^48 mcycles each, and every mcycle expands into 2^20
-- uarch transitions, the same three coordinates as the rolling verification game. The mcycle
-- claim samples the epoch every 2^LOG2_PERIOD mcycles. The uarch claim expands one mcycle
-- period into its uarch transitions. Each claim is stored bundled: the machine delivers one
-- subtree root per 2^bundle leaves, so the stored tree is that much shallower, and queries
-- below a bundle are answered by refining it.
--------------------------------------------------------------------------------

local ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
local LOG2_MCYCLE_BUNDLE = 4
local LOG2_UARCH_BUNDLE = 16

local LOG2_PERIOD = assert(tonumber(arg[3]), "missing log2 of the mcycle period")
local PERIOD = 1 << LOG2_PERIOD
local UARCH_SPAN = 1 << ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
assert(UARCH_SPAN - 1 == cartesi.UARCH_CYCLE_MAX, "uarch span does not match the emulator")

local MCYCLE_HEIGHT = ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH + ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - LOG2_PERIOD
local UARCH_HEIGHT = LOG2_PERIOD + ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local LEAVES_PER_INPUT = 1 << (ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - LOG2_PERIOD)
local ENTRIES_PER_INPUT = LEAVES_PER_INPUT >> LOG2_MCYCLE_BUNDLE
local MCYCLE_ENTRIES = ENTRIES_PER_INPUT << ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH

-- How long the referee waits for a join phase to gather its claims (each is a commitment
-- build). The per-move waiting during a match is the referee server's own tick timeout. Once
-- a uarch tournament's two contested finals are both covered, the referee keeps collecting
-- for a grace window, so every player that builds the same span is credited, not just the
-- first to answer, which keeps the narration a pure function of the claims.
local JOIN_SECONDS = 600
local SPAN_JOIN_SECONDS = 300
local SPAN_JOIN_GRACE = 15

local function stderrf(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- A machine stopped at a manual yield, halt, or mcycle overflow no longer advances on its own.
local function is_at_fixed_point(break_reason)
    return break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY
        or break_reason == cartesi.BREAK_REASON_HALTED
        or break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW
end

-- Reads an input, an ABI-encoded EvmAdvance blob, from a file. The referee and the players
-- all read the same bytes the blockchain posted.
local function read_input(filename)
    local file <close> = assert(io.open(filename, "rb"))
    return file:read("a")
end

-- Reads the epoch's inputs from the files on the command line, starting at `first`.
local function read_inputs(first)
    local inputs = {}
    for index = first, #arg do
        inputs[index - first + 1] = read_input(arg[index])
    end
    assert(#inputs > 0, "missing input files")
    return inputs
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
            LOG2_PERIOD,
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
    local window_start = (entry % ENTRIES_PER_INPUT) * bundle * PERIOD
    local machine <close> = assert(player.boundaries[input_index]:fork_server())
    local base = advance_fork(player, machine, input_index, window_start)
    local runs = {}
    local collection = new_mcycle_collection(machine, runs, bundle, 0)
    collect_mcycle_entries(collection, base + window_start + bundle * PERIOD)
    assert(collection.count == collection.capacity, "mcycle refinement did not fill its entry")
    return runs
end
-- docs:end refine_mcycle_claim

--------------------------------------------------------------------------------
-- Player: building a uarch claim
--
-- A uarch claim expands the mcycle period ending at the disputed leaf: the state hash
-- after every uarch transition of its 2^LOG2_PERIOD instructions, delivered as one bundle
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

-- Builds the uarch runs for the span of one mcycle period, `r` periods past input
-- `input_index`'s boundary. The span covering an input's first period opens with the feed,
-- whose transition also executes the first uarch step. The revert tail, captured at the
-- boundary before the feed, lets the collection cross a rejected yield inside the span.
-- docs:begin build_uarch_claim
local function build_uarch_claim(player, input_index, r)
    local machine <close> = assert(player.boundaries[input_index]:fork_server())
    local revert_uarch_tail = machine:collect_uarch_cycle_root_hashes(math.maxinteger, 0).hashes
    local base = advance_fork(player, machine, input_index, r * PERIOD)
    local start = base + r * PERIOD
    local runs = {}
    local mcycles = 0
    while mcycles < PERIOD do
        local collected = machine:collect_uarch_cycle_root_hashes(start + PERIOD, LOG2_UARCH_BUNDLE, revert_uarch_tail)
        mcycles = push_uarch_collection(runs, collected, mcycles, PERIOD, LOG2_UARCH_BUNDLE)
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
local function refine_uarch_claim(player, input_index, r, entry)
    local bundle = 1 << LOG2_UARCH_BUNDLE
    local entries_per_mcycle = UARCH_SPAN >> LOG2_UARCH_BUNDLE
    local mcycle_offset = entry // entries_per_mcycle
    local window_start = (entry % entries_per_mcycle) * bundle
    local machine <close> = assert(player.boundaries[input_index]:fork_server())
    local revert_uarch_tail = machine:collect_uarch_cycle_root_hashes(math.maxinteger, 0).hashes
    local base = advance_fork(player, machine, input_index, r * PERIOD + mcycle_offset)
    local target = base + r * PERIOD + mcycle_offset
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
-- The handlers below are what the referee's snippets invoke. Each returns the value to
-- answer with, or nil to stay silent. A player only answers about claims it holds, and
-- holding a claim is nothing more than having its tree registered under its root.
--------------------------------------------------------------------------------

local ops = {}

-- Registers a tree as a claim the player defends and returns its join commitment: the
-- root's two children, the final state (the last leaf), and the last leaf's proof.
local function register_claim(player, tree)
    local root = tree:root()
    player.trees[hex(root)] = tree
    local final_state, siblings = tree:prove((1 << tree.height) - 1)
    local left, right = tree:children(tree.height, 0)
    return { left = left, right = right, final_state = final_state, siblings = siblings }
end

-- The opening commitment: the player's mcycle claim, built on first use.
function ops.join(player)
    if not player.join_commitment then
        stderrf("%s: building mcycle claim\n", player.label)
        local tree = player.make_mcycle_tree(player)
        player.join_commitment = register_claim(player, tree)
        stderrf("%s: claim ready\n", player.label)
    end
    return player.join_commitment
end

-- One alternating step of the walk down a claim: opens the claim's node at (h, index),
-- returning its two children l and r, and, above the leaves, the two children nl and nr of
-- the child the walk descends into. The descent goes left when l differs from the opponent's
-- exposed left child, which the referee passes as opp_left. A player not holding the claim
-- stays silent, and the silence costs the claim nothing, since another player may hold it.
function ops.advance(player, root_hex, h, index, opp_left_hex)
    local tree = not player.mute and player.trees[root_hex]
    if not tree then
        return nil
    end
    local l, r = tree:children(h, index)
    local move = { l = l, r = r }
    if h > 1 then
        local descend_left = l ~= unhex(opp_left_hex)
        move.nl, move.nr = tree:children(h - 1, descend_left and 2 * index or 2 * index + 1)
    end
    return move
end

-- The proof of one leaf of one of the player's claims.
function ops.prove(player, root_hex, index)
    local tree = not player.mute and player.trees[root_hex]
    if not tree then
        return nil
    end
    local leaf, siblings = tree:prove(index)
    return { leaf = leaf, siblings = siblings }
end

-- Joins a uarch tournament over one mcycle period with a uarch claim, when the claim's
-- final state is one of the two the mcycle match contests. Claims are cached per span, so a
-- repeated request costs one build.
function ops.join_span(player, input, r, d1_hex, d2_hex)
    if player.mute then
        return nil
    end
    local key = string.format("%d:%d", input, r)
    local commitment = player.spans[key]
    if not commitment then
        stderrf("%s: building uarch claim for input %d, period %d\n", player.label, input, r)
        local tree = player.make_uarch_tree(player, input + 1, r)
        commitment = register_claim(player, tree)
        player.spans[key] = commitment
        stderrf("%s: uarch claim ready\n", player.label)
    end
    local final_hex = hex(commitment.final_state)
    if final_hex ~= d1_hex and final_hex ~= d2_hex then
        stderrf(
            "%s: uarch final %s matches neither contested final %s nor %s\n",
            player.label,
            short_hash(commitment.final_state),
            short_hash(unhex(d1_hex)),
            short_hash(unhex(d2_hex))
        )
        return nil
    end
    return commitment
end

-- The disputed transition's access logs, produced by positioning a fresh fork at the
-- transition and logging it, whatever claim is under dispute. The transition out of an
-- input boundary includes the input, when the epoch has one, before the first uarch step.
-- The transition closing an instruction executes one more step, by then a fixed point, and
-- the reset. Every other transition is an ordinary uarch step.
-- docs:begin transition_logs
function ops.transition_logs(player, input, r, position)
    if player.mute then
        return nil
    end
    local t_mcycle = position >> ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local t_uarch = position & (UARCH_SPAN - 1)
    local machine <close> = assert(player.boundaries[input + 1]:fork_server())
    local data = player.inputs[input + 1]
    if position == 0 and r == 0 and data then
        local revert_root_hash = machine:get_root_hash()
        local send_cmio_log =
            machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
        return { send_cmio_log = send_cmio_log, step_log = machine:log_step_uarch() }
    end
    advance_fork(player, machine, input + 1, r * PERIOD + t_mcycle)
    machine:run_uarch(t_uarch)
    if t_uarch == UARCH_SPAN - 1 then
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
    if player.mute then
        return nil
    end
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

-- A player bundles the game's operations with the machines it builds along the way. It
-- also carries a reference to itself under `player`, since it is the environment the
-- referee's snippets run in.
local function new_player(label, inputs)
    local player = {
        label = label,
        inputs = inputs,
        boundaries = {},
        fixed_leaves = {},
        trees = {},
        spans = {},
        make_mcycle_tree = function(self)
            return new_tree(MCYCLE_HEIGHT, LOG2_MCYCLE_BUNDLE, build_mcycle_claim(self), function(_, entry)
                return refine_mcycle_claim(self, entry)
            end)
        end,
        make_uarch_tree = function(self, input_index, r)
            return new_tree(UARCH_HEIGHT, LOG2_UARCH_BUNDLE, build_uarch_claim(self, input_index, r), function(_, entry)
                return refine_uarch_claim(self, input_index, r, entry)
            end)
        end,
    }
    for name, handler in pairs(ops) do
        player[name] = handler
    end
    player.player = player
    return player
end

--------------------------------------------------------------------------------
-- The dishonest players
--------------------------------------------------------------------------------

-- The quitter posts a claim fabricated out of thin air, every leaf the same made-up hash,
-- and never defends it. The fabricated tree is cheap to commit to (it is one run), but the
-- first unanswered request eliminates it. The claim is built straight from leaf runs, so it never
-- needs a machine, or even the inputs.
local function make_quitter(player)
    player.mute = true
    player.make_mcycle_tree = function()
        local fake = keccak("quitter")
        return new_tree(MCYCLE_HEIGHT, 0, { { hash = fake, count = 1 << MCYCLE_HEIGHT } }, nil)
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
        offset = entry_offset << (LOG2_MCYCLE_BUNDLE + LOG2_PERIOD),
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
    local global_leaf = input_index * LEAVES_PER_INPUT + leaf_offset
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
    -- uarch claim: the span ending at the lied-about sample gets its last leaf patched the same way
    local span_input, span_r = input_index + 1, leaf_offset
    local last_entry = (1 << (UARCH_HEIGHT - LOG2_UARCH_BUNDLE)) - 1
    local last_in_entry = (1 << LOG2_UARCH_BUNDLE) - 1
    local function patched_refine_uarch(self)
        local runs = refine_uarch_claim(self, span_input, span_r, last_entry)
        local before = slice_runs(runs, 0, last_in_entry)
        push_run(before, fake, 1)
        return before
    end
    local honest_make_uarch_tree = player.make_uarch_tree
    player.make_uarch_tree = function(self, input_index_1, r)
        if input_index_1 ~= span_input or r ~= span_r then
            return honest_make_uarch_tree(self, input_index_1, r)
        end
        local runs = build_uarch_claim(self, span_input, span_r)
        local patched_entry = new_tree(LOG2_UARCH_BUNDLE, 0, patched_refine_uarch(self), nil):root()
        local total = 1 << (UARCH_HEIGHT - LOG2_UARCH_BUNDLE)
        local spliced = slice_runs(runs, 0, last_entry)
        push_run(spliced, patched_entry, 1)
        assert(#spliced > 0 and total == last_entry + 1)
        return new_tree(UARCH_HEIGHT, LOG2_UARCH_BUNDLE, spliced, function(_, e)
            if e == last_entry then
                return patched_refine_uarch(self)
            end
            return refine_uarch_claim(self, span_input, span_r, e)
        end)
    end
end

--------------------------------------------------------------------------------
-- Referee
--
-- The referee holds only what the blockchain would: the agreed initial state hash, the
-- deployed dapp contract with the epoch's inputs, and the geometry. During a match it
-- tracks one node hash per claim as it walks the two trees down, so it stores nothing of
-- the claims but the path in dispute.
--------------------------------------------------------------------------------

-- The referee server and its coroutine dispatcher, built with the referee and shared by every
-- coroutine of its logic, and a running match counter (a match's id fixes its narration
-- priority, across mcycle and uarch tournaments alike).
local server, dispatcher
local match_count = 0

-- Validates a join commitment: the root is its two children joined, and the final state is
-- the tree's last leaf, proven by folding it up the siblings. Returns the claim.
local function validate_join(commitment, height)
    assert(#commitment.siblings == height, "join proof of the wrong height")
    local root = keccak(commitment.left, commitment.right)
    assert(
        fold_proof(commitment.final_state, (1 << height) - 1, commitment.siblings) == root,
        "join proof does not fold"
    )
    return { root = root, left = commitment.left, right = commitment.right, final_state = commitment.final_state }
end

-- The labels of a claim's defenders, sorted, for narration only.
local function labels_of(claim)
    local list = {}
    for label in pairs(claim.labels) do
        list[#list + 1] = label
    end
    table.sort(list)
    return table.concat(list, ", ")
end

-- Turns raw join replies into the distinct claims of a tournament. Each valid reply is
-- validated, kept only if `accept` allows it (a uarch tournament accepts only the two
-- contested finals), merged with the identical claim any other player posted, and its sender
-- recorded as a holder so that claim's matches notify it. Claims are sorted by root hash, so
-- the bracket is a pure function of the claim set, not of the order players connected.
local function distinct_claims(replies, height, accept)
    local claims, by_root = {}, {}
    for _, reply in ipairs(replies) do
        local ok, claim = pcall(validate_join, reply.value, height)
        if ok and (not accept or accept(claim)) then
            local root_hex = hex(claim.root)
            local existing = by_root[root_hex]
            if existing then
                existing.labels[reply.label] = true
            else
                claim.labels = { [reply.label] = true }
                by_root[root_hex] = claim
                claims[#claims + 1] = claim
            end
            server:add_holder(root_hex, reply.connection)
        end
    end
    table.sort(claims, function(a, b)
        return hex(a.root) < hex(b.root)
    end)
    return claims
end

-- Verifies the disputed transition's logs on their own, the way the Dave contracts verify
-- them on the blockchain, without ever instantiating a machine. The position picks the
-- form, as in CartesiStateTransition.sol: the transition out of an input boundary includes
-- the input the dapp contract holds (never one a player supplies), the transition closing an
-- instruction verifies a step and then the reset, and every other is an ordinary step. Each
-- verification returns the state hash its log provably advances to, and the chain starts
-- from the agreed state hash. Returns the hash the logs reach, or raises on a bad log.
-- docs:begin verify_transition
local function verify_transition(dapp_contract, span, position, agree_hash, logs)
    local machine = cartesi.machine
    local t_uarch = position & (UARCH_SPAN - 1)
    local hash = agree_hash
    local data = dapp_contract.inputs[span.input + 1]
    if position == 0 and span.r == 0 and data then
        local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
        hash = machine:verify_send_cmio_response(reason, data, hash, logs.send_cmio_log, hash)
    end
    hash = machine:verify_step_uarch(hash, logs.step_log)
    if t_uarch == UARCH_SPAN - 1 then
        hash = machine:verify_reset_uarch(hash, logs.reset_log)
    end
    return hash
end
-- docs:end verify_transition

-- The state hash both claims agree on right before the divergent leaf. When the divergence
-- is at a right leaf, it is the left leaf, exposed and agreed in the final round. When it is
-- at leaf 0, it is the tournament's initial state hash, which the referee knows. Otherwise it is
-- the leaf before the divergence, requested as a proof against either claim: the walk finds
-- the leftmost divergence, so the two trees agree at every earlier leaf, and a proof against
-- either one binds them both. A proof move proves itself, folding up to the claim's root.
local function wait_for_agreed_hash(m, tournament, position, claims)
    if position == 0 then
        return tournament.initial_hash
    end
    for _, claim in ipairs(claims) do
        local subject = string.format("m%d-agree-%d-%s", m.id, position, hex(claim.root))
        local conns = server:subscribers({ hex(claim.root) })
        local move = server:await(subject, conns, m.id, "LeafProof", function(v)
            return fold_proof(v.leaf, position - 1, v.siblings) == claim.root
        end, 'return player:prove("%s", %d)', hex(claim.root), position - 1)
        if move then
            return move.leaf
        end
    end
    return nil
end

-- Settles a uarch match once the walk isolates the divergent leaf. The
-- referee asks for the transition's logs and takes answers until one verifies against the
-- agreed state hash. The state hash the logs provably reach settles the transition: the
-- claim that committed to it wins, and a claim that committed to anything else loses.
-- Nobody proving anything by the deadline eliminates both claims.
-- docs:begin settle_uarch_match
local function settle_uarch_match(tournament, m, position, agree_hash, one, two, d1, d2)
    local tag = m.tag
    local form = "an ordinary uarch step"
    if position == 0 and tournament.span.r == 0 and tournament.dapp_contract.inputs[tournament.span.input + 1] then
        form = "the inclusion of input " .. tournament.span.input .. " and the first uarch step"
    elseif position & (UARCH_SPAN - 1) == UARCH_SPAN - 1 then
        form = "a uarch step and the uarch reset closing an instruction"
    end
    narrate(tag, "The disputed transition is %s.", form)
    -- The transition out of the agreed state is unique, so any log that verifies reaches the
    -- one true after-hash; a log that does not is malformed and closes its sender. Both claims'
    -- holders are asked, since either may supply the proof.
    local subject = string.format("m%d-logs-%d", m.id, position)
    local conns = server:subscribers({ hex(one.root), hex(two.root) })
    local move = server:await(subject, conns, m.id, "Logs", function(v)
        return (pcall(verify_transition, tournament.dapp_contract, tournament.span, position, agree_hash, v))
    end, "return player:transition_logs(%d, %d, %d)", tournament.span.input, tournament.span.r, position)
    if not move then
        narrate(tag, "No log settled the transition. Both claims are eliminated.")
        return nil
    end
    local hash = verify_transition(tournament.dapp_contract, tournament.span, position, agree_hash, move)
    narrate(tag, "The disputed transition provably leads to %s.", short_hash(hash))
    if hash == d1 then
        narrate(tag, "Claim %s committed to %s and is eliminated.", short_hash(two.root), short_hash(d2))
        return one
    elseif hash == d2 then
        narrate(tag, "Claim %s committed to %s and is eliminated.", short_hash(one.root), short_hash(d1))
        return two
    end
    narrate(tag, "Neither claim committed to it. Both are eliminated.")
    return nil
end
-- docs:end settle_uarch_match

-- Forward declaration: settling an mcycle match spawns a uarch tournament, which runs
-- matches, which settle against the machine.
local run_tournament

-- Settles an mcycle match once the walk isolates the divergent leaf: the two claims part
-- ways over what the state hash was after one period of one input. A uarch tournament
-- opens over that period. Any player may join it with a uarch claim whose final state is
-- one of the two contested values, and the uarch winner's final state names the mcycle
-- claim that survives.
-- docs:begin settle_mcycle_match
local function settle_mcycle_match(tournament, m, position, agree_hash, one, two, d1, d2)
    local tag = m.tag
    local span = { input = position // LEAVES_PER_INPUT, r = position % LEAVES_PER_INPUT }
    narrate(
        tag,
        "A uarch tournament opens over input %d, period %d, starting from %s.",
        span.input,
        span.r,
        short_hash(agree_hash)
    )
    -- Collect the uarch claims, from any player, whose final state is one of the two the
    -- mcycle match contests, until both are covered or the join window closes.
    local d1_hex, d2_hex = hex(d1), hex(d2)
    local subject = string.format("m%d-span-%d", m.id, position)
    local replies = server:collect(
        subject,
        nil,
        "Join",
        socket.gettime() + SPAN_JOIN_SECONDS,
        SPAN_JOIN_GRACE,
        function(rs)
            local seen = {}
            for _, reply in ipairs(rs) do
                local ok, claim = pcall(validate_join, reply.value, UARCH_HEIGHT)
                if ok then
                    seen[hex(claim.final_state)] = true
                else
                    stderrf("uarch claim from %s failed validation: %s\n", reply.label, tostring(claim))
                end
            end
            return seen[d1_hex] and seen[d2_hex]
        end,
        'return player:join_span(%d, %d, "%s", "%s")',
        span.input,
        span.r,
        d1_hex,
        d2_hex
    )
    local claims = distinct_claims(replies, UARCH_HEIGHT, function(claim)
        return claim.final_state == d1 or claim.final_state == d2
    end)
    for _, claim in ipairs(claims) do
        narrate(
            tag,
            "Claim %s, with final state %s, joined the uarch tournament (defended by %s).",
            short_hash(claim.root),
            short_hash(claim.final_state),
            labels_of(claim)
        )
    end
    local uarch_tournament = {
        level = "uarch",
        height = UARCH_HEIGHT,
        initial_hash = agree_hash,
        dapp_contract = tournament.dapp_contract,
        span = span,
        settle = settle_uarch_match,
    }
    local winner = run_tournament(uarch_tournament, claims)
    if not winner then
        narrate(tag, "The uarch tournament had no winner. Both claims are eliminated.")
        return nil
    end
    if winner.final_state == d1 then
        narrate(tag, "The uarch winner confirms %s. Claim %s is eliminated.", short_hash(d1), short_hash(two.root))
        return one
    end
    narrate(tag, "The uarch winner confirms %s. Claim %s is eliminated.", short_hash(d2), short_hash(one.root))
    return two
end
-- docs:end settle_mcycle_match

-- Runs one match to its end and returns the winning claim, or nil when both die. The two
-- claims alternate down their trees, one move per round, exactly as in Dave's Match.sol: the
-- referee holds one node to open (`other_parent`) and the opponent's standing left and right
-- children, and the on-turn claim opens its node, exposing the two children and, above the
-- leaves, the two grandchildren of the side the walk descends into. The walk follows the side
-- where the claims first disagree, converging on the leftmost divergent leaf, and the turn
-- passes to the opponent each round. A claim whose move nobody supplies before the timeout is
-- eliminated. At height 1 the exposed children are leaves, and the tournament's settle decides.
-- docs:begin run_match
local function run_match(tournament, one, two, roundno, id)
    local m = { id = id, tag = "match_" .. id }
    narrate(
        "tournament",
        "Round %d, match %d, at the %s level: claim %s (%s) against claim %s (%s).",
        roundno,
        m.id,
        tournament.level,
        short_hash(one.root),
        labels_of(one),
        short_hash(two.root),
        labels_of(two)
    )
    -- Commitment one opens first, so the match starts with one's root as the node to open and
    -- two's join-exposed root children standing, exactly the seeding of Match.sol.
    local other_parent, left_node, right_node = one.root, two.left, two.right
    local height, index = tournament.height, 0
    local turn, other = one, two -- turn holds the claim whose node is other_parent
    while true do
        local subject = string.format("m%d-h%d", m.id, height)
        local conns = server:subscribers({ hex(turn.root) })
        local move = server:await(subject, conns, m.id, "Advance", function(v)
            if keccak(v.l, v.r) ~= other_parent then
                return false
            end
            if height > 1 then
                return keccak(v.nl, v.nr) == ((v.l ~= left_node) and v.l or v.r)
            end
            return true
        end, 'return player:advance("%s", %d, %d, "%s")', hex(turn.root), height, index, hex(left_node))
        if not move then
            narrate(
                m.tag,
                "Claim %s went unanswered. Claim %s wins by timeout.",
                short_hash(turn.root),
                short_hash(other.root)
            )
            narrate(
                "tournament",
                "Match %d: claim %s (%s) wins by timeout.",
                m.id,
                short_hash(other.root),
                labels_of(other)
            )
            return other
        end
        local descend_left = move.l ~= left_node
        if height == 1 then
            -- The exposed children are leaves. The divergent leaf is the side descended into;
            -- the on-turn claim committed to it, the other to the opposing sibling.
            local leaf_position, d_turn, d_other, agree_hash
            if descend_left then
                leaf_position, d_turn, d_other = 2 * index, move.l, left_node
                agree_hash = wait_for_agreed_hash(m, tournament, leaf_position, { one, two })
            else
                leaf_position, d_turn, d_other = 2 * index + 1, move.r, right_node
                agree_hash = move.l -- the shared left leaf, equal to left_node
            end
            if not agree_hash then
                narrate(m.tag, "Nobody proved the agreed state. Match %d eliminates both claims.", m.id)
                return nil
            end
            local d1 = turn == one and d_turn or d_other
            local d2 = turn == one and d_other or d_turn
            narrate(
                m.tag,
                "The claims diverge at leaf %d: %s against %s, from the agreed state %s.",
                leaf_position,
                short_hash(d1),
                short_hash(d2),
                short_hash(agree_hash)
            )
            local winner = tournament.settle(tournament, m, leaf_position, agree_hash, one, two, d1, d2)
            if winner then
                narrate("tournament", "Match %d: claim %s (%s) wins.", m.id, short_hash(winner.root), labels_of(winner))
            else
                narrate("tournament", "Match %d: no claim survives.", m.id)
            end
            return winner
        end
        -- Descend one height: the on-turn claim's chosen grandchildren become the standing
        -- left and right, the opponent's node on the chosen side becomes the next to open, and
        -- the turn passes to the opponent.
        if descend_left then
            other_parent, index = left_node, 2 * index
        else
            other_parent, index = right_node, 2 * index + 1
        end
        left_node, right_node = move.nl, move.nr
        height = height - 1
        turn, other = other, turn
        narrate(
            m.tag,
            "Height %d: the claims first disagree within leaves [0x%x, 0x%x].",
            height,
            index << height,
            ((index + 1) << height) - 1
        )
    end
end
-- docs:end run_match

-- Numbers a new match, in creation order, across the whole game.
local function new_match_id()
    match_count = match_count + 1
    return match_count
end

-- Runs the tasks concurrently, one coroutine each in the referee server's dispatcher, and
-- returns their results once every task has finished, indexed as the tasks were.
local function run_all(tasks)
    local main = coroutine.running()
    local results, pending = {}, 0
    for slot, task in ipairs(tasks) do
        pending = pending + 1
        dispatcher:spawn(function()
            results[slot] = task()
            pending = pending - 1
            dispatcher:schedule(main, "task_done")
        end)
    end
    while pending > 0 do
        dispatcher:wake_when_scheduled()
    end
    return results
end

-- Runs one round: pairs the surviving claims two by two and runs their matches at once.
-- Returns the winners, an odd claim out taking a bye to the next round, and a match that
-- eliminates both sides leaving neither behind.
-- docs:begin run_round
local function run_round(tournament, claims, round)
    local matches = {}
    for i = 1, #claims - 1, 2 do
        local one, two, id = claims[i], claims[i + 1], new_match_id()
        matches[(i + 1) // 2] = function()
            return run_match(tournament, one, two, round, id)
        end
    end
    -- The winners, gathered in bracket order so the next round is a pure function of the claims,
    -- not of the order the matches happened to finish. A match that eliminated both sides is a
    -- hole in the results and contributes no winner.
    local results = run_all(matches)
    local winners = {}
    for slot = 1, #claims // 2 do
        winners[#winners + 1] = results[slot]
    end
    if #claims % 2 == 1 then
        narrate("tournament", "Claim %s takes a bye to round %d.", short_hash(claims[#claims].root), round + 1)
        winners[#winners + 1] = claims[#claims]
    end
    return winners
end
-- docs:end run_round

-- Runs the tournament, eliminating claims round by round until a single one is left. That is
-- all a tournament is: a reduction of the claims to the one that survives every match.
-- docs:begin run_tournament
function run_tournament(tournament, claims)
    local round = 0
    while #claims > 1 do
        round = round + 1
        claims = run_round(tournament, claims, round)
    end
    return claims[1]
end
-- docs:end run_tournament

-- Waits for the players to connect and post their opening mcycle claims, and returns the
-- distinct claims, sorted so the bracket is a pure function of the claim set, not of who
-- connected first. The join phase stays open until a seal connection closes it and every
-- player that connected has answered, so the referee never needs to know the player count.
-- docs:begin wait_for_commitments
local function wait_for_commitments()
    local replies = server:collect("join", nil, "Join", socket.gettime() + JOIN_SECONDS, 0, function(rs)
        return server.sealed and #rs >= server:player_count()
    end, "return player:join()")
    local claims = distinct_claims(replies, MCYCLE_HEIGHT)
    for _, claim in ipairs(claims) do
        narrate(
            "claims",
            "Claim %s, with final state %s, joined (defended by %s).",
            short_hash(claim.root),
            short_hash(claim.final_state),
            labels_of(claim)
        )
    end
    return claims
end
-- docs:end wait_for_commitments

-- Verifies an epoch result against the settled final state, the way the Dave contracts would on
-- the blockchain. The outputs Merkle root proof must be whole-machine, sit at the tx-buffer
-- word, and roll up to the final state. The output proof's root must be the value that word
-- holds, and its target the hash of the output itself. Returns whether it all holds.
local function verify_result(result, final_state)
    local root_hash_proof, output_proof = result.outputs_merkle_root_proof, result.output_proof
    return root_hash_proof.root_hash == final_state
        and root_hash_proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE
        and root_hash_proof.target_address == cartesi.AR_CMIO_TX_BUFFER_START
        and root_hash_proof.log2_target_size == cartesi.HASH_TREE_LOG2_WORD_SIZE
        and pcall(hash_tree.verify_slice, root_hash_proof)
        and keccak(output_proof.root_hash) == root_hash_proof.target_hash
        and pcall(hash_tree.verify_slice, output_proof)
        and keccak(result.output) == output_proof.target_hash
end

-- Waits on the settled claim, the one the tournament leaves standing. Announces it, then, since
-- the claim commits only to the epoch's final state hash, waits for the epoch's actual output,
-- proved against that hash. The referee takes the first posted result that verifies, from any
-- holder of the winning claim, since a wrong result cannot match, then releases the players.
-- docs:begin wait_for_result
local function wait_for_result(winner)
    narrate("verdict", "Tournament winner is claim %s, defended by %s.", short_hash(winner.root), labels_of(winner))
    narrate("verdict", "Winner claim root: %s", cartesi.tohex(winner.root))
    narrate("verdict", "Winner final state hash: %s", cartesi.tohex(winner.final_state))
    local conns = server:subscribers({ hex(winner.root) })
    local result = server:await("result", conns, match_count + 1, "EpochResult", function(v)
        return verify_result(v, winner.final_state)
    end, "return player:prove_result()")
    assert(result, "no result proved against the winning final state")
    local payload = evmu.decode_calldata(NOTICE, result.output, "raw").payload
    narrate("verdict", "Result proved against the final state:\n%s", payload)
    server:collect("finish", nil, nil, socket.gettime() + 5, 0, function(rs)
        return #rs >= server:player_count()
    end, "return player:finish()")
end
-- docs:end wait_for_result

-- Seen from the referee, the whole game is short. It waits for the players' opening claims,
-- reduces them to the one that survives every match, and settles the epoch on its result. The
-- mcycle tournament packs what the reduction needs: the agreed initial state hash, the dapp
-- contract whose inputs verification trusts, and the way its matches settle. Everything hard,
-- the accept loop, the wire, the coroutine scheduling, runs underneath, in the referee server
-- this is handed to.
-- docs:begin run_referee
local function run_referee(referee, dapp_contract)
    local claims = wait_for_commitments()
    local winner = claims[1]
    if #claims > 1 then
        local mcycle_tournament = {
            level = "mcycle",
            height = MCYCLE_HEIGHT,
            initial_hash = referee.initial_hash,
            dapp_contract = dapp_contract,
            settle = settle_mcycle_match,
        }
        winner = run_tournament(mcycle_tournament, claims)
    end
    assert(winner, "the tournament ended with no winner")
    wait_for_result(winner)
end
-- docs:end run_referee

-- Models application deployment, returning the contract context the referee works against. The
-- epoch's inputs are all posted to the blockchain, so the contract holds its own copy of
-- every one, the copy that verification trusts over anything a player commits.
local function deploy(inputs)
    return { inputs = inputs }
end

-- The referee, standing in for the Dave contracts. It holds only what the blockchain would: the
-- agreed initial state hash (the template's own root hash, what a freshly deployed application
-- looks like on chain), the deployed dapp contract, and, during a match, one node hash per side
-- of the walk. Its server hides the accept loop, the wire, and the coroutine scheduling; run()
-- drives run_referee inside it, against the dapp contract it is handed.
local function new_referee(server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    local listener = assert(socket.bind(host, tonumber(port)))
    dispatcher = prtu.new_dispatcher()
    server = prtu.new_server(dispatcher, listener)
    server:accept()
    return {
        initial_hash = cartesi.machine(TEMPLATE):get_root_hash(),
        run = function(self, dapp_contract)
            server:run(function()
                run_referee(self, dapp_contract)
            end)
        end,
    }
end

--------------------------------------------------------------------------------
-- Role dispatch
--------------------------------------------------------------------------------

local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")

if role == "referee" then
    local dapp_contract = deploy(read_inputs(4))
    local referee = new_referee(server_address)
    referee:run(dapp_contract)
elseif role == "honest" then
    prtu.serve(new_player("honest", read_inputs(4)), server_address)
elseif role == "quitter" then
    local player = new_player("quitter", {})
    make_quitter(player)
    prtu.serve(player, server_address)
elseif role == "forger" then
    local index = assert(tonumber(arg[4]), "missing forged input index")
    local forged = read_input(assert(arg[5], "missing forged input file"))
    local player = new_player("forger", read_inputs(6))
    make_forger(player, index, forged)
    prtu.serve(player, server_address)
elseif role == "tamperer" then
    local input_index = assert(tonumber(arg[4]), "missing tampered input index")
    local entry_offset = assert(tonumber(arg[5]), "missing tamper entry offset")
    local player = new_player("tamperer", read_inputs(6))
    make_tamperer(player, input_index, entry_offset)
    prtu.serve(player, server_address)
elseif role == "fabulist" then
    local input_index = assert(tonumber(arg[4]), "missing lied-about input index")
    local leaf_offset = assert(tonumber(arg[5]), "missing lied-about leaf offset")
    local player = new_player("fabulist", read_inputs(6))
    make_fabulist(player, input_index, leaf_offset)
    prtu.serve(player, server_address)
else
    error("unknown role: " .. role)
end
