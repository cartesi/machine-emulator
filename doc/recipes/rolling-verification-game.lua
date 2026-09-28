-- A verification game over an epoch of a Rolling Cartesi Machine.
-- The referee role's runner simulates blockchain input and epoch events before the dispute.
-- Players find their initial snapshot under its state hash. A claim belongs to its submitting connection.
--   rolling-verification-game.lua referee <address> <initial-state-hash> [<input> ...]
--   rolling-verification-game.lua honest <address> <initial-state-hash> [<label>]
--   rolling-verification-game.lua phase_closer <address> [stop]
-- Dishonest roles and the counterfactual ownership attack live in vg-dishonest.lua and vg-test.lua.
local cartesi = require("cartesi")
local jsonrpc = require("cartesi.jsonrpc")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local vgu = require("vgu")
local output_verifier = require("game-output")
local EVENTS = vgu.EVENTS
local EVERYONE = vgu.EVERYONE
local FOREVER = nil
local story = vgu.story
local addresses = vgu.addresses
local MCYCLES_PER_INPUT = 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local UARCH_CYCLES_PER_MCYCLE = 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local INPUTS_PER_EPOCH = 1 << 16
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE

local function shallow_copy(values)
    local result = {}
    for key, value in pairs(values) do
        result[key] = value
    end
    return result
end

local function shallow_clear(values)
    for key in pairs(values) do
        values[key] = nil
    end
end

local function shallow_move(values)
    local result = shallow_copy(values)
    shallow_clear(values)
    return result
end

-- Transform values while preserving their keys.
local function map(values, transform)
    local result = {}
    for key, value in pairs(values) do
        result[key] = transform(value)
    end
    return result
end

local function fold(values, initial, combine)
    local result = initial
    for key, value in pairs(values) do
        result = combine(result, value, key)
    end
    return result
end

local function usaturating_add(a, b)
    return math.ult(cartesi.MCYCLE_MAX - b, a) and cartesi.MCYCLE_MAX or a + b
end

-- Shortcuts for the break reason a run returns and the reason a manual yield carries.
local function is_halted(break_reason)
    return break_reason == cartesi.BREAK_REASON_HALTED
end

local function is_mcycle_overflow(break_reason)
    return break_reason == cartesi.BREAK_REASON_MCYCLE_OVERFLOW
end

local function is_yielded_manual(break_reason)
    return break_reason == cartesi.BREAK_REASON_YIELDED_MANUALLY
end

local function is_yielded_automatic(break_reason)
    return break_reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
end

local function is_target_mcycle(break_reason)
    return break_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE
end

-- A machine stopped at a halt, a manual yield, or an mcycle overflow no longer advances on its own.
local function is_at_fixed_point(break_reason)
    return is_halted(break_reason) or is_yielded_manual(break_reason) or is_mcycle_overflow(break_reason)
end

local function is_rx_accepted(yield_reason)
    return yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED
end

local function is_rx_rejected(yield_reason)
    return yield_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED
end

local function is_tx_output(yield_reason)
    return yield_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT
end

-- Returns the yield reason and data.
local function receive_cmio_request(machine)
    local cmd, reason, data = machine:receive_cmio_request()
    assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL or cmd == cartesi.HTIF_YIELD_CMD_AUTOMATIC, "unexpected yield command")
    return reason, data
end

-- Positions bound a half-open range of transitions and differ in one coordinate.
local function midpoint(agreed_position, disputed_position)
    return {
        epoch_input_offset = agreed_position.epoch_input_offset
            + ((disputed_position.epoch_input_offset - agreed_position.epoch_input_offset) >> 1),
        input_mcycle_offset = agreed_position.input_mcycle_offset
            + ((disputed_position.input_mcycle_offset - agreed_position.input_mcycle_offset) >> 1),
        uarch_cycle = agreed_position.uarch_cycle
            + ((disputed_position.uarch_cycle - agreed_position.uarch_cycle) >> 1),
    }
end

local function precedes(a, b)
    if a.epoch_input_offset ~= b.epoch_input_offset then
        return a.epoch_input_offset < b.epoch_input_offset
    end
    if a.input_mcycle_offset ~= b.input_mcycle_offset then
        return a.input_mcycle_offset < b.input_mcycle_offset
    end
    return a.uarch_cycle < b.uarch_cycle
end

local function fork_machine(machine)
    local clone = assert(machine:fork_server())
    clone:set_cleanup_call(jsonrpc.SHUTDOWN)
    return clone
end

-- An advancing pair owns the working machine, its pre-input snapshot, and pending outputs.
-- The execution context supplies logical coordinates. The pre-input snapshot
-- survives fixed points; bisection forks the entire pair at any agreed position.
local advancing_pair_meta = { __index = {} }
local advancing_pair_methods = advancing_pair_meta.__index
function advancing_pair_methods:close()
    for _, key in ipairs({ "machine", "backup" }) do
        if self[key] then
            self[key]:shutdown_server()
            self[key] = nil
        end
    end
end
advancing_pair_meta.__close = advancing_pair_methods.close

function advancing_pair_methods:move()
    return setmetatable(shallow_move(self), advancing_pair_meta)
end

function advancing_pair_methods:fork()
    local clone <close> = setmetatable(shallow_copy(self), advancing_pair_meta)
    -- Clear borrowed resources before a failing fork can trigger cleanup.
    clone.machine, clone.backup = nil, nil
    clone.machine = fork_machine(self.machine)
    clone.backup = fork_machine(self.backup)
    clone.pending_outputs = shallow_copy(self.pending_outputs)
    return clone:move()
end

-- Refresh the input boundary only when entering a new input. Acceptance leaves
-- it intact, so later logical mcycle offsets still have the same absolute origin.
function advancing_pair_methods:snapshot()
    local backup = fork_machine(self.machine)
    if self.backup then
        self.backup:shutdown_server()
    end
    self.backup = backup
    self.pending_outputs = {}
end

-- docs:begin revert
function advancing_pair_methods:revert()
    local restored <close> = setmetatable({ machine = fork_machine(self.backup) }, advancing_pair_meta)
    self.machine:swap(restored.machine)
end
-- docs:end revert

local function new_advancing_pair(machine)
    local pair <close> = setmetatable({ machine = machine }, advancing_pair_meta)
    pair:snapshot()
    return pair:move()
end

local function new_machine(initial_hash)
    local machine = assert(jsonrpc.spawn_server("127.0.0.1:0"))
    machine:set_cleanup_call(jsonrpc.SHUTDOWN)
    local ok, err = pcall(function()
        machine:load(cartesi.tohex(initial_hash))
        assert(machine:get_root_hash() == initial_hash, "initial machine snapshot hash mismatch")
    end)
    if not ok then
        machine:shutdown_server()
        error(err, 0)
    end
    return machine
end

local player_meta = { __index = {} }
local player_methods = player_meta.__index

function player_methods:close()
    for _, key in ipairs({ "initial", "latest", "agreed_machine", "tentative_machine" }) do
        if self[key] then
            self[key]:close()
            self[key] = nil
        end
    end
end
player_meta.__close = player_methods.close

-- Transfer construction state out of a <close> local without closing its resources.
function player_methods:move()
    return setmetatable(shallow_move(self), player_meta)
end

-- The inner execution loop leaves terminal handling to the input driver, as in PRT.
local function run_to_stop(machine, mcycle_end, on_yield_automatic)
    while true do
        local break_reason = machine:run(mcycle_end)
        if is_at_fixed_point(break_reason) or is_target_mcycle(break_reason) then
            return break_reason
        elseif is_yielded_automatic(break_reason) and on_yield_automatic then
            local yield_reason, data = receive_cmio_request(machine)
            on_yield_automatic(yield_reason, data)
        end
    end
end

-- Delivers a posted input, recording the root a rejection reverts to.
local function load_cmio_input(machine, data, revert_root_hash)
    if data ~= nil then
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
    end
end

-- Shared by the two execution granularities when leaving a virgin input boundary.
local function begin_input(pair, input_data)
    local revert_root_hash = pair.machine:get_root_hash()
    pair:snapshot()
    load_cmio_input(pair.machine, input_data, revert_root_hash)
end

-- luacheck: push ignore self
function player_methods:run_to_uarch_cycle(pair, input_data, input_mcycle_offset, uarch_cycle_begin, uarch_cycle_end)
    assert(uarch_cycle_begin <= uarch_cycle_end, "agreed machine is past desired state")
    assert(pair.machine:read_reg("uarch_cycle") <= uarch_cycle_end, "agreed machine is past desired state")
    if uarch_cycle_begin == uarch_cycle_end then
        return
    end
    if input_mcycle_offset == 0 and uarch_cycle_begin == 0 then
        begin_input(pair, input_data)
    end
    return pair.machine:run_uarch(uarch_cycle_end)
end

-- Retain only accepted outputs and check their cumulative root.
local function flush_pending_outputs(pending, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
    if not outputs or not is_rx_accepted(yield_reason) then
        return
    end
    for _, output in ipairs(pending) do
        outputs[#outputs + 1] = output
        hash_tree.frontier_push_back(outputs_frontier, cartesi.keccak256(output))
    end
    assert(hash_tree.frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")
end

-- Complete logical mcycles within one input. Offset zero is before delivery;
-- the unchanged pre-input backup supplies the absolute origin even after rollback.
-- docs:begin run_to_mcycle
function player_methods:run_to_mcycle(
    pair,
    input_data,
    input_mcycle_offset_begin,
    input_mcycle_offset_end,
    outputs,
    outputs_frontier
)
    assert(input_mcycle_offset_begin <= input_mcycle_offset_end, "agreed machine is past desired state")
    if input_mcycle_offset_begin == input_mcycle_offset_end then
        return
    end
    if input_mcycle_offset_begin == 0 then
        begin_input(pair, input_data)
    end
    local machine = pair.machine
    local input_mcycle_boundary = pair.backup:read_reg("mcycle")
    local mcycle_end = usaturating_add(input_mcycle_boundary, input_mcycle_offset_end)
    local function on_yield_automatic(yield_reason, output)
        if outputs and is_tx_output(yield_reason) then
            pair.pending_outputs[#pair.pending_outputs + 1] = output
        end
    end
    local break_reason = run_to_stop(machine, mcycle_end, on_yield_automatic)
    if not is_at_fixed_point(break_reason) then
        return break_reason, nil, input_mcycle_boundary
    end
    local yield_reason, outputs_merkle_root
    if is_yielded_manual(break_reason) then
        yield_reason, outputs_merkle_root = receive_cmio_request(machine)
    end
    if is_rx_rejected(yield_reason) then
        pair:revert()
    else
        flush_pending_outputs(pair.pending_outputs, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
    end
    pair.pending_outputs = {}
    return break_reason, yield_reason, input_mcycle_boundary
end
-- docs:end run_to_mcycle
-- luacheck: pop

-- Replay completed inputs, leaving the next input undelivered. Unposted inputs
-- repeat the final state and need no execution.
function player_methods:run_to_input_boundary(pair, inputs, epoch_input_offset_begin, epoch_input_offset_end)
    for epoch_input_offset = epoch_input_offset_begin, math.min(epoch_input_offset_end, #inputs) - 1 do
        self:run_to_mcycle(pair, inputs[epoch_input_offset + 1], 0, MCYCLES_PER_INPUT)
    end
end

function player_methods:read_input(_index, path) -- luacheck: ignore 212 self
    return util.read_file(path)
end

function player_methods:reset_bisection()
    self.agreed_machine:close()
    self.agreed_machine = self.initial:fork()
    self.agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
end

local function get_machine_word(machine, address)
    address = address & ~(WORD_SIZE - 1)
    return machine:read_memory(address, WORD_SIZE), machine:get_proof(address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
end

-- Protocol handlers are shared and separate from the player's methods and state.
-- The transport passes the receiving player as self.
local event_handler = {}

function event_handler:initial_state(initial_hash)
    assert(
        self.agreed_machine.machine:get_root_hash() == initial_hash,
        "initial machine does not match referee's state hash"
    )
end

function event_handler:input_added(epoch_input_offset, path)
    self.inputs[epoch_input_offset + 1] = self:read_input(epoch_input_offset, path)
    self:run_to_mcycle(
        self.latest,
        self.inputs[epoch_input_offset + 1],
        0,
        MCYCLES_PER_INPUT,
        self.outputs,
        self.outputs_frontier
    )
end

function event_handler:epoch_sealed()
    self.final_hash = self.latest.machine:get_root_hash()
    local leaves = map(self.outputs, cartesi.keccak256)
    self.output_proofs = hash_tree.frontier_next_proofs(self.previous_outputs_frontier, leaves)
    self.previous_outputs_frontier = self.outputs_frontier
    self.outputs_frontier = nil
end

function event_handler:commit_claim()
    return self.final_hash
end

function event_handler:dispute_started()
    self:reset_bisection()
end

-- docs:begin reveal_bisection
function event_handler:reveal_bisection(agreed_position, tentative_position)
    if precedes(self.agreed_position, agreed_position) then
        -- The previous midpoint is now the agreed predecessor.
        self.agreed_machine:close()
        self.agreed_machine, self.tentative_machine = self.tentative_machine, nil
    else
        self.tentative_machine:close()
    end
    self.agreed_position = agreed_position
    -- Replay from a fork of the whole agreed pair, including its pre-input snapshot.
    self.tentative_machine = self.agreed_machine:fork()
    if agreed_position.epoch_input_offset < tentative_position.epoch_input_offset then
        self:run_to_input_boundary(
            self.tentative_machine,
            self.inputs,
            agreed_position.epoch_input_offset,
            tentative_position.epoch_input_offset
        )
    end
    if agreed_position.input_mcycle_offset < tentative_position.input_mcycle_offset then
        self:run_to_mcycle(
            self.tentative_machine,
            self.inputs[tentative_position.epoch_input_offset + 1],
            agreed_position.input_mcycle_offset,
            tentative_position.input_mcycle_offset
        )
    end
    if agreed_position.uarch_cycle < tentative_position.uarch_cycle then
        self:run_to_uarch_cycle(
            self.tentative_machine,
            self.inputs[tentative_position.epoch_input_offset + 1],
            tentative_position.input_mcycle_offset,
            agreed_position.uarch_cycle,
            tentative_position.uarch_cycle
        )
    end
    return self.tentative_machine.machine:get_root_hash()
end
-- docs:end reveal_bisection

-- docs:begin prove_state_transition
function event_handler:prove_state_transition(epoch_input_offset, input_mcycle_offset, uarch_cycle)
    local machine = self.agreed_position.uarch_cycle < uarch_cycle and self.tentative_machine.machine
        or self.agreed_machine.machine
    local data = self.inputs[epoch_input_offset + 1]
    local proof
    if input_mcycle_offset == 0 and uarch_cycle == 0 and data then
        local before = machine:get_root_hash()
        local send = machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, before)
        proof = { send_cmio_log = send, step_log = machine:log_step_uarch() }
    elseif uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        local step = machine:log_step_uarch()
        proof = { step_log = step, reset_uarch_log = machine:log_reset_uarch() }
    else
        proof = { step_log = machine:log_step_uarch() }
    end
    self:reset_bisection()
    return proof
end
-- docs:end prove_state_transition

function event_handler:prove_outputs_merkle_root()
    local machine = self.latest.machine
    local y, yp = get_machine_word(machine, cartesi.machine:get_reg_address("iflags_Y"))
    local tohost, tp = get_machine_word(machine, cartesi.machine:get_reg_address("htif_tohost"))
    local tx, txp = get_machine_word(machine, cartesi.AR_CMIO_TX_BUFFER_START)
    return {
        iflags_y_data = y,
        iflags_y_proof = yp,
        htif_tohost_data = tohost,
        htif_tohost_proof = tp,
        tx_buffer_data = tx,
        tx_buffer_proof = txp,
    }
end

function event_handler:prove_output()
    if #self.outputs == 0 then
        return {}
    end
    return {
        output_index = self.output_proofs[#self.outputs].target_address,
        output = self.outputs[#self.outputs],
        output_proof = self.output_proofs[#self.outputs],
    }
end

-- The optional proof bootstraps output history after a previous epoch.
local function new_player(initial_hash, label, last_output_proof, machine)
    local self <close> = setmetatable({
        label = label or "honest",
        agreed_machine = new_advancing_pair(machine or new_machine(initial_hash)),
        agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
        inputs = {},
        outputs = {},
        event_handler = event_handler,
    }, player_meta)
    machine = self.agreed_machine.machine
    assert(machine:get_root_hash() == initial_hash, "initial machine snapshot hash mismatch")
    local break_reason = machine:run(machine:read_reg("mcycle"))
    assert(is_yielded_manual(break_reason), "initial machine is not waiting for an input")
    local yield_reason = receive_cmio_request(machine)
    assert(is_rx_accepted(yield_reason), "initial machine did not accept")
    self.initial = self.agreed_machine:fork()
    self.latest = self.agreed_machine:fork()
    self.tentative_machine = self.agreed_machine:fork()
    if last_output_proof then
        assert(
            last_output_proof.log2_root_size == cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT
                and last_output_proof.log2_target_size == 0,
            "last_output_proof is not an outputs proof"
        )
    end
    self.previous_outputs_frontier =
        hash_tree.frontier(last_output_proof or cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    self.outputs_frontier = hash_tree.frontier_copy(self.previous_outputs_frontier)
    return self:move()
end

-- The server provides the blockchain execution environment, bound when the referee starts.
local server

-- Blockchain operations; the simulation transport stays outside the algorithm excerpts.
local function current_time()
    return server:get_time()
end

local function request_all(subscriptions, event, arguments, validator)
    return server:request_all(subscriptions, event, arguments, validator)
end

local function request_first_valid(subscriptions, event, arguments, validator)
    return server:request_first_valid(subscriptions, event, arguments, validator)
end

local function accept_subscribers(initial_state_hash)
    return server:accept_subscribers(initial_state_hash)
end

-- The referee trusts its own input bytes and verifies the log without a machine.
-- Invalid logs raise an error, which the request's protected validator rejects.
-- docs:begin validate_state_transition_response
local function validate_state_transition_response(
    dapp_contract,
    epoch_input_offset,
    input_mcycle_offset,
    uarch_cycle,
    before,
    response,
    after
)
    local data = dapp_contract.inputs[epoch_input_offset + 1]
    if input_mcycle_offset == 0 and uarch_cycle == 0 and data then
        before = cartesi.machine:verify_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            data,
            before,
            response.send_cmio_log,
            before
        )
    end
    before = cartesi.machine:verify_step_uarch(before, response.step_log)
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        before = cartesi.machine:verify_reset_uarch(before, response.reset_uarch_log)
    end
    assert(before == after, "log does not reach the committed after-hash")
    return true
end
-- docs:end validate_state_transition_response

local function accept_hash(hash)
    return type(hash) == "string" and #hash == 32 and hash
end

local function validate_claim_response(response)
    assert(accept_hash(response), "invalid final hash")
    return response
end

local function validate_bisection_response(response)
    assert(accept_hash(response), "invalid midpoint hash")
    return response
end

local validate_outputs_merkle_root_response = output_verifier.validate_outputs_merkle_root_response
local validate_output_response = output_verifier.validate_output_response

-- Return a representative if all surviving players support the same final claim.
local function single_claim_remains(players)
    local first
    for _, sender in ipairs(addresses(players)) do
        local player = players[sender]
        if first and player.final_hash ~= first.final_hash then
            return nil
        end
        first = first or player
    end
    return first
end

local function no_claim_remains(players)
    return not next(players)
end

local function any_of(hashes)
    return hashes[next(hashes)]
end

local function hashes_disagree(hashes)
    local first
    for _, hash in pairs(hashes) do
        if first and hash ~= first then
            return true
        end
        first = hash
    end
    return false
end

-- Each midpoint advances a fork of the agreed pair.
local function request_bisections(tournament, agreed_position, tentative_position)
    local started_at = current_time()
    local deadline = fold(tournament.players, started_at, function(latest, player)
        return math.max(latest, started_at + player.allowance)
    end)
    local survivors <close> = request_all(
        addresses(tournament.players),
        EVENTS.reveal_bisection,
        { agreed_position, tentative_position },
        function(response, sender, received_at)
            local player = tournament.players[sender]
            assert(received_at < started_at + player.allowance, "late midpoint hash")
            local hash = validate_bisection_response(response)
            local elapsed = received_at - started_at
            player.allowance = player.allowance - math.max(elapsed - tournament.dapp_contract.response_budget, 0)
            player.midpoint_hash = hash
            return player
        end
    )
    return survivors:wait_at_most(deadline)
end

-- Narrow the two boundaries to one transition. Any disagreement selects the earlier half.
-- docs:begin bisect_level
local function bisect_level(tournament, bisection)
    story.report_bisection(bisection.agreed_position, bisection.disputed_position)
    local tentative_position = midpoint(bisection.agreed_position, bisection.disputed_position)
    while precedes(bisection.agreed_position, tentative_position) do
        tournament.players = request_bisections(tournament, bisection.agreed_position, tentative_position)
        if no_claim_remains(tournament.players) then
            return false
        end
        local winner = single_claim_remains(tournament.players)
        if winner then
            return false, winner
        end
        local hashes = map(tournament.players, function(player)
            return player.midpoint_hash
        end)
        if hashes_disagree(hashes) then
            bisection.disputed_position = tentative_position
            bisection.hashes_after = hashes
        else
            bisection.agreed_position = tentative_position
            bisection.last_agreed_hash = any_of(hashes)
        end
        story.report_bisection_progress(bisection.agreed_position, bisection.disputed_position)
        tentative_position = midpoint(bisection.agreed_position, bisection.disputed_position)
    end
    return true
end
-- docs:end bisect_level

-- Every surviving player must prove its own committed endpoint.
local function request_state_transitions(tournament, bisection)
    local agreed_position = bisection.agreed_position
    local started_at = current_time()
    local deadline = fold(tournament.players, started_at, function(latest, player)
        return math.max(latest, started_at + player.allowance)
    end)
    local survivors <close> = request_all(
        addresses(tournament.players),
        EVENTS.prove_state_transition,
        { agreed_position.epoch_input_offset, agreed_position.input_mcycle_offset, agreed_position.uarch_cycle },
        function(response, sender, received_at)
            local player = tournament.players[sender]
            assert(received_at < started_at + player.allowance, "late transition proof")
            validate_state_transition_response(
                tournament.dapp_contract,
                agreed_position.epoch_input_offset,
                agreed_position.input_mcycle_offset,
                agreed_position.uarch_cycle,
                bisection.last_agreed_hash,
                response,
                bisection.hashes_after[sender]
            )
            local elapsed = received_at - started_at
            player.allowance = player.allowance - math.max(elapsed - tournament.dapp_contract.response_budget, 0)
            story.report_state_transition(player)
            return player
        end
    )
    return survivors:wait_at_most(deadline)
end

-- docs:begin settle_dispute
local function settle_dispute(tournament)
    local _ <close> = request_all(addresses(tournament.players), EVENTS.dispute_started, {})
    while not no_claim_remains(tournament.players) do
        local winner = single_claim_remains(tournament.players)
        if winner then
            return winner
        end
        local bisection = {
            agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            disputed_position = { epoch_input_offset = INPUTS_PER_EPOCH, input_mcycle_offset = 0, uarch_cycle = 0 },
            last_agreed_hash = tournament.dapp_contract.initial_state_hash,
            hashes_after = map(tournament.players, function(player)
                return player.final_hash
            end),
        }
        local complete
        complete, winner = bisect_level(tournament, bisection)
        if not complete then
            return winner
        end
        -- The next input boundary is also the end of this input's mcycle range.
        bisection.disputed_position = {
            epoch_input_offset = bisection.agreed_position.epoch_input_offset,
            input_mcycle_offset = MCYCLES_PER_INPUT,
            uarch_cycle = 0,
        }
        complete, winner = bisect_level(tournament, bisection)
        if not complete then
            return winner
        end
        -- UARCH_CYCLE_MAX names the last cycle. Its outgoing transition includes reset.
        bisection.disputed_position = {
            epoch_input_offset = bisection.agreed_position.epoch_input_offset,
            input_mcycle_offset = bisection.agreed_position.input_mcycle_offset,
            uarch_cycle = UARCH_CYCLES_PER_MCYCLE,
        }
        complete, winner = bisect_level(tournament, bisection)
        if not complete then
            return winner
        end
        tournament.players = request_state_transitions(tournament, bisection)
    end
end
-- docs:end settle_dispute

-- Establish the outputs root, then accept distinct player-selected outputs until
-- the runner stops the game. Output offers are permissionless after settlement.
-- docs:begin wait_for_outputs
local function wait_for_outputs(winner)
    local root_proof <close> = request_first_valid(
        EVERYONE,
        EVENTS.prove_outputs_merkle_root,
        { winner.final_hash },
        function(response)
            return validate_outputs_merkle_root_response(response, winner.final_hash)
        end
    )
    local outputs_merkle_root = root_proof:wait_at_most(FOREVER)
    local accepted_output_indices = {}
    while true do
        local output_proof <close> = request_first_valid(
            EVERYONE,
            EVENTS.prove_output,
            { outputs_merkle_root },
            function(response)
                if not accepted_output_indices[response.output_index] then
                    return validate_output_response(response, outputs_merkle_root) and response
                end
            end
        )
        local output = output_proof:wait_at_most(FOREVER)
        accepted_output_indices[output.output_index] = true
        story.report_output(output)
    end
end
-- docs:end wait_for_outputs

local function request_claims(dapp_contract, subscribers)
    local started_at = current_time()
    local max_allowance = dapp_contract.max_allowance
    local deadline = started_at + max_allowance
    local survivors <close> = request_all(subscribers, EVENTS.commit_claim, {}, function(response, sender, received_at)
        assert(received_at < deadline, "late final hash")
        local hash = validate_claim_response(response)
        local elapsed = received_at - started_at
        return {
            label = sender.label,
            allowance = max_allowance - math.max(elapsed - dapp_contract.response_budget, 0),
            final_hash = hash,
        }
    end)
    return {
        dapp_contract = dapp_contract,
        players = survivors:wait_at_most(deadline),
    }
end

-- Simulate blockchain publication, waiting for each event's handlers before proceeding.
local function run_epoch(dapp_contract, subscribers)
    local initial <close> = request_all(subscribers, EVENTS.initial_state, { dapp_contract.initial_state_hash })
    initial:wait_at_most(FOREVER)
    for index, path in ipairs(dapp_contract.input_paths) do
        local input <close> = request_all(subscribers, EVENTS.input_added, { index - 1, path })
        input:wait_at_most(FOREVER)
    end
    local sealed <close> = request_all(subscribers, EVENTS.epoch_sealed, { #dapp_contract.inputs })
    sealed:wait_at_most(FOREVER)
end

local function run_referee(dapp_contract, subscribers)
    local tournament = request_claims(dapp_contract, subscribers)
    story.report_claims(tournament.players)
    local winner = settle_dispute(tournament)
    story.report_winner(winner)
    if winner then
        wait_for_outputs(winner)
    end
end

-- The deployed contract fixes the epoch's initial state, inputs, and clock settings.
-- Input events carry paths; proof verification trusts the contract's own input bytes.
local function make_dapp_contract(initial_state_hash, input_paths)
    assert(#initial_state_hash == 32 and #input_paths <= INPUTS_PER_EPOCH, "invalid epoch")
    return {
        initial_state_hash = initial_state_hash,
        input_paths = input_paths,
        inputs = map(input_paths, util.read_file),
        max_allowance = 4,
        response_budget = 1,
    }
end

local function new_referee(dapp_contract)
    return {
        dapp_contract = dapp_contract,
        run = function(self, referee_server)
            server = referee_server
            local subscribers = accept_subscribers(self.dapp_contract.initial_state_hash)
            run_epoch(self.dapp_contract, subscribers)
            run_referee(self.dapp_contract, subscribers)
        end,
    }
end

local vg = {
    addresses = addresses,
    new_player = new_player,
    new_referee = new_referee,
    make_dapp_contract = make_dapp_contract,
    event_handler = event_handler,
    player_methods = player_methods,
    advancing_pair_methods = advancing_pair_methods,
    usaturating_add = usaturating_add,
    load_cmio_input = load_cmio_input,
    validate_state_transition_response = validate_state_transition_response,
}
if ... == "rolling-verification-game" then
    return vg
end
local role = assert(arg[1], "missing role")
local address = assert(arg[2], "missing referee address")
if role == "phase_closer" then
    return vgu.run_client(vgu.new_phase_closer(arg[3]), address)
end
local initial_state_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
if role == "referee" then
    local dapp_contract = make_dapp_contract(initial_state_hash, { table.unpack(arg, 4) })
    vgu.run_server(new_referee(dapp_contract), address)
    vgu.close_narration()
elseif role == "honest" then
    local player <close> = new_player(initial_state_hash, arg[4])
    vgu.run_client(player, address)
else
    error("unknown role: " .. role)
end
