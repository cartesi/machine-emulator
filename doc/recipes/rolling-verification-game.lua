-- A verification game over an epoch of a Rolling Cartesi Machine.
-- Only the referee receives input paths. Players find their initial snapshot under
-- its state hash and receive inputs in events. A claim belongs to its submitting connection.
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

local function midpoint(interval)
    return interval.lo + ((interval.hi - interval.lo) >> 1)
end

-- A position counts completed inputs, mcycles within the input, and uarch cycles
-- within the mcycle. Leaf k is reached at position k + 1; its predecessor is at k.
local function position(interval, offset)
    return {
        epoch_input_offset = interval.level == "input" and offset or interval.epoch_input_offset,
        input_mcycle_offset = interval.level == "mcycle" and offset or interval.input_mcycle_offset or 0,
        uarch_cycle = interval.level == "uarch_cycle" and offset or 0,
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

-- An advancing pair owns only the working machine and its pre-input snapshot.
-- The execution context supplies logical coordinates. The execution snapshot
-- lasts until the input reaches a fixed point; bisection owns its replay checkpoint.
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
    if self.backup then
        clone.backup = fork_machine(self.backup)
    end
    return clone:move()
end

-- These operations settle input execution only. Bisection snapshots the entire
-- pair independently, including a pending input snapshot.
function advancing_pair_methods:snapshot()
    assert(not self.backup, "input already has a snapshot")
    self.backup = fork_machine(self.machine)
end

function advancing_pair_methods:commit()
    assert(self.backup, "input has no snapshot")
    self.backup:shutdown_server()
    self.backup = nil
end

function advancing_pair_methods:revert()
    assert(self.backup, "input has no snapshot")
    self.machine:swap(self.backup)
    self:commit()
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

-- Advance a loaded input, settling its checkpoint when it reaches a fixed point.
function player_methods:run_to_stop(pair, _epoch_input_offset, mcycle_end, on_yield_automatic) -- luacheck: ignore self
    local machine = pair.machine
    while true do
        local break_reason = machine:run(mcycle_end)
        if is_at_fixed_point(break_reason) then
            local yield_reason, data
            if is_yielded_manual(break_reason) then
                yield_reason, data = receive_cmio_request(machine)
            end
            if is_rx_rejected(yield_reason) then
                pair:revert()
            else
                pair:commit()
            end
            return break_reason, yield_reason, data
        elseif is_target_mcycle(break_reason) then
            return break_reason
        elseif is_yielded_automatic(break_reason) then
            if on_yield_automatic then
                local yield_reason, data = receive_cmio_request(machine)
                on_yield_automatic(yield_reason, data)
            end
        end
    end
end

-- Delivers a posted input, recording the root a rejection reverts to.
local function load_cmio_input(machine, data, revert_root_hash)
    if data ~= nil then
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
    end
end

function player_methods:run_uarch(pair, epoch_input_offset, input_mcycle_offset, uarch_cycle_end)
    local uarch_cycle = pair.machine:read_reg("uarch_cycle")
    assert(uarch_cycle <= uarch_cycle_end, "agreed machine is past desired state")
    if input_mcycle_offset == 0 and uarch_cycle == 0 and uarch_cycle_end > 0 then
        self:run_advance_state_input(pair, epoch_input_offset, 0)
    end
    pair.machine:run_uarch(uarch_cycle_end)
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

-- Run one input from its virgin boundary to the requested offset, as in PRT.
function player_methods:run_advance_state_input(
    pair,
    epoch_input_offset,
    input_mcycle_offset_end,
    outputs,
    outputs_frontier
)
    local machine = pair.machine
    local input_mcycle_boundary = machine:read_reg("mcycle")
    local revert_root_hash = machine:get_root_hash()
    pair:snapshot()
    load_cmio_input(machine, self.inputs[epoch_input_offset + 1], revert_root_hash)
    local mcycle_end = usaturating_add(input_mcycle_boundary, input_mcycle_offset_end)
    local pending = {}
    local function on_yield_automatic(yield_reason, output)
        if outputs and is_tx_output(yield_reason) then
            pending[#pending + 1] = output
        end
    end
    local break_reason, yield_reason, outputs_merkle_root =
        self:run_to_stop(pair, epoch_input_offset, mcycle_end, on_yield_automatic)
    flush_pending_outputs(pending, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
    return break_reason, yield_reason, input_mcycle_boundary
end

-- Replay to an input boundary without collecting outputs. Unposted inputs
-- repeat the final state and need no execution.
function player_methods:run_to_input_boundary(pair, epoch_input_offset_begin, epoch_input_offset_end)
    for epoch_input_offset = epoch_input_offset_begin, math.min(epoch_input_offset_end, #self.inputs) - 1 do
        self:run_advance_state_input(pair, epoch_input_offset, MCYCLES_PER_INPUT)
    end
end

function player_methods:run_to_mcycle_boundary(
    pair,
    epoch_input_offset,
    input_mcycle_offset_begin,
    input_mcycle_offset_end
)
    if input_mcycle_offset_begin == 0 then
        self:run_advance_state_input(pair, epoch_input_offset, input_mcycle_offset_end)
    elseif pair.backup then
        local mcycle_end = usaturating_add(pair.backup:read_reg("mcycle"), input_mcycle_offset_end)
        self:run_to_stop(pair, epoch_input_offset, mcycle_end)
    end
end

function player_methods:read_input(_index, path) -- luacheck: ignore 212 self
    return util.read_file(path)
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
    self:run_advance_state_input(
        self.latest,
        epoch_input_offset,
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
    self.agreed_machine:close()
    self.agreed_machine = self.initial:fork()
    self.agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
end

function event_handler:reveal_bisection(agreed_position, tentative_position)
    if precedes(self.agreed_position, agreed_position) then
        -- The previous midpoint is now the agreed predecessor.
        self.agreed_machine:close()
        self.agreed_machine, self.tentative_machine = self.tentative_machine, nil
    else
        self.tentative_machine:close()
    end
    self.agreed_position = agreed_position
    -- Replay from a fork of the whole agreed pair, including any pending input snapshot.
    self.tentative_machine = self.agreed_machine:fork()
    if agreed_position.epoch_input_offset < tentative_position.epoch_input_offset then
        self:run_to_input_boundary(
            self.tentative_machine,
            agreed_position.epoch_input_offset,
            tentative_position.epoch_input_offset
        )
    end
    if agreed_position.input_mcycle_offset < tentative_position.input_mcycle_offset then
        self:run_to_mcycle_boundary(
            self.tentative_machine,
            tentative_position.epoch_input_offset,
            agreed_position.input_mcycle_offset,
            tentative_position.input_mcycle_offset
        )
    end
    if agreed_position.uarch_cycle < tentative_position.uarch_cycle then
        self:run_uarch(
            self.tentative_machine,
            tentative_position.epoch_input_offset,
            tentative_position.input_mcycle_offset,
            tentative_position.uarch_cycle
        )
    end
    return self.tentative_machine.machine:get_root_hash()
end

function event_handler:prove_state_transition(epoch_input_offset, input_mcycle_offset, uarch_cycle)
    local machine = self.agreed_position.uarch_cycle < uarch_cycle and self.tentative_machine.machine
        or self.agreed_machine.machine
    local data = self.inputs[epoch_input_offset + 1]
    if input_mcycle_offset == 0 and uarch_cycle == 0 and data then
        local before = machine:get_root_hash()
        local send = machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, before)
        return { send_cmio_log = send, step_log = machine:log_step_uarch() }
    elseif uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        local step = machine:log_step_uarch()
        return { step_log = step, reset_uarch_log = machine:log_reset_uarch() }
    else
        return { step_log = machine:log_step_uarch() }
    end
end

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
        agreed_machine = setmetatable({ machine = machine or new_machine(initial_hash) }, advancing_pair_meta),
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

-- The referee trusts its own input bytes and verifies the log without a machine.
-- Invalid logs raise an error, which the request's protected validator rejects.
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

-- The interval contains resulting states, indexed from zero, with the agreed
-- predecessor outside it. Each midpoint advances a fork of the agreed pair.
local function request_bisections(tournament, interval)
    local started_at = server:get_time()
    local deadline = fold(tournament.players, started_at, function(latest, player)
        return math.max(latest, started_at + player.allowance)
    end)
    local survivors <close> = server:request_all(
        addresses(tournament.players),
        EVENTS.reveal_bisection,
        { position(interval, interval.lo), position(interval, midpoint(interval) + 1) },
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
    return survivors:wait(deadline)
end

-- Bisect the inclusive range of resulting-state indices. The agreed predecessor
-- is not one of its leaves. Any disagreement selects the earlier half.
local function bisect_level(tournament, level, count, bisection)
    local interval = {
        level = level,
        lo = 0,
        hi = count - 1,
        epoch_input_offset = bisection.epoch_input_offset,
        input_mcycle_offset = bisection.input_mcycle_offset,
    }
    story.report_bisection(interval)
    while interval.lo < interval.hi do
        tournament.players = request_bisections(tournament, interval)
        if no_claim_remains(tournament.players) then
            return nil
        end
        local winner = single_claim_remains(tournament.players)
        if winner then
            return nil, winner
        end
        local hashes = map(tournament.players, function(player)
            return player.midpoint_hash
        end)
        local mid = midpoint(interval)
        if hashes_disagree(hashes) then
            interval.hi = mid
            bisection.hashes_after = hashes
        else
            interval.lo = mid + 1
            bisection.last_agreed_hash = any_of(hashes)
        end
        story.report_bisection_progress(interval)
    end
    return interval.lo
end

-- Every surviving player must prove its own committed endpoint.
local function request_state_transitions(tournament, epoch_input_offset, input_mcycle_offset, uarch_cycle, bisection)
    local started_at = server:get_time()
    local deadline = fold(tournament.players, started_at, function(latest, player)
        return math.max(latest, started_at + player.allowance)
    end)
    local survivors <close> = server:request_all(
        addresses(tournament.players),
        EVENTS.prove_state_transition,
        { epoch_input_offset, input_mcycle_offset, uarch_cycle },
        function(response, sender, received_at)
            local player = tournament.players[sender]
            assert(received_at < started_at + player.allowance, "late transition proof")
            validate_state_transition_response(
                tournament.dapp_contract,
                epoch_input_offset,
                input_mcycle_offset,
                uarch_cycle,
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
    return survivors:wait(deadline)
end

local function settle_dispute(tournament)
    while not no_claim_remains(tournament.players) do
        local winner = single_claim_remains(tournament.players)
        if winner then
            return winner
        end
        local started <close> = server:request_all(addresses(tournament.players), EVENTS.dispute_started, {})
        started:wait()
        local bisection = {
            last_agreed_hash = tournament.dapp_contract.initial_state_hash,
            hashes_after = map(tournament.players, function(player)
                return player.final_hash
            end),
        }
        local epoch_input_offset, winner_input = bisect_level(tournament, "input", INPUTS_PER_EPOCH, bisection)
        if not epoch_input_offset then
            return winner_input
        end
        bisection.epoch_input_offset = epoch_input_offset
        local input_mcycle_offset, winner_mcycle = bisect_level(tournament, "mcycle", MCYCLES_PER_INPUT, bisection)
        if not input_mcycle_offset then
            return winner_mcycle
        end
        bisection.input_mcycle_offset = input_mcycle_offset
        -- UARCH_CYCLE_MAX names the last cycle. Its outgoing transition includes reset.
        local uarch_cycle, winner_uarch_cycle =
            bisect_level(tournament, "uarch_cycle", UARCH_CYCLES_PER_MCYCLE, bisection)
        if not uarch_cycle then
            return winner_uarch_cycle
        end
        tournament.players =
            request_state_transitions(tournament, epoch_input_offset, input_mcycle_offset, uarch_cycle, bisection)
    end
end

-- Establish the outputs root, then accept distinct player-selected outputs until
-- the runner stops the game. Output offers are permissionless after settlement.
local function wait_for_outputs(winner)
    local root_proof <close> = server:request_first_valid(
        EVERYONE,
        EVENTS.prove_outputs_merkle_root,
        { winner.final_hash },
        function(response)
            return validate_outputs_merkle_root_response(response, winner.final_hash)
        end
    )
    local outputs_merkle_root = root_proof:wait()
    local accepted_output_indices = {}
    while true do
        local output_proof <close> = server:request_first_valid(
            EVERYONE,
            EVENTS.prove_output,
            { outputs_merkle_root },
            function(response)
                if not accepted_output_indices[response.output_index] then
                    return validate_output_response(response, outputs_merkle_root) and response
                end
            end
        )
        local output = output_proof:wait()
        accepted_output_indices[output.output_index] = true
        story.report_output(output)
    end
end

local function request_claims(tournament)
    local started_at = server:get_time()
    local deadline = fold(tournament.players, started_at, function(latest, player)
        return math.max(latest, started_at + player.allowance)
    end)
    local survivors <close> = server:request_all(
        addresses(tournament.players),
        EVENTS.commit_claim,
        {},
        function(response, sender, received_at)
            local player = tournament.players[sender]
            assert(received_at < started_at + player.allowance, "late final hash")
            local hash = validate_claim_response(response)
            local elapsed = received_at - started_at
            player.allowance = player.allowance - math.max(elapsed - tournament.dapp_contract.response_budget, 0)
            player.final_hash = hash
            return player
        end
    )
    return survivors:wait(deadline)
end

local function run_referee(dapp_contract)
    local tournament = { dapp_contract = dapp_contract, players = {} }
    for index, sender in ipairs(server:accept_subscribers(dapp_contract.initial_state_hash)) do
        tournament.players[sender] = { index = index, label = sender.label, allowance = dapp_contract.max_allowance }
    end
    local initial <close> = server:request_all(EVERYONE, EVENTS.initial_state, { dapp_contract.initial_state_hash })
    initial:wait()
    for index, path in ipairs(dapp_contract.input_paths) do
        local input <close> = server:request_all(EVERYONE, EVENTS.input_added, { index - 1, path })
        input:wait()
    end
    local sealed <close> = server:request_all(EVERYONE, EVENTS.epoch_sealed, { #dapp_contract.inputs })
    sealed:wait()
    tournament.players = request_claims(tournament)
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
            run_referee(self.dapp_contract)
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
