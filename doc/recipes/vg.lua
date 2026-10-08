-- A verification game over an epoch of a Rolling Cartesi Machine.
-- The referee role's runner simulates blockchain input and epoch events before the dispute.
-- Players find their initial snapshot under its state hash. A claim belongs to its submitting connection.
--   vg.lua referee <address> <initial-state-hash> [<input> ...]
--   vg.lua honest <address> <initial-state-hash> [<label>]
--   vg.lua phase_closer <address> [stop]
-- Dishonest roles and the counterfactual ownership attack live in vg-dishonest.lua and vg-test.lua.
local cartesi = require("cartesi")
local jsonrpc = require("cartesi.jsonrpc")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local vgu = require("vgu")
local output_verifier = require("game-output")
local EVENTS = vgu.EVENTS
-- A nil audience broadcasts to every live player connection.
local ANYONE = nil
local FOREVER = nil
local story = vgu.story
local addresses = vgu.addresses
local LOG2_INPUTS_PER_EPOCH = 16
local LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local LOG2_MAX_UARCH_CYCLES_PER_MCYCLE = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local INPUTS_PER_EPOCH = 1 << LOG2_INPUTS_PER_EPOCH
local MAX_MCYCLES_PER_ADVANCE_STATE = 1 << LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
local DEFAULT_MACHINE_CACHE_CAPACITY = 8
local DEFAULT_MACHINE_CACHE_INPUT_GAP = 1

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

local function is_single_uarch_cycle(extent)
    return extent.log2_input_count == 0 and extent.log2_mcycle_count == 0 and extent.log2_uarch_cycle_count == 0
end

-- Halve the first non-unit count and return the tentative position halfway through the range.
-- docs:begin bisect_interval
local function bisect_interval(interval)
    local extent = interval.extent
    local tentative_position = shallow_copy(interval.agreed_position)
    if extent.log2_input_count > 0 then
        extent.log2_input_count = extent.log2_input_count - 1
        tentative_position.epoch_input_offset = tentative_position.epoch_input_offset + (1 << extent.log2_input_count)
    elseif extent.log2_mcycle_count > 0 then
        extent.log2_mcycle_count = extent.log2_mcycle_count - 1
        tentative_position.input_mcycle_offset = tentative_position.input_mcycle_offset
            + (1 << extent.log2_mcycle_count)
    elseif extent.log2_uarch_cycle_count > 0 then
        extent.log2_uarch_cycle_count = extent.log2_uarch_cycle_count - 1
        tentative_position.uarch_cycle = tentative_position.uarch_cycle + (1 << extent.log2_uarch_cycle_count)
    end
    return tentative_position
end
-- docs:end bisect_interval

local function is_same_position(a, b)
    return a.epoch_input_offset == b.epoch_input_offset
        and a.input_mcycle_offset == b.input_mcycle_offset
        and a.uarch_cycle == b.uarch_cycle
end

-- Bisection between different inputs compares recorded state hashes before inputs.
local function covers_at_least_one_input(agreed_position, tentative_position)
    return agreed_position.epoch_input_offset ~= tentative_position.epoch_input_offset
end

-- At or past its input's fixed point, a position holds the next input's base until a uarch cycle runs.
local function is_past_fixed_point(position, input_mcycle_length)
    return position.uarch_cycle == 0
        and input_mcycle_length ~= nil
        and position.input_mcycle_offset >= input_mcycle_length
end

local function move_machine(machine)
    local moved = cartesi.new()
    machine:swap(moved)
    return moved
end

local function fork_machine(machine)
    local clone = assert(machine:fork_server())
    clone:set_cleanup_call(jsonrpc.SHUTDOWN)
    return clone
end

-- A machine pair owns the working machine and its snapshot while an input is
-- pending. The input mcycle base and expected revert root hash travel with
-- the pair when bisection forks it. Outputs belong to the forward input run.
local machine_pair_meta = { __index = {} }
local machine_pair_methods = machine_pair_meta.__index
function machine_pair_methods:close()
    for _, key in ipairs({ "machine", "backup_machine" }) do
        if self[key] then
            self[key]:shutdown_server()
            self[key] = nil
        end
    end
end
machine_pair_meta.__close = machine_pair_methods.close

function machine_pair_methods:move()
    return setmetatable(shallow_move(self), machine_pair_meta)
end

function machine_pair_methods:fork()
    local clone <close> = setmetatable(shallow_copy(self), machine_pair_meta)
    -- Clear borrowed resources before a failing fork can trigger cleanup.
    clone.machine, clone.backup_machine = nil, nil
    clone.machine = fork_machine(self.machine)
    if self.backup_machine then
        clone.backup_machine = fork_machine(self.backup_machine)
    end
    return clone:move()
end

function machine_pair_methods:snapshot()
    assert(not self.backup_machine, "machine already has a snapshot")
    self.backup_machine = fork_machine(self.machine)
end

function machine_pair_methods:commit()
    if self.backup_machine then
        self.backup_machine:shutdown_server()
        self.backup_machine = nil
    end
end

-- docs:begin revert
function machine_pair_methods:revert()
    local backup_machine = assert(self.backup_machine, "no snapshot to revert to")
    local address = self.machine:get_server_address()
    self.machine:shutdown_server()
    self.machine:swap(backup_machine)
    self.backup_machine = nil
    self.machine:rebind_server(address)
    assert(self.machine:get_root_hash() == self.revert_root_hash, "rollback did not restore the input boundary")
end
-- docs:end revert

local function new_machine_pair(machine)
    local pair <close> = setmetatable({ machine = machine }, machine_pair_meta)
    pair.revert_root_hash = machine:get_root_hash()
    return pair:move()
end

-- A checkpoint is the machine at an input base, before delivery, indexed by the input. The first
-- checkpoint is the initial machine at input zero and is always retained. The epoch run considers
-- every later input base, and the cache retains a bounded set of forks. When the cache is full,
-- a new checkpoint replaces the first one closer than the input gap to its predecessor. If there
-- is none, the gap doubles, so checkpoints spread across the epoch as it grows.
local machine_cache_meta = { __index = {} }
local machine_cache_methods = machine_cache_meta.__index

local function new_machine_cache(initial_machine, capacity, input_gap)
    capacity = capacity or DEFAULT_MACHINE_CACHE_CAPACITY
    input_gap = input_gap or DEFAULT_MACHINE_CACHE_INPUT_GAP
    local cache <close> = setmetatable({
        capacity = capacity,
        input_gap = input_gap,
        replace_cursor = 2,
        last_epoch_input_offset = 0,
        checkpoints = { { epoch_input_offset = 0, machine = initial_machine } },
    }, machine_cache_meta)
    assert(math.type(capacity) == "integer" and capacity > 0, "invalid machine cache capacity")
    assert(math.type(input_gap) == "integer" and input_gap > 0, "invalid machine cache input gap")
    return cache:move()
end

function machine_cache_methods:close()
    for _, checkpoint in ipairs(self.checkpoints or {}) do
        checkpoint.machine:shutdown_server()
    end
    self.checkpoints = nil
end
machine_cache_meta.__close = machine_cache_methods.close

function machine_cache_methods:move()
    return setmetatable(shallow_move(self), machine_cache_meta)
end

-- docs:begin cache_consider
function machine_cache_methods:consider(epoch_input_offset, machine)
    local checkpoints = assert(self.checkpoints, "machine cache is closed or moved")
    assert(epoch_input_offset > self.last_epoch_input_offset, "machine checkpoints are not ordered")
    self.last_epoch_input_offset = epoch_input_offset
    if epoch_input_offset - checkpoints[#checkpoints].epoch_input_offset < self.input_gap then
        return
    end
    local replace_index
    if #checkpoints == self.capacity then
        replace_index = self.replace_cursor
        while replace_index <= #checkpoints do
            local previous = checkpoints[replace_index - 1].epoch_input_offset
            if checkpoints[replace_index].epoch_input_offset - previous < self.input_gap then
                break
            end
            replace_index = replace_index + 1
        end
        if replace_index > #checkpoints then
            self.input_gap = self.input_gap << 1
            self.replace_cursor = 2
            return
        end
    end
    local clone <close> = new_machine_pair(fork_machine(machine))
    if replace_index then
        table.remove(checkpoints, replace_index).machine:shutdown_server()
        self.replace_cursor = replace_index
    end
    checkpoints[#checkpoints + 1] = { epoch_input_offset = epoch_input_offset, machine = clone.machine }
    clone.machine = nil
end
-- docs:end cache_consider

local function find_nearest_checkpoint(cache, epoch_input_offset)
    local checkpoints = assert(cache.checkpoints, "machine cache is closed or moved")
    assert(epoch_input_offset >= 0, "invalid epoch input offset")
    local nearest
    for _, checkpoint in ipairs(checkpoints) do
        if checkpoint.epoch_input_offset > epoch_input_offset then
            break
        end
        nearest = checkpoint
    end
    return nearest
end

-- Fork the nearest retained input boundary not past the requested offset.
function machine_cache_methods:nearest_not_past_epoch_input_offset(epoch_input_offset)
    local checkpoint = find_nearest_checkpoint(self, epoch_input_offset)
    local pair <close> = new_machine_pair(fork_machine(checkpoint.machine))
    return pair:move(), checkpoint.epoch_input_offset
end

-- Take ownership of the received pair and keep it unless a retained checkpoint is strictly nearer.
function machine_cache_methods:nearer_not_past_epoch_input_offset_or(
    pair,
    pair_epoch_input_offset,
    epoch_input_offset_end
)
    local received_pair <close> = assert(pair, "missing machine pair")
    local checkpoint = find_nearest_checkpoint(self, epoch_input_offset_end)
    assert(pair_epoch_input_offset <= epoch_input_offset_end, "pair is past desired input")
    if checkpoint.epoch_input_offset <= pair_epoch_input_offset then
        return received_pair:move(), pair_epoch_input_offset
    end
    local advancing_pair <close>, cached_epoch_input_offset =
        self:nearest_not_past_epoch_input_offset(epoch_input_offset_end)
    received_pair:close()
    return advancing_pair:move(), cached_epoch_input_offset
end

local player_meta = { __index = {} }
local player_methods = player_meta.__index

local function close_pair(pair)
    if pair then
        pair:close()
    end
end

local function close_cache(cache)
    if cache then
        cache:close()
    end
end

function player_methods:close()
    close_pair(self.epoch_pair)
    self.epoch_pair = nil
    close_pair(self.agreed_pair)
    self.agreed_pair = nil
    close_pair(self.tentative_pair)
    self.tentative_pair = nil
    close_cache(self.machine_cache)
    self.machine_cache = nil
end
player_meta.__close = player_methods.close

-- Load the epoch's initial machine from its content-addressed snapshot.
-- Dishonest roles override this to change how the machine executes.
function player_methods:new_machine(initial_state_hash) -- luacheck: ignore 212 self
    local machine <close> = assert(jsonrpc.spawn_server("127.0.0.1:0"))
    machine:load(cartesi.tohex(initial_state_hash))
    assert(machine:get_root_hash() == initial_state_hash, "initial machine snapshot hash mismatch")
    return move_machine(machine)
end

-- Obtain an exact input boundary without exposing checkpoint selection to callers.
function player_methods:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local pair <close>, cached_epoch_input_offset =
        self.machine_cache:nearest_not_past_epoch_input_offset(epoch_input_offset)
    self:run_to_epoch_input_offset(pair, self.inputs, cached_epoch_input_offset, epoch_input_offset)
    return pair:move()
end

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
local function load_cmio_input(machine, input_data, revert_root_hash)
    if input_data ~= nil then
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, revert_root_hash)
    end
end

-- luacheck: push ignore self
function player_methods:run_to_uarch_cycle(pair, input_data, input_mcycle_offset, uarch_cycle_begin, uarch_cycle_end)
    assert(uarch_cycle_begin <= uarch_cycle_end, "agreed machine is past desired state")
    assert(pair.machine:read_reg("uarch_cycle") <= uarch_cycle_end, "agreed machine is past desired state")
    if uarch_cycle_begin == uarch_cycle_end then
        return
    end
    if input_mcycle_offset == 0 and uarch_cycle_begin == 0 then
        pair.input_mcycle_base = pair.machine:read_reg("mcycle")
        pair:snapshot()
        load_cmio_input(pair.machine, input_data, pair.revert_root_hash)
    end
    return pair.machine:run_uarch(uarch_cycle_end)
end

-- Retain only accepted outputs and check their cumulative root.
local function flush_pending_outputs(pending_outputs, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
    if not outputs or not is_rx_accepted(yield_reason) then
        return
    end
    for _, output_data in ipairs(pending_outputs) do
        outputs[#outputs + 1] = output_data
        hash_tree.frontier_push_back(outputs_frontier, cartesi.keccak256(output_data))
    end
    assert(hash_tree.frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")
end

-- Complete logical mcycles within one input. Offset zero is before delivery;
-- the recorded base supplies the absolute origin even after rollback.
-- docs:begin run_to_input_mcycle_offset
function player_methods:run_to_input_mcycle_offset(
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
        pair.input_mcycle_base = pair.machine:read_reg("mcycle")
        pair:snapshot()
        load_cmio_input(pair.machine, input_data, pair.revert_root_hash)
    end
    local machine = pair.machine
    local input_mcycle_base = pair.input_mcycle_base
    local mcycle_end = usaturating_add(input_mcycle_base, input_mcycle_offset_end)
    local pending_outputs = {}
    local on_yield_automatic = outputs
        and function(yield_reason, output_data)
            if is_tx_output(yield_reason) then
                pending_outputs[#pending_outputs + 1] = output_data
            end
        end
    local break_reason = run_to_stop(machine, mcycle_end, on_yield_automatic)
    if not is_at_fixed_point(break_reason) then
        return break_reason, nil, input_mcycle_base
    end
    local input_mcycle_length = machine:read_reg("mcycle") - input_mcycle_base
    local yield_reason, outputs_merkle_root
    if is_yielded_manual(break_reason) then
        yield_reason, outputs_merkle_root = receive_cmio_request(machine)
    end
    if is_rx_rejected(yield_reason) then
        pair:revert()
    else
        flush_pending_outputs(pending_outputs, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
        if is_rx_accepted(yield_reason) then
            pair.revert_root_hash = machine:get_root_hash()
        end
        pair:commit()
    end
    return break_reason, yield_reason, input_mcycle_base, input_mcycle_length
end
-- docs:end run_to_input_mcycle_offset
-- luacheck: pop

-- Replay completed inputs, leaving the next input undelivered. Unposted inputs
-- repeat the final state and need no execution.
function player_methods:run_to_epoch_input_offset(pair, inputs, epoch_input_offset_begin, epoch_input_offset_end)
    for epoch_input_offset = epoch_input_offset_begin, math.min(epoch_input_offset_end, #inputs) - 1 do
        self:run_to_input_mcycle_offset(pair, inputs[epoch_input_offset + 1], 0, MAX_MCYCLES_PER_ADVANCE_STATE)
    end
end

function player_methods:read_input(_index, path) -- luacheck: ignore 212 self
    return util.read_file(path)
end

-- Returns a pair at position_end, starting from a closer checkpoint when the cache has one.
-- docs:begin run_to_position
function player_methods:run_to_position(pair, position_begin, position_end)
    local received_pair <close> = pair
    local advancing_pair <close>, epoch_input_offset = self.machine_cache:nearer_not_past_epoch_input_offset_or(
        received_pair:move(),
        position_begin.epoch_input_offset,
        position_end.epoch_input_offset
    )
    if epoch_input_offset < position_end.epoch_input_offset then
        self:run_to_epoch_input_offset(advancing_pair, self.inputs, epoch_input_offset, position_end.epoch_input_offset)
    end
    if position_begin.input_mcycle_offset < position_end.input_mcycle_offset then
        self:run_to_input_mcycle_offset(
            advancing_pair,
            self.inputs[position_end.epoch_input_offset + 1],
            position_begin.input_mcycle_offset,
            position_end.input_mcycle_offset
        )
    end
    if position_begin.uarch_cycle < position_end.uarch_cycle then
        self:run_to_uarch_cycle(
            advancing_pair,
            self.inputs[position_end.epoch_input_offset + 1],
            position_end.input_mcycle_offset,
            position_begin.uarch_cycle,
            position_end.uarch_cycle
        )
    end
    return advancing_pair:move()
end
-- docs:end run_to_position

-- docs:begin reset_bisection
function player_methods:reset_bisection()
    close_pair(self.agreed_pair)
    close_pair(self.tentative_pair)
    self.agreed_pair = self:new_machine_pair_at_epoch_input_offset(0)
    self.agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 }
    self.tentative_pair = nil
end
-- docs:end reset_bisection

local function get_machine_word(machine, address)
    address = address & ~(WORD_SIZE - 1)
    return machine:read_memory(address, WORD_SIZE), machine:get_proof(address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
end

local function get_outputs_merkle_root_proof(machine)
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

-- Protocol handlers are shared and separate from the player's methods and state.
-- The transport passes the receiving player as self.
local event_handler = {}

-- docs:begin input_added
function event_handler:input_added(epoch_input_offset, path)
    local next_epoch_input_offset = epoch_input_offset + 1
    self.inputs[next_epoch_input_offset] = self:read_input(epoch_input_offset, path)
    local _, _, _, input_mcycle_length = self:run_to_input_mcycle_offset(
        self.epoch_pair,
        self.inputs[next_epoch_input_offset],
        0,
        MAX_MCYCLES_PER_ADVANCE_STATE,
        self.outputs,
        self.outputs_frontier
    )
    self.state_hashes_before_inputs[next_epoch_input_offset] = self.epoch_pair.machine:get_root_hash()
    self.input_mcycle_lengths[epoch_input_offset] = input_mcycle_length
    assert(not self.epoch_pair.backup_machine, "input stopped before completion")
    self.machine_cache:consider(next_epoch_input_offset, self.epoch_pair.machine)
end
-- docs:end input_added

-- Retain the recorded hashes and output proofs after closing the epoch pair.
-- docs:begin epoch_sealed
function event_handler:epoch_sealed()
    -- docs:begin null
    assert(not self.epoch_pair.backup_machine, "cannot seal an unfinished input")
    -- docs:end null
    self.final_state_hash = self.epoch_pair.machine:get_root_hash()
    -- docs:begin null
    assert(
        self.state_hashes_before_inputs[#self.inputs] == self.final_state_hash,
        "state hash before next input does not match final state"
    )
    -- docs:end null
    self.outputs_merkle_root_proof = get_outputs_merkle_root_proof(self.epoch_pair.machine)
    self.epoch_pair:close()
    self.epoch_pair = nil
    local leaves = map(self.outputs, cartesi.keccak256)
    self.output_proofs = hash_tree.frontier_next_proofs(self.previous_outputs_frontier, leaves)
    self.previous_outputs_frontier = self.outputs_frontier
    self.outputs_frontier = nil
end
-- docs:end epoch_sealed

-- docs:begin commit_claim
function event_handler:commit_claim()
    return self.final_state_hash
end
-- docs:end commit_claim

-- docs:begin dispute_started
function event_handler:dispute_started()
    self:reset_bisection()
end
-- docs:end dispute_started

-- docs:begin reveal_bisection
function event_handler:reveal_bisection(agreed_position, tentative_position)
    local epoch_input_offset = tentative_position.epoch_input_offset
    if covers_at_least_one_input(agreed_position, tentative_position) then
        return self.state_hashes_before_inputs[math.min(epoch_input_offset, #self.inputs)]
    end
    if self.tentative_pair then
        if is_same_position(self.agreed_position, agreed_position) then
            self.tentative_pair:close()
        else
            self.agreed_pair:close()
            self.agreed_pair = self.tentative_pair
        end
    else
        self.agreed_pair = self:run_to_position(self.agreed_pair:move(), self.agreed_position, agreed_position)
    end
    self.agreed_position, self.tentative_pair = agreed_position, nil
    if is_past_fixed_point(tentative_position, self.input_mcycle_lengths[epoch_input_offset]) then
        return self.state_hashes_before_inputs[epoch_input_offset + 1]
    end
    self.tentative_pair = self:run_to_position(self.agreed_pair:fork(), agreed_position, tentative_position)
    return self.tentative_pair.machine:get_root_hash()
end
-- docs:end reveal_bisection

-- docs:begin prove_state_transition
function event_handler:prove_state_transition(epoch_input_offset, input_mcycle_offset, uarch_cycle)
    local pair = self.agreed_position.uarch_cycle ~= uarch_cycle and self.tentative_pair or self.agreed_pair
    local machine = pair.machine
    local input_data = self.inputs[epoch_input_offset + 1]
    local proof
    if input_mcycle_offset == 0 and uarch_cycle == 0 and input_data then
        local send =
            machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input_data, pair.revert_root_hash)
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

-- docs:begin prove_outputs_merkle_root
function event_handler:prove_outputs_merkle_root()
    return self.outputs_merkle_root_proof
end
-- docs:end prove_outputs_merkle_root

-- docs:begin prove_output
function event_handler:prove_output()
    if #self.outputs == 0 then
        return {}
    end
    return {
        output_index = self.output_proofs[#self.outputs].target_address,
        output_data = self.outputs[#self.outputs],
        output_proof = self.output_proofs[#self.outputs],
    }
end
-- docs:end prove_output

-- The optional proof bootstraps output history after a previous epoch. Optional
-- overrides of methods or machine cache settings apply before the epoch's pair is loaded.
local function new_player(initial_state_hash, label, last_output_proof, overrides)
    local self <close> = setmetatable({
        label = label or "honest",
        initial_state_hash = initial_state_hash,
        inputs = {},
        state_hashes_before_inputs = { [0] = initial_state_hash },
        input_mcycle_lengths = {},
        machine_cache_capacity = DEFAULT_MACHINE_CACHE_CAPACITY,
        machine_cache_input_gap = DEFAULT_MACHINE_CACHE_INPUT_GAP,
        outputs = {},
        event_handler = event_handler,
    }, player_meta)
    for name, value in pairs(overrides or {}) do
        self[name] = value
    end
    self.epoch_pair = new_machine_pair(self:new_machine(initial_state_hash))
    local machine = self.epoch_pair.machine
    local break_reason = machine:run(machine:read_reg("mcycle"))
    assert(is_yielded_manual(break_reason), "initial machine is not waiting for an input")
    local yield_reason = receive_cmio_request(machine)
    assert(is_rx_accepted(yield_reason), "initial machine did not accept")
    self.machine_cache =
        new_machine_cache(fork_machine(machine), self.machine_cache_capacity, self.machine_cache_input_gap)
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

local function notify_all(subscriptions, event, arguments)
    server:notify_all(subscriptions, event, arguments)
end

local function request_all(subscriptions, event, arguments, validator)
    return server:request_all(subscriptions, event, arguments, validator)
end

local function wait_for_first_valid(subscriptions, event, arguments, validator)
    local request <close> = server:request_first_valid(subscriptions, event, arguments, validator)
    return request:wait_at_most(FOREVER)
end

local function accept_subscribers(initial_state_hash)
    return server:accept_subscribers(initial_state_hash)
end

-- The referee trusts its own input bytes and verifies the logs without a machine.
-- Return the root hash they reach; invalid logs raise an error for the protected validator.
-- docs:begin validate_state_transition_response
local function validate_state_transition_response(
    dapp_contract,
    root_hash_before,
    epoch_input_offset,
    input_mcycle_offset,
    uarch_cycle,
    response
)
    local obtained_root_hash = root_hash_before
    local input_data = dapp_contract.inputs[epoch_input_offset + 1]
    if input_mcycle_offset == 0 and uarch_cycle == 0 and input_data then
        obtained_root_hash = cartesi.machine:verify_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            input_data,
            root_hash_before,
            response.send_cmio_log,
            root_hash_before
        )
    end
    obtained_root_hash = cartesi.machine:verify_step_uarch(obtained_root_hash, response.step_log)
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        obtained_root_hash = cartesi.machine:verify_reset_uarch(obtained_root_hash, response.reset_uarch_log)
    end
    return obtained_root_hash
end
-- docs:end validate_state_transition_response

local function validate_hash_response(hash, message)
    assert(type(hash) == "string" and #hash == 32, message)
    return hash
end

local validate_outputs_merkle_root_response = output_verifier.validate_outputs_merkle_root_response
local validate_output_response = output_verifier.validate_output_response

-- Return a representative if all surviving players support the same final claim.
local function get_winner(players)
    local first
    for _, sender in ipairs(addresses(players)) do
        local player = players[sender]
        if first and player.final_state_hash ~= first.final_state_hash then
            return nil
        end
        first = first or player
    end
    return first
end

local function is_there_at_most_one_claim(players)
    return not next(players) or get_winner(players) ~= nil
end

local function any_of(hashes)
    return hashes[next(hashes)]
end

local function is_unanimous(hashes)
    local first
    for _, hash in pairs(hashes) do
        if first and hash ~= first then
            return false
        end
        first = hash
    end
    return true
end

-- Ask each player for the hash at the tentative position.
-- docs:begin request_bisections
local function request_bisections(dapp_contract, players, agreed_position, tentative_position)
    local started_at = current_time()
    local deadline = fold(players, started_at, function(latest, player)
        return math.max(latest, started_at + player.allowance)
    end)
    local survivors <close> = request_all(
        addresses(players),
        EVENTS.reveal_bisection,
        { agreed_position, tentative_position },
        function(response, sender, received_at)
            local player = players[sender]
            assert(received_at < started_at + player.allowance, "late tentative hash")
            local hash = validate_hash_response(response, "invalid tentative hash")
            local elapsed = received_at - started_at
            player.allowance = player.allowance - math.max(elapsed - dapp_contract.response_budget, 0)
            player.tentative_hash = hash
            return player
        end
    )
    local remaining_players = survivors:wait_at_most(deadline)
    -- docs:begin null
    story.report_bisection_eliminations(players, remaining_players)
    -- docs:end null
    return remaining_players
end
-- docs:end request_bisections

-- Halve the first non-unit count. Any disagreement selects the earlier half.
-- docs:begin isolate_state_transition
local function isolate_state_transition(tournament, interval)
    local players = tournament.players
    while not is_single_uarch_cycle(interval.extent) do
        local tentative_position = bisect_interval(interval)
        -- docs:begin null
        story.report_bisection(interval.agreed_position, tentative_position)
        -- docs:end null
        players = request_bisections(tournament.dapp_contract, players, interval.agreed_position, tentative_position)
        if is_there_at_most_one_claim(players) then
            break
        end
        local hashes = map(players, function(player)
            return player.tentative_hash
        end)
        if is_unanimous(hashes) then
            interval.agreed_position = tentative_position
            interval.last_agreed_hash = any_of(hashes)
        else
            interval.hashes_after = hashes
        end
        -- docs:begin null
        story.report_bisection_progress(interval)
        -- docs:end null
    end
    return players
end
-- docs:end isolate_state_transition

-- Every surviving player must prove its own committed endpoint.
-- docs:begin request_state_transitions
local function request_state_transitions(tournament, interval)
    local agreed_position = interval.agreed_position
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
            assert(received_at < started_at + player.allowance, "late state transition proof")
            local obtained_root_hash = validate_state_transition_response(
                tournament.dapp_contract,
                interval.last_agreed_hash,
                agreed_position.epoch_input_offset,
                agreed_position.input_mcycle_offset,
                agreed_position.uarch_cycle,
                response
            )
            assert(obtained_root_hash == interval.hashes_after[sender], "log does not reach the committed after-hash")
            local elapsed = received_at - started_at
            player.allowance = player.allowance - math.max(elapsed - tournament.dapp_contract.response_budget, 0)
            -- docs:begin null
            story.report_state_transition(player)
            -- docs:end null
            return player
        end
    )
    local remaining_players = survivors:wait_at_most(deadline)
    -- docs:begin null
    story.report_transition_eliminations(tournament.players, remaining_players)
    -- docs:end null
    return remaining_players
end
-- docs:end request_state_transitions

-- docs:begin settle_dispute
local function settle_dispute(tournament)
    notify_all(addresses(tournament.players), EVENTS.dispute_started, {})
    -- docs:begin null
    local round = 0
    -- docs:end null
    while not is_there_at_most_one_claim(tournament.players) do
        -- docs:begin null
        round = round + 1
        story.section("round_" .. round)
        -- docs:end null
        local interval = {
            agreed_position = { epoch_input_offset = 0, input_mcycle_offset = 0, uarch_cycle = 0 },
            extent = {
                log2_input_count = LOG2_INPUTS_PER_EPOCH,
                log2_mcycle_count = LOG2_MAX_MCYCLES_PER_ADVANCE_STATE,
                log2_uarch_cycle_count = LOG2_MAX_UARCH_CYCLES_PER_MCYCLE,
            },
            last_agreed_hash = tournament.dapp_contract.initial_state_hash,
            hashes_after = map(tournament.players, function(player)
                return player.final_state_hash
            end),
        }
        tournament.players = isolate_state_transition(tournament, interval)
        if is_there_at_most_one_claim(tournament.players) then
            break
        end
        tournament.players = request_state_transitions(tournament, interval)
    end
    return get_winner(tournament.players)
end
-- docs:end settle_dispute

-- Establish the outputs root, then accept distinct player-selected outputs until
-- the runner stops the game. Output offers are permissionless after settlement.
-- docs:begin wait_for_outputs
local function wait_for_outputs(final_state_hash)
    local outputs_merkle_root = wait_for_first_valid(
        ANYONE,
        EVENTS.prove_outputs_merkle_root,
        { final_state_hash },
        function(response)
            return validate_outputs_merkle_root_response(response, final_state_hash)
        end
    )
    local accepted_output_indices = {}
    while true do
        local output = wait_for_first_valid(ANYONE, EVENTS.prove_output, { outputs_merkle_root }, function(response)
            if not accepted_output_indices[response.output_index] then
                return validate_output_response(response, outputs_merkle_root)
            end
        end)
        accepted_output_indices[output.output_index] = true
        -- docs:begin null
        story.report_output(output)
        -- docs:end null
    end
end
-- docs:end wait_for_outputs

-- docs:begin request_claims
local function request_claims(dapp_contract, subscribers)
    local started_at = current_time()
    local max_allowance = dapp_contract.max_allowance
    local joining_deadline = started_at + max_allowance
    local claims <close> = request_all(subscribers, EVENTS.commit_claim, {}, function(response, sender, received_at)
        assert(received_at < joining_deadline, "late final hash")
        local hash = validate_hash_response(response, "invalid final hash")
        return {
            label = sender.label,
            allowance = max_allowance - (received_at - started_at),
            final_state_hash = hash,
        }
    end)
    local players = claims:wait_at_most(joining_deadline)
    return {
        dapp_contract = dapp_contract,
        players = players,
    }
end
-- docs:end request_claims

-- Simulate blockchain publication, waiting for each event's handlers before proceeding.
-- docs:begin run_epoch
local function run_epoch(dapp_contract, subscribers)
    for index, path in ipairs(dapp_contract.input_paths) do
        notify_all(subscribers, EVENTS.input_added, { index - 1, path })
    end
    notify_all(subscribers, EVENTS.epoch_sealed, { #dapp_contract.inputs })
end
-- docs:end run_epoch

-- docs:begin run_referee
local function run_referee(dapp_contract, subscribers)
    local tournament = request_claims(dapp_contract, subscribers)
    -- docs:begin null
    story.section("claims")
    story.report_claims(tournament.players)
    -- docs:end null
    local winner = settle_dispute(tournament)
    -- docs:begin null
    story.section("verdict")
    story.report_winner(winner)
    -- docs:end null
    if winner then
        -- docs:begin null
        story.section("outputs")
        -- docs:end null
        wait_for_outputs(winner.final_state_hash)
    end
end
-- docs:end run_referee

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
    machine_pair_methods = machine_pair_methods,
    usaturating_add = usaturating_add,
    covers_at_least_one_input = covers_at_least_one_input,
    is_past_fixed_point = is_past_fixed_point,
    new_machine_cache = new_machine_cache,
    load_cmio_input = load_cmio_input,
    validate_state_transition_response = validate_state_transition_response,
}
if ... == "vg" then
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
