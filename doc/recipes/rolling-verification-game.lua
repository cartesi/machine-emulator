-- A two-player verification game over an epoch of a Rolling Cartesi Machine.
-- Only the referee receives input filenames. Players find their initial snapshot under
-- its state hash and receive inputs in events. A claim belongs to its submitting connection.
--   rolling-verification-game.lua referee <address> <initial-state-hash> [<input> ...]
--   rolling-verification-game.lua honest <address> <initial-state-hash> [<label>]
-- Dishonest roles and the counterfactual ownership attack live in vg-dishonest.lua and vg-test.lua.
local cartesi = require("cartesi")
local jsonrpc = require("cartesi.jsonrpc")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local evmu = require("cartesi.evmu")
local vgu = require("vgu")
local output_verifier = require("game-output")
local EVENTS = vgu.EVENTS
local phase, eventf, short_hash = vgu.phase, vgu.eventf, vgu.short_hash
local MCYCLES_PER_INPUT = 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local INPUTS_PER_EPOCH = 1 << 16
local RESPONSE_BUDGET, ALLOWANCE = 1, 4
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE

local function usaturating_add(a, b)
    return math.ult(cartesi.MCYCLE_MAX - b, a) and cartesi.MCYCLE_MAX or a + b
end

-- An entry owns its machine and all replay coordinates. Forking copies both together.
local entry_meta = { __index = {} }
function entry_meta.__index.close(self)
    if self.machine then
        self.machine:shutdown_server()
        self.machine = nil
    end
end
entry_meta.__close = entry_meta.__index.close
local function fork_entry(entry)
    local clone = setmetatable({}, entry_meta)
    for key, value in pairs(entry) do
        clone[key] = value
    end
    clone.strategy = {}
    for key, value in pairs(entry.strategy) do
        clone.strategy[key] = value
    end
    clone.machine = assert(entry.machine:fork_server())
    clone.machine:set_cleanup_call(jsonrpc.SHUTDOWN)
    return clone
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
local event_handler = {}

function player_methods.close(self)
    for _, key in ipairs({ "initial", "forward", "agreed", "tentative", "boundary" }) do
        if self[key] then
            self[key]:close()
            self[key] = nil
        end
    end
end
player_meta.__close = player_methods.close

function player_methods.take_branch(self, branch)
    if branch == "agree" then
        assert(self.tentative, "no tentative state to promote")
        self.agreed:close()
        self.agreed = self.tentative
    elseif branch == "disagree" then
        if self.tentative then
            self.tentative:close()
        end
    else
        assert(branch == "start" and not self.tentative, "invalid branch")
    end
    self.tentative = nil
end

function player_methods.run_to(_self, entry, target, sink)
    local machine = entry.machine
    while true do
        local reason = machine:run(target)
        if reason == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            local _, request_reason, data = machine:receive_cmio_request()
            if sink and request_reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
                sink[#sink + 1] = data
            end
        elseif reason ~= cartesi.BREAK_REASON_YIELDED_SOFTLY then
            return reason
        end
    end
end

function player_methods.run_uarch(_self, entry, target)
    entry.machine:run_uarch(target)
end

-- The same delivery and settlement operations drive forward execution and replay.
-- `input_mcycle_offset == nil` means no input has been delivered at this boundary.
function player_methods.deliver_input(self, entry, boundary)
    if entry.input_mcycle_offset ~= nil then
        return
    end
    entry.input_mcycle_boundary = boundary.machine:read_reg("mcycle")
    local data = self.inputs[entry.input_index + 1]
    if data then
        entry.machine:send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            data,
            boundary.machine:get_root_hash()
        )
    end
    entry.input_mcycle_offset = 0
end

function player_methods.revert_if_rejected(_self, entry, boundary)
    if entry.machine:read_reg("iflags_Y") == 0 then
        return
    end
    local _, reason, data = entry.machine:receive_cmio_request()
    if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
        local restored <close> = fork_entry(boundary)
        entry.machine:swap(restored.machine)
        entry.strategy = restored.strategy
    end
    return reason, data
end

-- Run or replay a prefix of the current input, settling rejection the same way
-- at every mcycle target. The offset is relative to the input's virgin boundary.
function player_methods.run_input_to(self, entry, boundary, input_mcycle_offset, sink)
    self:deliver_input(entry, boundary)
    self:run_to(entry, usaturating_add(entry.input_mcycle_boundary, input_mcycle_offset), sink)
    local reason, data = self:revert_if_rejected(entry, boundary)
    entry.input_mcycle_offset = input_mcycle_offset
    return reason, data
end

function player_methods.advance(self, entry, sink)
    if not self.inputs[entry.input_index + 1] then
        return
    end
    local boundary <close> = fork_entry(entry)
    local reason, data = self:run_input_to(entry, boundary, MCYCLES_PER_INPUT, sink)
    entry.input_index, entry.input_mcycle_offset = entry.input_index + 1, nil
    return reason, data
end

function event_handler.initial_state(self, hash)
    assert(not self.started and hash == self.initial_hash, "unexpected initial state")
    self.started = true
    return true
end

function player_methods.read_input(_self, _index, filename)
    return util.read_file(filename)
end

function event_handler.input_added(self, index, filename)
    assert(self.started and not self.sealed, "input outside an open epoch")
    assert(index == #self.inputs and index < INPUTS_PER_EPOCH, "input is repeated or out of order")
    self.inputs[index + 1] = self:read_input(index, filename)
    local pending = {}
    local reason, root = self:advance(self.forward, pending)
    if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
        for output_index, output in ipairs(pending) do
            local hash = cartesi.keccak256(output)
            -- This demo offers only the last output. Retain its proof, replacing
            -- the previous offer only when an accepted input produces a new one.
            if output_index == #pending then
                self.output_proof = hash_tree.frontier_next_proofs(self.outputs_frontier, { hash })[1]
            end
            self.outputs[#self.outputs + 1] = output
            hash_tree.frontier_push_back(self.outputs_frontier, hash)
        end
        assert(hash_tree.frontier_get_root_hash(self.outputs_frontier) == root, "outputs Merkle root mismatch")
    end
    return true
end

function event_handler.epoch_sealed(self, count)
    assert(self.started and not self.sealed and count == #self.inputs, "invalid epoch seal")
    self.sealed = true
    self.final_hash = self.forward.machine:get_root_hash()
    return true
end

function event_handler.commit_final_hash(self)
    assert(self.sealed, "epoch has not been sealed")
    return self.final_hash
end

-- Keep an agreed machine and one tentative fork, retaining a third fork only as the
-- disputed input's rollback boundary. No history tree or checkpoint cache is needed.
function event_handler.commit_bisection(self, arguments)
    assert(self.sealed, "epoch has not been sealed")
    self:take_branch(arguments.branch)
    local agreed, level, target = self.agreed, arguments.level, arguments.target
    local tentative = fork_entry(level == "input" and target >= #self.inputs and self.forward or agreed)
    self.tentative = tentative
    if level == "input" then
        for _ = tentative.input_index + 1, math.min(target, #self.inputs) do
            self:advance(tentative)
        end
        tentative.input_index = target
    else
        if not self.boundary then
            self.boundary = fork_entry(agreed)
        end
        if level == "mcycle" then
            self:run_input_to(tentative, self.boundary, target)
        else
            assert(level == "uarch_cycle", "unknown bisection level")
            self:deliver_input(tentative, self.boundary)
            self:run_uarch(tentative, target)
        end
    end
    return tentative.machine:get_root_hash()
end

function event_handler.commit_log(self, arguments)
    self:take_branch(arguments.branch)
    local entry <close> = fork_entry(self.agreed)
    local machine = entry.machine
    local input = self.inputs[entry.input_index + 1]
    if arguments.mcycle == 0 and arguments.uarch_cycle == 0 and input then
        local before = machine:get_root_hash()
        local log = machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, before)
        return { send_cmio_log = log, step_log = machine:log_step_uarch() }
    end
    if arguments.uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        local log = machine:log_step_uarch()
        return { step_log = log, reset_uarch_log = machine:log_reset_uarch() }
    end
    return { step_log = machine:log_step_uarch() }
end

local function get_machine_word(machine, address)
    address = address & ~(WORD_SIZE - 1)
    return machine:read_memory(address, WORD_SIZE), machine:get_proof(address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
end

function event_handler.prove_outputs_merkle_root(self)
    assert(self.sealed, "epoch has not been sealed")
    local machine = self.forward.machine
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

function event_handler.prove_output(self)
    assert(self.sealed, "epoch has not been sealed")
    if #self.outputs == 0 then
        return {}
    end
    return {
        output_index = #self.outputs - 1,
        output = self.outputs[#self.outputs],
        output_proof = self.output_proof,
    }
end

local function new_player(initial_hash, label, machine)
    local initial =
        setmetatable({ machine = machine or new_machine(initial_hash), input_index = 0, strategy = {} }, entry_meta)
    local self = setmetatable({
        initial_hash = initial_hash,
        label = label or "honest",
        initial = initial,
        inputs = {},
        outputs = {},
        event_handler = event_handler,
        outputs_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"),
    }, player_meta)
    local ok, err = pcall(function()
        assert(initial.machine:get_root_hash() == initial_hash, "initial machine snapshot hash mismatch")
        assert(
            initial.machine:read_reg("iflags_Y") ~= 0
                and initial.machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED,
            "initial machine is not waiting for an input"
        )
        self.forward = fork_entry(initial)
        self.agreed = fork_entry(initial)
    end)
    if not ok then
        self:close()
        error(err, 0)
    end
    return self
end

-- The referee trusts its own input bytes and verifies the log without a machine.
local function verify_state_transition(referee, input, mcycle, uarch_cycle, before, log, after)
    local data = referee.inputs[input + 1]
    if mcycle == 0 and uarch_cycle == 0 and data then
        before = cartesi.machine:verify_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            data,
            before,
            log.send_cmio_log,
            before
        )
    end
    before = cartesi.machine:verify_step_uarch(before, log.step_log)
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
        before = cartesi.machine:verify_reset_uarch(before, log.reset_uarch_log)
    end
    assert(before == after, "log does not reach the committed after-hash")
    return true
end
verify_state_transition = util.protect(verify_state_transition)

local function accept_hash(hash)
    return type(hash) == "string" and #hash == 32 and hash
end
local function accept_table(value)
    return type(value) == "table" and value
end

-- Each request starts its own clock. Sequential waits do not charge a player for
-- an opponent's delay because the transport records when each answer was accepted.
local move_meta = { __index = {} }
function move_meta.__close(self)
    self.future:close()
end
function move_meta.__index.wait(self)
    local player, future = self.player, self.future
    local deadline = self.started_at + RESPONSE_BUDGET + player.allowance
    local value = future:wait(deadline)
    local ended_at = value and future.accepted_at or deadline
    player.allowance = math.max(0, player.allowance - math.max(0, ended_at - self.started_at - RESPONSE_BUDGET))
    if not value then
        player.forfeited = true
    end
    return value
end
local function start_move(server, player, event, arguments, accept)
    return setmetatable({
        future = server:request_owner(player.connection, event, arguments, accept),
        started_at = server:get_time(),
        player = player,
    }, move_meta)
end
local function request_move(server, player, event, arguments, accept)
    local move <close> = start_move(server, player, event, arguments, accept)
    return move:wait()
end
local function request_pair(server, players, event, arguments)
    local first <close> = start_move(server, players[1], event, arguments, accept_hash)
    local second <close> = start_move(server, players[2], event, arguments, accept_hash)
    return { first:wait(), second:wait() }
end
local function timeout_winner(players)
    if players[1].forfeited then
        return not players[2].forfeited and players[2] or nil
    end
    if players[2].forfeited then
        return players[1]
    end
end

local function bisect_level(server, players, level, hi, state)
    phase("bisect_" .. level)
    local lo = 0
    while math.ult(1, hi - lo) do
        local mid = lo + ((hi - lo) >> 1)
        local hashes = request_pair(
            server,
            players,
            EVENTS.commit_bisection,
            { { branch = state.branch, level = level, target = mid } }
        )
        if not hashes[1] or not hashes[2] then
            return nil
        end
        if hashes[1] == hashes[2] then
            lo, state.before, state.branch = mid, hashes[1], "agree"
        else
            hi, state.after, state.branch = mid, hashes[1], "disagree"
        end
        eventf("%s interval of disagreement is [0x%x, 0x%x].", level, lo, hi)
    end
    return lo
end

local function settle_dispute(referee, server, players)
    local state = { before = referee.initial_hash, after = players[1].final_hash, branch = "start" }
    local input = bisect_level(server, players, "input", INPUTS_PER_EPOCH, state)
    if not input then
        return timeout_winner(players)
    end
    local mcycle = bisect_level(server, players, "mcycle", MCYCLES_PER_INPUT, state)
    if not mcycle then
        return timeout_winner(players)
    end
    -- UARCH_CYCLE_MAX names the last cycle. Its outgoing transition includes reset.
    local uarch_cycle = bisect_level(server, players, "uarch_cycle", cartesi.UARCH_CYCLE_MAX + 1, state)
    if not uarch_cycle then
        return timeout_winner(players)
    end
    local log = request_move(
        server,
        players[1],
        EVENTS.commit_log,
        { { branch = state.branch, mcycle = mcycle, uarch_cycle = uarch_cycle } },
        accept_table
    )
    local valid = log and verify_state_transition(referee, input, mcycle, uarch_cycle, state.before, log, state.after)
    referee.transition = { input = input, mcycle = mcycle, uarch_cycle = uarch_cycle, valid = not not valid }
    eventf("Player 1's transition proof is %s.", valid and "valid" or "invalid")
    return valid and players[1] or players[2]
end

local referee_meta = { __index = {} }
function referee_meta.__index.run(self, server)
    local connections = server:accept_players(2)
    local players = {}
    self.players = players
    for index, connection in ipairs(connections) do
        players[index] = { connection = connection, index = index, allowance = ALLOWANCE }
    end
    local function announce(event, arguments)
        local responses <close> = server:request_all(nil, event, arguments)
        responses:wait()
    end
    announce(EVENTS.initial_state, { self.initial_hash })
    for index, filename in ipairs(self.input_paths) do
        announce(EVENTS.input_added, { index - 1, filename })
    end
    announce(EVENTS.epoch_sealed, { #self.inputs })
    phase("claims")
    local hashes = request_pair(server, players, EVENTS.commit_final_hash, {})
    for index, player in ipairs(players) do
        player.final_hash = hashes[index]
        if player.final_hash then
            eventf("Player %d claimed %s.", index, short_hash(player.final_hash))
        end
    end
    local winner
    if not hashes[1] or not hashes[2] then
        winner = timeout_winner(players)
    elseif hashes[1] == hashes[2] then
        winner = players[1]
    else
        winner = settle_dispute(self, server, players)
    end
    self.winner = winner
    phase("verdict")
    if not winner then
        eventf("Both players forfeited. No winner.")
        return
    end
    self.final_hash = winner.final_hash
    eventf("Player %d wins. Final state hash: %s", winner.index, cartesi.tohex(winner.final_hash))
    local root = request_move(server, winner, EVENTS.prove_outputs_merkle_root, {}, function(response)
        return output_verifier.validate_outputs_merkle_root_response(response, winner.final_hash)
    end)
    if not root then
        eventf("No valid outputs root offered.")
        return
    end
    self.outputs_root = root
    local output = request_move(server, winner, EVENTS.prove_output, {}, function(response)
        if next(response) == nil then
            return response
        end
        output_verifier.validate_output_response(response, root)
        return response
    end)
    if not output or not output.output then
        eventf("No output offered.")
        return
    end
    self.output = output
    local ok, decoded = pcall(evmu.decode_calldata, "Notice(bytes payload)", output.output, "raw")
    if ok then
        eventf("Result proved against the final state:\n%s", decoded.payload)
    end
end

local function new_referee(initial_hash, input_paths)
    assert(#initial_hash == 32 and #input_paths <= INPUTS_PER_EPOCH, "invalid epoch")
    local inputs = {}
    for index, path in ipairs(input_paths) do
        inputs[index] = util.read_file(path)
    end
    return setmetatable({ initial_hash = initial_hash, input_paths = input_paths, inputs = inputs }, referee_meta)
end

local vg = {
    new_player = new_player,
    new_referee = new_referee,
    event_handler = event_handler,
    player_methods = player_methods,
    fork_entry = fork_entry,
    usaturating_add = usaturating_add,
    verify_state_transition = verify_state_transition,
    request_pair = request_pair,
}
if ... == "rolling-verification-game" then
    return vg
end
local role, address = assert(arg[1], "missing role"), assert(arg[2], "missing referee address")
local initial_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
if role == "referee" then
    vgu.run_server(new_referee(initial_hash, { table.unpack(arg, 4) }), address)
    vgu.close_narration()
elseif role == "honest" then
    local player <close> = new_player(initial_hash, arg[4])
    vgu.run_client(player, address)
else
    error("unknown role: " .. role)
end
