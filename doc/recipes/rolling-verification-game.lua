-- A two-player verification game over an epoch of a Rolling Cartesi Machine.
-- Only the referee receives input paths. Players find their initial snapshot under
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
local EVENTS, EVERYONE = vgu.EVENTS, vgu.EVERYONE
local phase, eventf, short_hash = vgu.phase, vgu.eventf, vgu.short_hash
local get_other_turn_index = vgu.get_other_turn_index
local MCYCLES_PER_INPUT = 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local UARCH_CYCLES_PER_MCYCLE = 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local INPUTS_PER_EPOCH = 1 << 16
local RESPONSE_BUDGET, ALLOWANCE = 1, 4
local OUTPUT_WINDOW = 4
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE

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

-- Both sides select the same half and descend to the next coordinate when a
-- level reaches one transition. Only a uarch leaf is ready for a transition log.
local function advance_interval(interval, agree)
    local lo, hi = interval.lo, interval.hi
    if agree then
        lo = midpoint(interval)
    else
        hi = midpoint(interval)
    end
    local next_interval = {
        level = interval.level,
        lo = lo,
        hi = hi,
        input = interval.input,
        mcycle = interval.mcycle,
    }
    if hi - lo == 1 then
        if interval.level == "input" then
            next_interval.input = lo
            next_interval.level, next_interval.lo, next_interval.hi = "mcycle", 0, MCYCLES_PER_INPUT
        elseif interval.level == "mcycle" then
            next_interval.mcycle = lo
            next_interval.level, next_interval.lo, next_interval.hi = "uarch_cycle", 0, UARCH_CYCLES_PER_MCYCLE
        end
    end
    return next_interval
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
    local pair = setmetatable({}, advancing_pair_meta)
    for key, value in pairs(self) do
        pair[key] = value
    end
    for key in pairs(self) do
        self[key] = nil
    end
    return pair
end

function advancing_pair_methods:fork()
    local clone <close> = setmetatable({}, advancing_pair_meta)
    for key, value in pairs(self) do
        if key ~= "machine" and key ~= "backup" then
            clone[key] = value
        end
    end
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
    for _, key in ipairs({ "latest", "agreed", "tentative", "input_boundary" }) do
        if self[key] then
            self[key]:close()
            self[key] = nil
        end
    end
end
player_meta.__close = player_methods.close

-- Transfer construction state out of a <close> local without closing its resources.
function player_methods:move()
    local player = setmetatable({}, player_meta)
    for name, value in pairs(self) do
        player[name] = value
    end
    for name in pairs(self) do
        self[name] = nil
    end
    return player
end

-- Bisection keeps or discards a whole advancing pair, never an input snapshot.
function player_methods:snapshot(source)
    assert(not self.tentative, "previous midpoint has not been resolved")
    self.tentative = (source or self.agreed):fork()
    return self.tentative
end

function player_methods:commit()
    assert(self.tentative, "no bisection snapshot")
    self.agreed:close()
    self.agreed, self.tentative = self.tentative, nil
end

function player_methods:revert()
    assert(self.tentative, "no bisection snapshot")
    self.tentative:close()
    self.tentative = nil
end

function player_methods:take_branch(branch)
    if branch == "agree" then
        self:commit()
    elseif branch == "disagree" then
        self:revert()
    end
end

-- Automatic yields go to the optional callback. The caller handles manual yields.
function player_methods:run_to_stop(pair, _epoch_input_offset, mcycle_end, on_yield_automatic) -- luacheck: ignore 212 self
    local machine = pair.machine
    while true do
        local break_reason = machine:run(mcycle_end)
        if is_at_fixed_point(break_reason) or is_target_mcycle(break_reason) then
            return break_reason
        elseif is_yielded_automatic(break_reason) then
            if on_yield_automatic then
                local yield_reason, data = receive_cmio_request(machine)
                on_yield_automatic(yield_reason, data)
            end
        end
    end
end

-- Crossing an input boundary creates the rejection checkpoint before delivery.
local function load_cmio_input(pair, data)
    local machine = pair.machine
    local revert_root_hash = machine:get_root_hash()
    pair:snapshot()
    if data ~= nil then
        machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
    end
end

function player_methods:run_uarch(pair, epoch_input_offset, input_mcycle_offset, target)
    if input_mcycle_offset == 0 and pair.machine:read_reg("uarch_cycle") == 0 and target > 0 then
        load_cmio_input(pair, self.inputs[epoch_input_offset + 1])
    end
    pair.machine:run_uarch(target)
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
-- A cycle target keeps the execution snapshot. A fixed point settles it:
-- rejection reverts, while acceptance and other terminal stops commit.
function player_methods:run_advance_state_input(
    pair,
    epoch_input_offset,
    input_mcycle_offset_end,
    outputs,
    outputs_frontier
)
    local machine = pair.machine
    local input_mcycle_boundary = machine:read_reg("mcycle")
    if input_mcycle_offset_end == 0 then
        local break_reason = machine:run(input_mcycle_boundary)
        local yield_reason = is_yielded_manual(break_reason) and receive_cmio_request(machine) or nil
        return break_reason, yield_reason, input_mcycle_boundary
    end
    local pending = {}
    local function on_yield_automatic(yield_reason, output)
        if outputs and is_tx_output(yield_reason) then
            pending[#pending + 1] = output
        end
    end
    load_cmio_input(pair, self.inputs[epoch_input_offset + 1])
    local mcycle_end = usaturating_add(input_mcycle_boundary, input_mcycle_offset_end)
    local break_reason = self:run_to_stop(pair, epoch_input_offset, mcycle_end, on_yield_automatic)
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
        flush_pending_outputs(pending, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
        pair:commit()
    end
    return break_reason, yield_reason, input_mcycle_boundary
end

-- Replay to an input boundary without collecting outputs. Unposted inputs
-- repeat the final state and need no execution.
function player_methods:run_to_input_boundary(pair, epoch_input_offset_begin, epoch_input_offset_end)
    for epoch_input_offset = epoch_input_offset_begin, math.min(epoch_input_offset_end, #self.inputs) - 1 do
        self:run_advance_state_input(pair, epoch_input_offset, MCYCLES_PER_INPUT)
    end
end

function player_methods:read_input(_index, path) -- luacheck: ignore 212 self
    return util.read_file(path)
end

-- Mcycle bisection replays from a separately owned input boundary. Settling an
-- execution snapshot must not release that checkpoint or change the agreed state.
function player_methods:propose_midpoint(interval)
    local level, target = interval.level, midpoint(interval)
    local source = self.agreed
    if level == "input" and target >= #self.inputs then
        source = self.latest
    elseif level == "mcycle" then
        if not self.input_boundary then
            self.input_boundary = self.agreed:fork()
        end
        source = self.input_boundary
    end
    local tentative = self:snapshot(source)
    if level == "input" then
        if target < #self.inputs then
            self:run_to_input_boundary(tentative, interval.lo, target)
        end
    elseif level == "mcycle" then
        self:run_advance_state_input(tentative, interval.input, target)
    else
        self:run_uarch(tentative, interval.input, interval.mcycle, target)
    end
    return tentative.machine:get_root_hash()
end

-- Resolve our previous proposal, then compare the opponent's proposal locally.
-- The response's agreement and next proposal belong to this one connection.
function player_methods:answer_midpoint(branch, interval, midpoint_hash)
    self:take_branch(branch)
    local agree
    if midpoint_hash then
        agree = self:propose_midpoint(interval) == midpoint_hash
        self:take_branch(agree and "agree" or "disagree")
        interval = advance_interval(interval, agree)
    end
    return interval, agree
end

local function get_machine_word(machine, address)
    address = address & ~(WORD_SIZE - 1)
    return machine:read_memory(address, WORD_SIZE), machine:get_proof(address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
end

-- Protocol handlers are shared and separate from the player's methods and state.
-- The transport passes the receiving player as self.
local event_handler = {}

function event_handler:initial_state(initial_hash)
    assert(self.agreed.machine:get_root_hash() == initial_hash, "initial machine does not match referee's state hash")
end

function event_handler:input_added(epoch_input_offset, path)
    self.inputs[epoch_input_offset + 1] = self:read_input(epoch_input_offset, path)
    self:run_advance_state_input(self.latest, epoch_input_offset, MCYCLES_PER_INPUT, self.outputs, self.outputs_frontier)
end

function event_handler:epoch_sealed()
    self.final_hash = self.latest.machine:get_root_hash()
    local leaves = {}
    for i, output in ipairs(self.outputs) do
        leaves[i] = cartesi.keccak256(output)
    end
    self.output_proofs = hash_tree.frontier_next_proofs(self.previous_outputs_frontier, leaves)
    self.previous_outputs_frontier, self.outputs_frontier = self.outputs_frontier, nil
end

function event_handler:commit_final_hash()
    return self.final_hash
end

function event_handler:commit_bisection(branch, interval, midpoint_hash)
    local agree
    interval, agree = self:answer_midpoint(branch, interval, midpoint_hash)
    return { agree = agree, midpoint_hash = self:propose_midpoint(interval) }
end

function event_handler:commit_log(branch, interval, midpoint_hash)
    local agree
    interval, agree = self:answer_midpoint(branch, interval, midpoint_hash)
    local pair <close> = self.agreed:fork()
    local machine = pair.machine
    local input = self.inputs[interval.input + 1]
    local log
    if interval.mcycle == 0 and interval.lo == 0 and input then
        local before = machine:get_root_hash()
        local send = machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, input, before)
        log = { send_cmio_log = send, step_log = machine:log_step_uarch() }
    elseif interval.lo == cartesi.UARCH_CYCLE_MAX then
        local step = machine:log_step_uarch()
        log = { step_log = step, reset_uarch_log = machine:log_reset_uarch() }
    else
        log = { step_log = machine:log_step_uarch() }
    end
    return { agree = agree, log = log }
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
    local agreed = setmetatable({ machine = machine or new_machine(initial_hash) }, advancing_pair_meta)
    local self <close> = setmetatable({
        label = label or "honest",
        agreed = agreed,
        inputs = {},
        outputs = {},
        event_handler = event_handler,
    }, player_meta)
    machine = agreed.machine
    assert(machine:get_root_hash() == initial_hash, "initial machine snapshot hash mismatch")
    local break_reason = machine:run(machine:read_reg("mcycle"))
    assert(is_yielded_manual(break_reason), "initial machine is not waiting for an input")
    local yield_reason = receive_cmio_request(machine)
    assert(is_rx_accepted(yield_reason), "initial machine did not accept")
    self.latest = self.agreed:fork()
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

-- The referee trusts its own input bytes and verifies the log without a machine.
-- Invalid logs raise an error, which the request's protected validator rejects.
local function verify_state_transition(referee, input, mcycle, uarch_cycle, before, log)
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
    return before
end

local function accept_hash(hash)
    return type(hash) == "string" and #hash == 32 and hash
end
-- Only the requested player's clock runs. The budget discounts a successful
-- response's charge, but does not extend its exclusive deadline.
local function request_move(server, player, event, arguments, accept)
    local started_at = server:get_time()
    local future <close> = server:request_owner(player.connection, event, arguments, accept)
    local deadline = started_at + player.allowance
    local value = future:wait(deadline)
    if value then
        player.allowance = player.allowance - math.max(0, future.accepted_at - started_at - RESPONSE_BUDGET)
    else
        player.allowance, player.forfeited = 0, true
    end
    return value
end
local function timeout_winner(players)
    if players[1].forfeited then
        return not players[2].forfeited and players[2] or nil
    end
    if players[2].forfeited then
        return players[1]
    end
end

-- Bisect one coordinate. The response that selects its last half already
-- proposes the first midpoint of the next coordinate. Keep that pending turn
-- and the endpoint hashes in the shared bisection state.
-- The final uarch response supplies a transition log instead of a midpoint.
local function bisect_level(referee, server, players, level, hi, bisection, input, mcycle)
    phase("bisect_" .. level)
    local lo = 0
    while hi - lo > 1 do
        local interval = { level = level, lo = lo, hi = hi, input = input, mcycle = mcycle }
        local mid = midpoint(interval)
        local other = get_other_turn_index(bisection.turn)
        local terminal = level == "uarch_cycle" and hi - lo == 2
        local response = request_move(
            server,
            players[bisection.turn],
            terminal and EVENTS.commit_log or EVENTS.commit_bisection,
            { bisection.branch, interval, bisection.midpoint_hash },
            function(value)
                if type(value) ~= "table" or (bisection.midpoint_hash and type(value.agree) ~= "boolean") then
                    return
                end
                if terminal then
                    return {
                        agree = value.agree,
                        obtained_state_hash = verify_state_transition(
                            referee,
                            input,
                            mcycle,
                            value.agree and mid or lo,
                            value.agree and bisection.midpoint_hash or bisection.last_agreed_hash,
                            value.log
                        ),
                    }
                end
                if accept_hash(value.midpoint_hash) then
                    return value
                end
            end
        )
        if not response then
            return nil, players[other]
        end
        if bisection.midpoint_hash then
            if response.agree then
                lo, bisection.last_agreed_hash = mid, bisection.midpoint_hash
            else
                hi, bisection.hash_after, bisection.hash_after_proponent = mid, bisection.midpoint_hash, other
            end
            bisection.branch = response.agree and "agree" or "disagree"
            eventf(
                "Player %d %s. %s interval of disagreement is [0x%x, 0x%x].",
                bisection.turn,
                response.agree and "agrees" or "disagrees",
                level,
                lo,
                hi
            )
        end
        if terminal then
            bisection.obtained_state_hash = response.obtained_state_hash
            break
        end
        bisection.midpoint_hash, bisection.turn = response.midpoint_hash, other
    end
    return lo
end

local function settle_dispute(referee, server, players)
    local bisection = {
        last_agreed_hash = referee.initial_hash,
        hash_after = players[1].final_hash,
        hash_after_proponent = 1,
        branch = "start",
    }
    bisection.turn = get_other_turn_index(bisection.hash_after_proponent)
    local input, winner_input = bisect_level(referee, server, players, "input", INPUTS_PER_EPOCH, bisection)
    if not input then
        return winner_input
    end
    local mcycle, winner_mcycle = bisect_level(referee, server, players, "mcycle", MCYCLES_PER_INPUT, bisection, input)
    if not mcycle then
        return winner_mcycle
    end
    -- UARCH_CYCLE_MAX names the last cycle. Its outgoing transition includes reset.
    local uarch_cycle, winner_uarch_cycle =
        bisect_level(referee, server, players, "uarch_cycle", UARCH_CYCLES_PER_MCYCLE, bisection, input, mcycle)
    if not uarch_cycle then
        return winner_uarch_cycle
    end
    eventf("Player %d's transition proof is valid.", bisection.turn)
    if bisection.obtained_state_hash == bisection.hash_after then
        return players[bisection.hash_after_proponent]
    end
    return players[get_other_turn_index(bisection.hash_after_proponent)]
end

-- Output offers are permissionless and have their own bounded demonstration
-- window. Refreshing the audience lets newly connected providers answer too.
-- Empty and invalid offers never consume the opportunity to submit a valid proof.
local function request_output_proof(server, event, arguments, accept)
    local deadline = server:get_time() + OUTPUT_WINDOW
    while server:request_block() < deadline do
        local until_block = math.min(deadline, server:request_block() + 1)
        local proof <close> = server:request_first_valid(EVERYONE, event, arguments, accept)
        local response = proof:wait(until_block)
        if response then
            return response
        end
    end
end

local referee_meta = { __index = {} }
function referee_meta.__index:run(server)
    local connections = server:accept_players(2)
    local players = {}
    self.players = players
    for index, connection in ipairs(connections) do
        players[index] = { connection = connection, index = index, allowance = ALLOWANCE }
    end
    local function announce(event, arguments)
        local responses <close> = server:request_all(EVERYONE, event, arguments)
        responses:wait()
    end
    announce(EVENTS.initial_state, { self.initial_hash })
    for index, path in ipairs(self.input_paths) do
        announce(EVENTS.input_added, { index - 1, path })
    end
    announce(EVENTS.epoch_sealed, { #self.inputs })
    phase("claims")
    for index, player in ipairs(players) do
        player.final_hash = request_move(server, player, EVENTS.commit_final_hash, {}, accept_hash)
        if player.final_hash then
            eventf("Player %d claimed %s.", index, short_hash(player.final_hash))
        end
    end
    local winner
    if not players[1].final_hash or not players[2].final_hash then
        winner = timeout_winner(players)
    elseif players[1].final_hash == players[2].final_hash then
        winner = players[1]
    else
        winner = settle_dispute(self, server, players)
    end
    self.winner = winner
    phase("verdict")
    if not winner then
        eventf("Neither player submitted a final claim.")
        return
    end
    self.final_hash = winner.final_hash
    eventf("Player %d wins. Final state hash: %s", winner.index, cartesi.tohex(winner.final_hash))
    server:open_players()
    local root = request_output_proof(server, EVENTS.prove_outputs_merkle_root, { self.final_hash }, function(response)
        return output_verifier.validate_outputs_merkle_root_response(response, winner.final_hash)
    end)
    if not root then
        eventf("No valid outputs root offered.")
        return
    end
    self.outputs_root = root
    local output = request_output_proof(server, EVENTS.prove_output, { root }, function(response)
        output_verifier.validate_output_response(response, root)
        return response
    end)
    if not output then
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
    advancing_pair_methods = advancing_pair_methods,
    usaturating_add = usaturating_add,
    load_cmio_input = load_cmio_input,
    verify_state_transition = verify_state_transition,
    request_move = request_move,
    advance_interval = advance_interval,
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
