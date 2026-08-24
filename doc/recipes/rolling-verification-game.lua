-- A model of the Cartesi verification game extended to an epoch of a Rolling Cartesi Machine.
--
-- A referee, standing in for the blockchain, mediates a dispute between two players over the
-- state hash an epoch of inputs settles on. The dispute is settled in three bisections, over
-- the epoch's inputs, over the disputed input's 2^48 mcycles, and over the disputed
-- instruction's 2^20 uarch cycles. The transition out of an input boundary includes the input
-- and executes the first uarch step, the transition out of an instruction's last uarch cycle
-- executes one more step of the long-halted uarch and then the reset, carrying any revert, and
-- every other transition is an ordinary uarch step, the same division of the epoch Dave
-- disputes on the blockchain.
--
-- All game logic lives in the referee, which never trusts a player, and knows the epoch's
-- inputs, since they are on the blockchain. The inputs arrive as files holding the ABI-encoded
-- EvmAdvance blobs the blockchain posted, so nobody re-derives them. The narration, the wire
-- protocol, the player plumbing, and the bisection loop live in the vgu.lua module, shared with
-- verification-game.lua.
--
-- Roles, selected by the first argument, and cheats, selected by the second.
--   rolling-verification-game.lua referee   <address> <input> [<input> ...]
--   rolling-verification-game.lua honest    <address> <input> [<input> ...]
--   rolling-verification-game.lua dishonest <address> wrong-input    <index> <cheat-input> <input> [<input> ...]
--   rolling-verification-game.lua dishonest <address> no-rollback    <input> [<input> ...]
--   rolling-verification-game.lua dishonest <address> mid-processing <index> <offset> <uarch-cycle>
--                                            <cheat-input> <input> [<input> ...]
--   rolling-verification-game.lua dishonest <address> extra-input    <extra-input> <input> [<input> ...]

local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local socket = require("socket")
local evmu = require("cartesi.evmu")
local hash_tree = require("cartesi.hash-tree")
local dishonest = require("dishonest")
local vgu = require("vgu")

-- Shorthands for the machinery shared through vgu.lua.
local phase, eventf, short_hash = vgu.phase, vgu.eventf, vgu.short_hash
local take_branch, bisect_level = vgu.take_branch, vgu.bisect_level
local wait_for_any, wait_for_log, wait_for_commitments = vgu.wait_for_any, vgu.wait_for_log, vgu.wait_for_commitments
local read_file, write_file = vgu.read_file, vgu.write_file

-- The schemas this game adds to the shared dictionary.
-- The disputed transition's binary step logs, as raw file bytes. A combined transition
-- carries two logs, an ordinary step just the one.
vgu.SCHEMA_DICT.LogCommitment = {
    send_cmio_log = "Base64",
    step_log = "Base64",
    reset_log = "Base64",
}
-- An output, its proof in the outputs Merkle tree, and the proof tying that tree's root hash
-- into the final state hash.
vgu.SCHEMA_DICT.EpochResult = {
    output = "Base64",
    output_proof = "Proof",
    outputs_merkle_root_proof = "Proof",
}

local TEMPLATE = "rolling-calculator-template"

-- Every input is limited to this many mcycles, matching Dave's LOG2_BARCH_SPAN_TO_INPUT.
-- The uarch cycles per instruction are the emulator's own UARCH_CYCLE_MAX, matching its
-- LOG2_UARCH_SPAN_TO_BARCH.
local MCYCLES_PER_INPUT = 1 << 48

-- Every epoch is limited to this many inputs. The input bisection ranges over all of them,
-- however many the epoch actually received.
local INPUTS_PER_EPOCH = 1 << 16

local NOTICE = "Notice(bytes payload)"

-- Reads an input, an ABI-encoded EvmAdvance blob, from a file. The referee and the players all
-- read the same bytes the blockchain posted.
local function read_input(filename)
    local file <close> = assert(io.open(filename, "rb"))
    return file:read("a")
end

-- Reads the epoch's inputs from the files on the command line, starting at `first`.
-- Inputs are numbered from 0, like every game coordinate, so input `i` is the one included out
-- of input boundary `i`, and the list stores it at position `i + 1`.
local function read_inputs(first)
    local inputs = {}
    for index = first, #arg do
        inputs[index - first + 1] = read_input(arg[index])
    end
    assert(#inputs > 0, "missing input files")
    return inputs
end

--------------------------------------------------------------------------------
-- Players
--------------------------------------------------------------------------------

-- Instantiates the rolling calculator template on its own freshly spawned server. The template
-- is stored at its first manual yield, standing ready for the epoch's first input.
local function new_remote_machine()
    local server = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    server:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    return server(TEMPLATE)
end

-- Runs a machine towards the target mcycle, resuming through automatic yields and collecting
-- each output they carry into `sink` (when given), until it reaches the target, yields manual,
-- or halts.
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

-- A machine that rejected its input must stand at the recorded revert state, so its server is
-- shut down and it trades places with a fresh fork of the machine it reverts to, which is left
-- untouched. Whoever holds the rejecting machine now holds the reverted one. Any other machine
-- passes through, along with the data its request carried.
-- docs:begin revert_if_rejected
local function revert_if_rejected(_player, machine, revert_machine)
    local _, request_reason, data = machine:receive_cmio_request()
    if request_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
        machine:shutdown_server()
        machine:swap(assert(revert_machine:fork_server()))
        return request_reason
    end
    return request_reason, data
end
-- docs:end revert_if_rejected

-- Feeds one input and runs it out, leaving the machine at the next input boundary and
-- returning the reason of the request it yielded and, on acceptance, the outputs Merkle root
-- the guest reported. An index past the epoch's last input carries no data and leaves the
-- machine untouched. The run's target lies far past any yield, and a yielded machine no longer
-- advances, so the run just stops at the accept or reject request. The snapshot taken at the
-- feed is the recorded revert state. Inputs are typically accepted, and an accepted input
-- passes through the revert untouched, so a player crosses a whole epoch on the same server
-- while the snapshot beside it comes and goes.
-- docs:begin advance
local function advance(player, machine, data, sink)
    if not data then
        return
    end
    local snapshot = assert(machine:fork_server())
    local revert_root_hash = machine:get_root_hash()
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
    run_to(machine, machine:read_reg("mcycle") + MCYCLES_PER_INPUT, sink)
    local request_reason, accept_data = player:revert_if_rejected(machine, snapshot)
    snapshot:shutdown_server()
    return request_reason, accept_data
end
-- docs:end advance

-- The claimed final state. Forks the agreed machine, processes the whole epoch through it, and
-- reports the final root hash. Along the way it collects the epoch result prove_output()
-- answers with later: each accepted input's outputs are folded into the outputs Merkle tree
-- frontier, checked against the root hash the guest reported, and the accepting state's
-- tx-buffer word proof is kept, tying that root hash into the state hash. Once the epoch
-- closes, the frontier proves the last output against the final root.
local function commit_final_hash(player)
    local machine = assert(player.agreed.machine:fork_server())
    local genesis_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    local frontier = hash_tree.frontier_copy(genesis_frontier)
    local outputs, leaves, root_hash_proof = {}, {}, nil
    for _, data in ipairs(player.inputs) do
        local sink = {}
        local request_reason, reported_root = player:advance(machine, data, sink)
        if request_reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            for _, output in ipairs(sink) do
                outputs[#outputs + 1] = output
                leaves[#leaves + 1] = cartesi.keccak256(output)
                hash_tree.frontier_push_back(frontier, leaves[#leaves])
            end
            assert(hash_tree.frontier_get_root_hash(frontier) == reported_root, "outputs Merkle root mismatch")
            root_hash_proof = machine:get_proof(cartesi.AR_CMIO_TX_BUFFER_START, cartesi.HASH_TREE_LOG2_WORD_SIZE)
        end
    end
    player.epoch_result = {
        output = outputs[#outputs],
        output_proof = hash_tree.frontier_next_proofs(genesis_frontier, leaves)[#leaves],
        outputs_merkle_root_proof = root_hash_proof,
    }
    player.final_hash = machine:get_root_hash()
    machine:shutdown_server()
    return player.final_hash
end

-- One bisection round. After taking the previous branch, the player forks the agreed entry,
-- advances the fork to the target on the round's level, and returns its root hash. The input
-- level advances whole inputs. The mcycle level runs to an offset from the disputed input's
-- boundary, including the input first when the fork still stands there, and reverts a fork
-- that finds the guest rejecting back to the boundary. The uarch_cycle level runs the
-- microarchitecture within the disputed instruction, again including the input first when that
-- instruction is the one that resumes the machine.
-- docs:begin commit_bisection
local function commit_bisection(player, branch, level, target)
    take_branch(player, branch)
    local agreed = player.agreed
    if level == "input" then
        local machine = assert(agreed.machine:fork_server())
        for index = agreed.input_index + 1, target do
            player:advance(machine, player.inputs[index])
        end
        player.tentative = { machine = machine, input_index = target }
    else
        -- The first round below the input level pins the disputed input and its boundary, the
        -- recorded revert state any rejecting fork reverts to.
        local boundary = player.boundary
            or {
                machine = assert(agreed.machine:fork_server()),
                mcycle = agreed.machine:read_reg("mcycle"),
                data = player.inputs[agreed.input_index + 1],
            }
        player.boundary = boundary
        local machine = assert(agreed.machine:fork_server())
        if not agreed.offset and boundary.data then
            local revert_root_hash = machine:get_root_hash()
            machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, boundary.data, revert_root_hash)
        end
        local offset = agreed.offset or 0
        if level == "mcycle" then
            offset = target
            if run_to(machine, boundary.mcycle + target) == cartesi.BREAK_REASON_YIELDED_MANUALLY then
                player:revert_if_rejected(machine, boundary.machine)
            end
        else
            machine:run_uarch(target)
        end
        player.tentative = { machine = machine, input_index = agreed.input_index, offset = offset }
    end
    return player.tentative.machine:get_root_hash()
end
-- docs:end commit_bisection

-- The terminal round, once the bisections have isolated the disputed transition, named by its
-- mcycle offset and uarch cycle. The last branch leaves the agreed machine right before it. The
-- transition out of an input boundary includes the input, when there is one, before the first
-- uarch step, the one out of an instruction's last uarch cycle executes one more step and then
-- the reset, and every other is an ordinary step. A combined transition is committed as its two
-- logs, each performing the action it records.
-- docs:begin commit_log
-- Both players run in the referee's directory, so each names its log files by its role.
local step_log_name = arg[1] .. "-step.log"
local reset_log_name = arg[1] .. "-reset.log"
local cmio_log_name = arg[1] .. "-cmio.log"

local function commit_log(player, branch, mcycle_offset, uarch_cycle)
    take_branch(player, branch)
    local agreed = player.agreed.machine
    if mcycle_offset == 0 and uarch_cycle == 0 and player.boundary.data then
        os.remove(cmio_log_name)
        agreed:log_send_cmio_response(
            cartesi.HTIF_YIELD_REASON_ADVANCE_STATE,
            player.boundary.data,
            agreed:get_root_hash(),
            cmio_log_name
        )
        os.remove(step_log_name)
        agreed:log_step_uarch(1, step_log_name)
        return { send_cmio_log = read_file(cmio_log_name), step_log = read_file(step_log_name) }
    end
    os.remove(step_log_name)
    agreed:log_step_uarch(1, step_log_name)
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX - 1 then
        os.remove(reset_log_name)
        agreed:log_reset_uarch(reset_log_name)
        return { step_log = read_file(step_log_name), reset_log = read_file(reset_log_name) }
    end
    return { step_log = read_file(step_log_name) }
end
-- docs:end commit_log

-- The epoch result captured during commit_final_hash. Posting it is a player's last act, so it
-- marks itself done and its serve loop exits right after this reply, once the boundary fork is
-- released. The send_result_delay is a demo-ordering device, not protocol: the honest player
-- holds its reply back so the loser's invalid result arrives, and is rejected, first.
local function prove_output(player)
    socket.sleep(player.send_result_delay)
    if player.boundary then
        player.boundary.machine:shutdown_server()
    end
    player.done = true
    return player.epoch_result
end

-- A player bundles this game's operations with the machine it was handed (bare or the
-- composite), standing at the epoch's start, and with the inputs it claims the epoch takes.
local function new_player(machine, inputs, send_result_delay)
    return vgu.new_player({
        agreed = { machine = machine, input_index = 0 },
        inputs = inputs,
        send_result_delay = send_result_delay,
        advance = advance,
        revert_if_rejected = revert_if_rejected,
        commit_final_hash = commit_final_hash,
        commit_bisection = commit_bisection,
        commit_log = commit_log,
        prove_output = prove_output,
    })
end

--------------------------------------------------------------------------------
-- Referee
--------------------------------------------------------------------------------

-- Asks both players for the result and returns the first epoch result to arrive.
local function wait_for_output(players)
    return wait_for_any(players, "EpochResult", "return player:prove_output()")
end

-- Checks an epoch result against a verified final hash. The outputs Merkle root proof must
-- be whole-machine, sit at the tx-buffer word, and roll up to the final hash. The output
-- proof's root must be the value that word holds, and its target the hash of the output itself.
-- Returns whether it all holds.
-- docs:begin verify_result
local function verify_result(result, final_hash)
    local outputs_merkle_root_proof, output_proof = result.outputs_merkle_root_proof, result.output_proof
    return outputs_merkle_root_proof.root_hash == final_hash
        and outputs_merkle_root_proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE
        and outputs_merkle_root_proof.target_address == cartesi.AR_CMIO_TX_BUFFER_START
        and outputs_merkle_root_proof.log2_target_size == cartesi.HASH_TREE_LOG2_WORD_SIZE
        and pcall(hash_tree.verify_slice, outputs_merkle_root_proof)
        and cartesi.keccak256(output_proof.root_hash) == outputs_merkle_root_proof.target_hash
        and pcall(hash_tree.verify_slice, output_proof)
        and cartesi.keccak256(result.output) == output_proof.target_hash
end
-- docs:end verify_result

-- Verifies the disputed transition's logs on their own, the way a Cartesi contract would on the
-- blockchain, without ever instantiating a machine. Every transition carries a uarch step, the
-- one out of an input boundary precedes it with the input inclusion, and the one out of an
-- instruction's last uarch cycle follows it with the reset. Each verification returns the state
-- hash its log provably advances to, the next one starts from it, and the last must reach the
-- committed after-hash. The disputed input is named by its index and taken from the dapp
-- contract's own copy of the epoch's inputs, never from a player, so a log that includes any
-- other input fails, however consistent it is. Past the epoch's last input the contract holds
-- no input, there is nothing to include, and the transition reduces to an ordinary step. A
-- rejected log raises an error, and pcall turns it into a false verdict.
-- docs:begin verify_state_transition
local function verify_state_transition(
    dapp_contract,
    input,
    mcycle_offset,
    uarch_cycle,
    state_hash_before,
    log,
    state_hash_after
)
    local machine = cartesi.machine
    local data = dapp_contract.inputs[input + 1]
    local pass = pcall(function()
        local hash = state_hash_before
        if mcycle_offset == 0 and uarch_cycle == 0 and data then
            eventf("Verifying input inclusion log!")
            local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
            write_file("posted-cmio.log", log.send_cmio_log)
            hash = machine:verify_send_cmio_response(reason, data, hash, "posted-cmio.log", hash)
        end
        eventf("Verifying uarch step log!")
        write_file("posted-step.log", log.step_log)
        hash = machine:verify_step_uarch(hash, "posted-step.log", 1)
        if uarch_cycle == cartesi.UARCH_CYCLE_MAX - 1 then
            eventf("Verifying uarch reset log!")
            write_file("posted-reset.log", log.reset_log)
            hash = machine:verify_reset_uarch(hash, "posted-reset.log")
        end
        assert(hash == state_hash_after, "log does not reach the committed after-hash")
    end)
    eventf("Log is %s!", pass and "valid" or "invalid")
    return pass
end
-- docs:end verify_state_transition

-- Drives the interactive dispute and returns the winner. It shrinks the interval of
-- disagreement in three bisections, to the input whose processing diverges, to the disputed
-- mcycle offset within it, and to the disputed uarch cycle within that, tracking the
-- agreed lower-end hash and player 1's after-hash in `state`. At the disputed transition it
-- hands player 1's logs to verify_state_transition, which checks them standalone against the
-- agreed before-hash, the committed after-hash, and the contract's own copy of the disputed
-- input. If they prove, player 1 won, otherwise player 2 is the honest one.
-- docs:begin settle_dispute
local function settle_dispute(players, initial_hash, dapp_contract)
    local bisection = { last_agreed_hash = initial_hash, hash_after = players[1].final_hash, branch = "start" }

    -- Bisect to the disputed input
    local input = bisect_level(players, "input", INPUTS_PER_EPOCH, bisection)
    -- Narrow down to the disputed main-processor instruction.
    local mcycle_offset = bisect_level(players, "mcycle", MCYCLES_PER_INPUT, bisection)
    -- Narrow down to the uarch instruction.
    local uarch_cycle = bisect_level(players, "uarch_cycle", cartesi.UARCH_CYCLE_MAX, bisection)

    phase("verdict")
    local log = wait_for_log(players[1], bisection.branch, mcycle_offset, uarch_cycle)
    eventf("Player 1 posted logs")

    -- Player 1 won if its logs verify against the agreed before-hash, otherwise player 2 is honest.
    local winner = verify_state_transition(
        dapp_contract,
        input,
        mcycle_offset,
        uarch_cycle,
        bisection.last_agreed_hash,
        log,
        bisection.hash_after
    ) and players[1] or players[2]
    eventf("Player %d wins! Final state hash is %s.", winner.index, short_hash(winner.final_hash))
    return winner
end
-- docs:end settle_dispute

-- Waits for the result, an output that proves into the winner's committed final state. It takes
-- the first posted result that verifies, since the loser's proofs cannot match, and keeps
-- asking until one arrives. The honest player holds its reply back so the loser's invalid
-- result is rejected first.
local function wait_for_result(players, final_hash)
    phase("output")
    while true do
        local result = wait_for_output(players)
        local payload = evmu.decode_calldata(NOTICE, result.output, "raw").payload
        if verify_result(result, final_hash) then
            eventf("Result posted:\n%sAccepted!", payload)
            return
        end
        eventf("Result posted:\n%sRejected!", payload)
    end
end

-- Runs the whole game in three steps. It collects both players' committed final hashes, settles
-- any dispute over them to name the honest winner, then posts the result that verifies against
-- the winner's hash. Equal commitments mean no dispute, so either player's hash is the true one.
local function run_referee(referee, dapp_contract)
    local players = wait_for_commitments()

    local winner = players[1]
    if players[1].final_hash ~= players[2].final_hash then
        winner = settle_dispute(players, referee.initial_hash, dapp_contract)
    end

    wait_for_result(players, winner.final_hash)
end

-- Models application deployment, returning the contract context the referee works against. The
-- epoch's inputs are all posted to the blockchain, so the contract holds its own copy of
-- every one, the copy that verification trusts over anything a player commits.
local function deploy(inputs)
    return { inputs = inputs }
end

-- Builds a referee for the epoch. The rolling template is stored ready to take its first input,
-- so the agreed starting state hash is its own root hash, what a freshly deployed application
-- looks like to the blockchain.
local function new_referee()
    local template = cartesi.machine(TEMPLATE)
    return { initial_hash = template:get_root_hash(), run = run_referee }
end

--------------------------------------------------------------------------------
-- Role dispatch
--------------------------------------------------------------------------------

local role = assert(arg[1], "missing role (referee, honest, or dishonest)")

if role == "referee" then
    local dapp_contract = deploy(read_inputs(3))
    local referee = new_referee()
    referee:run(dapp_contract)
elseif role == "honest" then
    -- The one-second delay is the demo-ordering device from prove_output: it holds the honest
    -- result back so the dishonest player's invalid result is rejected first in the referee's log.
    local player = new_player(new_remote_machine(), read_inputs(3), 1)
    player:run()
elseif role == "dishonest" then
    local cheat = assert(arg[3], "missing cheat mode (wrong-input, no-rollback, mid-processing, or extra-input)")
    local player
    if cheat == "wrong-input" then
        -- Honest code over a doctored input list, the cheat input standing in at the index.
        local index = assert(tonumber(arg[4]), "missing cheat input index")
        local inputs = read_inputs(6)
        inputs[index + 1] = read_input(assert(arg[5], "missing cheat input file"))
        player = new_player(new_remote_machine(), inputs)
    elseif cheat == "no-rollback" then
        -- Honest code and inputs, minus the revert on rejected inputs.
        player = new_player(new_remote_machine(), read_inputs(4))
        -- Keeps the rejecting machine instead of reverting.
        function player.revert_if_rejected(_player, machine)
            local _, request_reason, data = machine:receive_cmio_request()
            return request_reason, data
        end
        -- The kept machine is parked on its rejected yield, a fixed point no input can enter,
        -- so the feed is skipped for it.
        function player.advance(self, machine, data, sink)
            local _, request_reason = machine:receive_cmio_request()
            if data and request_reason ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                return request_reason
            end
            return advance(self, machine, data, sink)
        end
    elseif cheat == "extra-input" then
        -- Honest code over one input the epoch never received, appended after the real ones.
        local inputs = read_inputs(5)
        inputs[#inputs + 1] = read_input(assert(arg[4], "missing extra input file"))
        player = new_player(new_remote_machine(), inputs)
    elseif cheat == "mid-processing" then
        -- The composite switches to a machine fed the cheat input, at the cheat point.
        local index = assert(tonumber(arg[4]), "missing cheat input index")
        local offset = assert(tonumber(arg[5]), "missing cheat mcycle offset")
        local uarch_cycle = assert(tonumber(arg[6]), "missing cheat uarch cycle")
        local inputs = read_inputs(8)
        player = new_player(
            dishonest.new_rolling_composite_machine(
                new_remote_machine(),
                inputs[index + 1],
                offset,
                uarch_cycle,
                new_remote_machine(),
                read_input(assert(arg[7], "missing cheat input file"))
            ),
            inputs
        )
    else
        error("unknown cheat mode: " .. cheat)
    end
    player:run()
else
    error("unknown role: " .. role)
end
