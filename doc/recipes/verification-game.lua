-- A model of the Cartesi verification game.
--
-- A referee, standing in for the blockchain, mediates a dispute between two players, told
-- apart only by connection order. Each controls its own Cartesi machine and claims a final
-- state hash for the same computation. One is honest, the other cheats past a chosen point by
-- switching to a machine that ran a different expression.
--
-- All game logic lives in the referee, which never trusts a player. The players are thin and
-- identical, differing only in the machine they hold, the honest one bare and the dishonest
-- one a composite that reports a fake machine past the cheat point. Each runs Lua code the
-- referee sends against its machine and replies. The fork trick lets it answer bisection
-- queries without re-running from scratch. The narration, the wire protocol, the player
-- plumbing, and the bisection loop live in the vgu.lua module, shared with the rolling variant
-- of the game.
--
-- Roles, selected by the first argument.
--   verification-game.lua referee   <address> <expr>
--   verification-game.lua honest    <address> <expr>
--   verification-game.lua dishonest <address> <expr> <cheat-mcycle> <cheat-uarch-cycle> <cheat-expr>

local cartesi = require("cartesi")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local util = require("cartesi.util")
local socket = require("socket")
local hash_tree = require("cartesi.hash-tree")
local dishonest = require("dishonest")
local vgu = require("vgu")

-- Shorthands for the machinery shared through vgu.lua.
local phase, eventf, short_hash = vgu.phase, vgu.eventf, vgu.short_hash
local take_branch, bisect_level = vgu.take_branch, vgu.bisect_level
local wait_for_any, wait_for_log, wait_for_commitments = vgu.wait_for_any, vgu.wait_for_log, vgu.wait_for_commitments
local read_file, write_file = vgu.read_file, vgu.write_file

-- The schemas this game adds to the shared dictionary.
-- A value at a proof's target and the proof itself, used for the winner's output drive.
vgu.SCHEMA_DICT.StateValueProof = {
    target_value = "Base64",
    proof = "Proof",
}
-- The disputed transition's binary step logs, as raw file bytes. The transition that
-- closes an instruction carries a step and a reset log, an ordinary step just the one.
vgu.SCHEMA_DICT.LogCommitment = {
    step_log = "Base64",
    reset_log = "Base64",
}

local TEMPLATE = "calculator-template"

--------------------------------------------------------------------------------
-- Players
--
-- The two players run identical code, differing only in the machine they hold, the honest one
-- a bare machine and the dishonest one a composite that reports a fake machine past the cheat
-- point.
--------------------------------------------------------------------------------

-- Instantiates the calculator template on its own freshly spawned server, with `expr` written
-- into the input NVRAM.
local function new_remote_machine(expr)
    local server = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    server:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    local machine = server(TEMPLATE)
    local input = assert(util.find_drive(machine:get_initial_config(), "nvram", "input"))
    -- bc reads a line at a time, so the expression needs a trailing newline. The rest of the
    -- pristine NVRAM stays zero.
    machine:write_memory(input.start, expr .. "\n")
    return machine
end

-- The claimed final state. Forks the agreed machine, runs it to halt, and reports its root
-- hash. At halt it also captures the output into player.output_result (the result string plus
-- the output drive's subtree proof) so prove_output() answers later without a rerun, and records
-- the final hash and halting mcycle so rounds past the halt are answered from this fixed point.
-- It runs at commitment time, when the agreed machine is still the clean mcycle-0 machine.
local function commit_final_hash(player)
    local machine = assert(player.agreed.machine:fork_server())
    local output_nvram = assert(util.find_drive(machine:get_initial_config(), "nvram", "output"))
    machine:run(math.maxinteger)
    player.output_result = {
        target_value = (string.unpack("z", machine:read_memory(output_nvram.start, output_nvram.length))),
        proof = machine:get_proof(output_nvram.start, output_nvram.log2_size),
    }
    player.final_hash = machine:get_root_hash()
    player.halt_mcycle = machine:read_reg("mcycle")
    machine:shutdown_server()
    return player.final_hash
end

-- One bisection round. After taking the previous branch, the player forks the agreed machine,
-- advances the fork to the target (an mcycle or uarch_cycle per level), and returns its root
-- hash. An mcycle round at or past the halting mcycle is a fixed point answered with the cached
-- final hash, no fork at all.
local function commit_bisection(player, branch, level, target)
    take_branch(player, branch)
    if level == "mcycle" and target >= player.halt_mcycle then
        return player.final_hash
    end
    player.tentative = { machine = assert(player.agreed.machine:fork_server()) }
    if level == "mcycle" then
        player.tentative.machine:run(target)
    else
        player.tentative.machine:run_uarch(target)
    end
    return player.tentative.machine:get_root_hash()
end

-- The terminal round, once bisection has isolated the disputed step, which the referee names by
-- the mcycle and uarch cycle the bisections converged on. The last branch leaves the agreed
-- machine at those coordinates, so the player logs the transition out of it, and only the uarch
-- cycle picks the log form. The transition out of UARCH_CYCLE_MAX-1 executes one more step, by
-- then a fixed point, and the reset, committed as two logs, every other an ordinary step,
-- decided by the cycle the referee names rather than the machine's own uarch_cycle, which sits
-- at the halt.
-- Both players run in the referee's directory, so each names its log files by its role.
local step_log_name = arg[1] .. "-step.log"
local reset_log_name = arg[1] .. "-reset.log"

local function commit_log(player, branch, _mcycle, uarch_cycle)
    take_branch(player, branch)
    local agreed = player.agreed.machine
    os.remove(step_log_name)
    agreed:log_step_uarch(1, step_log_name)
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX - 1 then
        os.remove(reset_log_name)
        agreed:log_reset_uarch(reset_log_name)
        return { step_log = read_file(step_log_name), reset_log = read_file(reset_log_name) }
    end
    return { step_log = read_file(step_log_name) }
end

-- The output captured during commit_final_hash, the result bytes and the output drive's subtree
-- proof. Only those bytes travel, the referee pads the rest when it hashes. Posting the result is
-- a player's last act, so it marks itself done and its serve loop exits right after this reply.
-- The send_result_delay is a demo-ordering device, not protocol: the honest player holds its reply
-- back so the loser's invalid result arrives, and is rejected, first.
local function prove_output(player)
    socket.sleep(player.send_result_delay)
    player.done = true
    return player.output_result
end

-- A player bundles this game's operations with the machine it was handed (bare or the
-- composite), which anchors the bisection at the lower bound.
local function new_player(machine, send_result_delay)
    return vgu.new_player({
        agreed = { machine = machine },
        send_result_delay = send_result_delay,
        commit_final_hash = commit_final_hash,
        commit_bisection = commit_bisection,
        commit_log = commit_log,
        prove_output = prove_output,
    })
end

--------------------------------------------------------------------------------
-- Referee
--------------------------------------------------------------------------------

-- Asks both players for the result and returns the first output proof to arrive.
local function wait_for_output(players)
    return wait_for_any(players, "StateValueProof", "return player:prove_output()")
end

-- Checks an output submission against a verified final hash. The proof must be whole-machine, the
-- bytes must hash to the proof's target, the target must sit at the output drive address, and the
-- proof must roll up to the final hash. Returns whether it holds.
-- docs:begin verify_output
local function verify_output(dapp_contract, output, final_hash)
    return output.proof.root_hash == final_hash
        and output.proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE
        and output.proof.target_address == dapp_contract.output.start
        and output.proof.log2_target_size == dapp_contract.output.log2_size
        and hash_tree.get_root_hash(output.target_value, dapp_contract.output.log2_size) == output.proof.target_hash
        and pcall(hash_tree.verify_slice, output.proof)
end
-- docs:end verify_output

-- Verifies the disputed transition's logs on their own, the way a Cartesi contract would on the
-- blockchain, without ever instantiating a machine. Every transition carries a uarch step, and
-- the only one out of UARCH_CYCLE_MAX-1 follows it with the terminal reset. Each verification
-- returns the state hash its log provably advances to, the next one starts from it, and the
-- last must reach the committed after-hash. A rejected log raises an error, and pcall turns it
-- into a false verdict.
-- docs:begin verify_state_transition
local function verify_state_transition(uarch_cycle, state_hash_before, log, state_hash_after)
    local machine = cartesi.machine
    local pass = pcall(function()
        eventf("Verifying uarch step log!")
        write_file("posted-step.log", log.step_log)
        local hash = machine:verify_step_uarch(state_hash_before, "posted-step.log", 1)
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
-- disagreement, first an mcycle range to the disputed instruction, then a uarch_cycle range to
-- the disputed step, tracking the agreed lower-end hash and player 1's after-hash in `state`. At
-- the disputed step it hands player 1's log to verify_state_transition, which checks it standalone
-- against the agreed before-hash and the committed after-hash. If it proves, player 1 won,
-- otherwise player 2 is the honest one.
--
-- Both levels bisect the emulator's full ceiling. Past its halt a machine is a fixed point, so a
-- hash asked there just repeats its final hash, and the disagreement still lands on the diverging
-- cycle wherever each halts.
--
-- The converged uarch cycle says whether the disputed transition is an ordinary step or the
-- step and reset out of UARCH_CYCLE_MAX-1. The referee names it to player 1, which logs the
-- matching transition. Player 2 is not asked, only player 1 is verified.
-- docs:begin settle_dispute
local function settle_dispute(players, initial_hash)
    local bisection = { last_agreed_hash = initial_hash, hash_after = players[1].final_hash, branch = "start" }

    -- Bisect to the disputed main-processor instruction.
    local mcycle = bisect_level(players, "mcycle", cartesi.MCYCLE_MAX, bisection)
    -- Narrow down to the uarch instruction.
    local uarch_cycle = bisect_level(players, "uarch_cycle", cartesi.UARCH_CYCLE_MAX, bisection)

    -- A converged cycle of UARCH_CYCLE_MAX-1 means the disputed transition ends in the reset, else it is a step.
    phase("verdict")
    local log = wait_for_log(players[1], bisection.branch, mcycle, uarch_cycle)
    eventf("Player 1 posted log")

    -- Player 1 won if its log verifies against the agreed before-hash, otherwise player 2 is honest.
    local winner = verify_state_transition(uarch_cycle, bisection.last_agreed_hash, log, bisection.hash_after)
            and players[1]
        or players[2]
    eventf("Player %d wins! Final state hash is %s.", winner.index, short_hash(winner.final_hash))
    return winner
end
-- docs:end settle_dispute

-- Models application deployment, returning the contract context the referee works against. Its
-- constant, expression-independent parts are fixed here before any dispute, as they would be on
-- chain at deploy time. It loads the calculator template once to read what the contract
-- publishes, the input and output NVRAM descriptors and a proof of the pristine input drive,
-- then discards it. The agreed initial hash is not here, since it depends on the expression.
local function deploy()
    local template = cartesi.machine(TEMPLATE)
    local config = template:get_initial_config()
    local dapp_contract = {
        input = assert(util.find_drive(config, "nvram", "input")),
        output = assert(util.find_drive(config, "nvram", "output")),
    }
    dapp_contract.input_proof = template:get_proof(dapp_contract.input.start, dapp_contract.input.log2_size)
    return dapp_contract
end

-- Waits for the result, the value that hashes into the winner's committed final state. It takes the
-- first posted proof that verifies, since the loser's output cannot match, and keeps asking until
-- one arrives. The honest player holds its reply back so the loser's invalid result is rejected first.
-- docs:begin wait_for_result
local function wait_for_result(dapp_contract, players, final_hash)
    phase("output")
    while true do
        local output = wait_for_output(players)
        if verify_output(dapp_contract, output, final_hash) then
            eventf("Result posted:\n%sAccepted!", output.target_value)
            return
        end
        eventf("Result posted:\n%sRejected!", output.target_value)
    end
end
-- docs:end wait_for_result

-- Runs the whole game in three steps. It collects both players' committed final hashes, settles any
-- dispute over them to name the honest winner, then posts the result that verifies against the
-- winner's hash. Equal commitments mean no dispute, so either player's hash is the true one.
-- docs:begin run_referee
local function run_referee(referee, dapp_contract)
    local players = wait_for_commitments()

    local winner = players[1]
    if players[1].final_hash ~= players[2].final_hash then
        winner = settle_dispute(players, referee.initial_hash)
    end

    wait_for_result(dapp_contract, players, winner.final_hash)
end
-- docs:end run_referee

-- Builds a referee for a public expression against a deployed dapp contract. The agreed initial
-- hash depends on the expression, so it is computed here and kept on the referee. Rolling the
-- hash of the input NVRAM holding the expression up the pristine input proof gives the root hash
-- of the template instantiated with it, with hash_tree.get_root_hash padding the rest to match the honest
-- player's NVRAM. Honest play starts from exactly this state, never a player-declared one.
local function new_referee(dapp_contract, expr)
    local initial_hash = hash_tree.roll_hash_up_tree(
        dapp_contract.input_proof,
        hash_tree.get_root_hash(expr .. "\n", dapp_contract.input.log2_size)
    )
    return { initial_hash = initial_hash, run = run_referee }
end

--------------------------------------------------------------------------------
-- Role dispatch
--------------------------------------------------------------------------------

local role = assert(arg[1], "missing role (referee, honest, or dishonest)")

if role == "referee" then
    local dapp_contract = deploy()
    local referee = new_referee(dapp_contract, assert(arg[3], "missing public expression"))
    referee:run(dapp_contract)
elseif role == "honest" then
    -- The one-second delay is the demo-ordering device from prove_output: it holds the honest
    -- result back so the dishonest player's invalid result is rejected first in the referee's log.
    local player = new_player(new_remote_machine(assert(arg[3], "missing expression")), 1)
    player:run()
elseif role == "dishonest" then
    local player = new_player(
        dishonest.new_composite_machine(
            new_remote_machine(assert(arg[3], "missing expression")),
            assert(tonumber(arg[4]), "missing cheat mcycle"),
            assert(tonumber(arg[5]), "missing cheat uarch cycle"),
            new_remote_machine(assert(arg[6], "missing cheat expression"))
        )
    )
    player:run()
else
    error("unknown role: " .. role)
end
