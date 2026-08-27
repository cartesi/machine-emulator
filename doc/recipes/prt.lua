-- A model of a Permissionless Refereed Tournament (PRT) over an epoch of a Rolling Cartesi
-- Machine.
--
-- A referee, standing in for the Dave contracts on the blockchain, resolves a dispute among
-- any number of players over the epoch's history. Where the verification game bisected live,
-- PRT has each player commit upfront to a computation hash, the root of a Merkle tree of
-- machine state hashes sampled along the whole computation, and the dispute walks down the
-- two trees. Claims are what matter, not players: any player may answer any request about
-- any claim, every answer carries its own proof, and the referee takes the first answer that
-- verifies. A request nobody answers eliminates the claim it was about, never a player.
--
-- The dispute has two levels, one per cycle counter. An mcycle claim commits to the machine
-- state hash every 2^p mcycles across the epoch (the mcycle computation hash of
-- cartesi-machine.lua). When two mcycle claims diverge at a leaf, each side commits to a
-- uarch claim over that one period, the state hash after every uarch transition of its 2^p
-- instructions (the uarch cycle computation hash), and the walk repeats. The uarch leaf it
-- isolates is a single state transition, settled by verifying access logs, exactly as in the
-- verification games.
--
-- Roles, selected by the first argument. Every game role takes the referee address, and every
-- machine-holding role takes the epoch's input files. The referee
-- is never told how many players to expect: it accepts subscribers until a seal connection
-- closes that phase, then asks those subscribers for claims. The referee sorts the claims it
-- gathers, so the bracket and the whole narration are a pure function of the claim set, not of
-- the order in which players connect.
--   prt.lua referee  <address> <input> [<input> ...]
--   prt.lua honest   <address> <input> [<input> ...]
--   prt.lua quitter  <address>
--   prt.lua forger   <address> <index> <forged-input> <input> [<input> ...]
--   prt.lua tamperer <address> <input-index> <entry-offset> <input> [<input> ...]
--   prt.lua fabulist <address> <input-index> <leaf-offset> <input> [<input> ...]
--   prt.lua seal     <address>
--
-- The seal role is the sealer: it stays connected and closes the initial subscription phase
-- and every tournament the referee opens. The recipe starts it once every player is in, so
-- those players form the mcycle tournament's audience, and every tournament then seals as
-- soon as it opens.
--
-- The referee lives here. The players, their machines, claim builds, and dishonest strategies
-- live in prt-player.lua, and the claim trees, the match walk, and the referee server in
-- prtu.lua.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local prtu = require("prtu")

local keccak = cartesi.keccak256
local new_match, is_valid_move, advance_match = prtu.new_match, prtu.is_valid_move, prtu.advance_match

-- The seal role carries no dispute: it is the sealer, which closes the initial subscription
-- phase once the last player has connected, then the submissions of every tournament as it
-- opens. It needs none of the game geometry.
if arg[1] == "seal" then
    return prtu.serve(prtu.new_sealer(), assert(arg[2], "missing referee address"))
end

local geometry = require("prt-geometry")
local prt_player = require("prt-player")
local REQUESTS = prt_player.REQUESTS
local MCYCLE_HEIGHT, UARCH_HEIGHT = geometry.MCYCLE_HEIGHT, geometry.UARCH_HEIGHT
local PERIODS_PER_INPUT = geometry.PERIODS_PER_INPUT
local UARCH_CYCLES_PER_MCYCLE = geometry.UARCH_CYCLES_PER_MCYCLE
local story = require("prt-story")
local MACHINE_TEMPLATE = "rolling-calculator-template"

local function write_stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Reads the epoch's inputs from the files on the command line, starting at `first`.
local function read_inputs(first)
    local inputs = {}
    for index = first, #arg do
        inputs[index - first + 1] = util.read_file(arg[index])
    end
    assert(#inputs > 0, "missing input files")
    return inputs
end

--------------------------------------------------------------------------------
-- Referee
--
-- The referee holds only what the blockchain would: the agreed initial state hash, the
-- deployed dapp contract with the epoch's inputs, and the geometry. During a match it
-- tracks one node hash per claim as it walks the two trees down, so it stores nothing of
-- the claims but the path in dispute. It never narrates who holds a claim: the transcript
-- is about claims, and the players announce their own claims on their own stderr.
--------------------------------------------------------------------------------

-- The referee server and its coroutine dispatcher, built with the referee and shared by every
-- coroutine of its logic.
local server

-- Whether a standard hash-tree proof places a leaf at the expected logical index and geometry
-- under the expected computation hash.
local function is_valid_claim_proof(proof, index, height, computation_hash)
    if type(proof) ~= "table" or type(proof.sibling_hashes) ~= "table" then
        return false
    end
    return proof.target_address == index
        and proof.log2_target_size == 0
        and proof.log2_root_size == height
        and #proof.sibling_hashes == height
        and proof.root_hash == computation_hash
        and pcall(hash_tree.verify_slice, proof)
end

-- Validates a claim commitment: its two children establish the computation hash, and its
-- standard proof places the final state at the tree's last leaf. Returns the claim.
local function validate_claim_commitment(witness, height)
    local computation_hash = keccak(witness.left, witness.right)
    assert(
        is_valid_claim_proof(witness.proof, (1 << height) - 1, height, computation_hash),
        "invalid final-state proof"
    )
    return {
        computation_hash = computation_hash,
        left = witness.left,
        right = witness.right,
        final_state = witness.proof.target_hash,
    }
end

-- Orders binary hashes by their bytes, independent of the process locale.
local function is_hash_less(a, b)
    for i = 1, math.min(#a, #b) do
        local ai, bi = a:byte(i), b:byte(i)
        if ai ~= bi then
            return ai < bi
        end
    end
    return #a < #b
end

-- Partitions tournament submissions by computation hash, returning one claim per partition,
-- sorted by that hash. `validate` turns an accepted commitment into its claim, and each sender
-- subscribes to requests for that claim. The sort makes the bracket a pure function of the claim
-- set, not of connection order.
-- docs:begin partition_claims
local function partition_claims(submissions, validate)
    local claims, by_hash = {}, {}
    for _, submission in ipairs(submissions) do
        local ok, claim = pcall(validate, submission.value)
        if ok then
            if not by_hash[claim.computation_hash] then
                by_hash[claim.computation_hash] = claim
                claims[#claims + 1] = claim
            end
            server:subscribe(claim.computation_hash, submission.connection)
        elseif not ok then
            write_stderr("a submission failed validation: %s\n", tostring(claim))
        end
    end
    table.sort(claims, function(a, b)
        return is_hash_less(a.computation_hash, b.computation_hash)
    end)
    return claims
end
-- docs:end partition_claims

-- Opens a tournament to a fixed audience and partitions its valid claim commitments.
local function open_tournament(conns, validate, request, ...)
    return partition_claims(server:collect_submissions(conns, request, ...), validate)
end

local function validate_mcycle_claim(witness)
    return validate_claim_commitment(witness, MCYCLE_HEIGHT)
end

-- Verifies the disputed transition's logs on their own, the way the Dave contracts verify
-- them on the blockchain, without ever instantiating a machine. The transition index picks the
-- form, as in CartesiStateTransition.sol: the transition out of an input boundary includes
-- the input the dapp contract holds (never one a player supplies), the transition closing an
-- instruction verifies a step and then the reset, and every other is an ordinary step. Each
-- verification returns the state hash its log provably advances to, and the chain starts
-- from the agreed state hash. Returns the hash the logs reach, or raises on a bad log.
-- docs:begin verify_transition
local function verify_transition(dapp_contract, disputed_period, transition_index, current_hash, logs)
    local machine = cartesi.machine
    local uarch_cycle = transition_index & (UARCH_CYCLES_PER_MCYCLE - 1)
    local hash = current_hash
    local data = dapp_contract.inputs[disputed_period.input_index + 1]
    if transition_index == 0 and disputed_period.period_index == 0 and data then
        local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
        hash = machine:verify_send_cmio_response(reason, data, hash, logs.send_cmio_log, hash)
    end
    hash = machine:verify_step_uarch(hash, logs.step_log)
    if uarch_cycle == UARCH_CYCLES_PER_MCYCLE - 1 then
        hash = machine:verify_reset_uarch(hash, logs.reset_log)
    end
    return hash
end
-- docs:end verify_transition

-- The state hash both claims agree on right before the divergent leaf, when the walk did not
-- expose it. At leaf 0 it is the tournament's initial state hash, which the referee knows.
-- Otherwise it is the leaf before the divergence, requested as a proof against either claim:
-- the walk finds the leftmost divergence, so the two trees agree at every earlier leaf, and a
-- proof against either one binds them both. The standard proof verifies against the computation hash.
local function wait_for_agreed_hash(match, tournament, state_index)
    if state_index == 0 then
        return tournament.initial_hash
    end
    for _, claim in ipairs({ match.claim1, match.claim2 }) do
        local conns = server:get_subscribers({ claim.computation_hash })
        local move = server:accept_first(conns, function(v)
            return is_valid_claim_proof(v, state_index - 1, tournament.height, claim.computation_hash) and v
        end, REQUESTS.prove_state, claim.computation_hash, state_index - 1)
        if move then
            return move.target_hash
        end
    end
    return nil
end

-- Settles a uarch match once the walk isolates the divergent leaf. The referee asks the
-- holders of both claims for the transition's logs and takes the first answer that verifies
-- against the agreed state hash. The transition out of the agreed state is unique, so any log
-- that verifies reaches the one true after-hash. The claim that committed to it wins, and a
-- claim that committed to anything else loses. Nobody proving anything eliminates both.
-- docs:begin settle_uarch_match
local function settle_uarch_match(tournament, match, transition_index, current_hash, claim1_next_hash, claim2_next_hash)
    local disputed_period = tournament.disputed_period
    story.report_transition(tournament, match, transition_index)
    local conns = server:get_subscribers({ match.claim1.computation_hash, match.claim2.computation_hash })
    local next_hash = server:accept_first(conns, function(v)
        return verify_transition(tournament.dapp_contract, disputed_period, transition_index, current_hash, v)
    end, REQUESTS.provide_transition_logs, disputed_period.input_index, disputed_period.period_index, transition_index)
    local winner = next_hash == claim1_next_hash and match.claim1
        or next_hash == claim2_next_hash and match.claim2
        or nil
    story.report_transition_result(match, next_hash, winner, claim1_next_hash, claim2_next_hash)
    return winner
end
-- docs:end settle_uarch_match

-- Forward declaration: settling an mcycle match spawns a uarch tournament, which runs
-- matches, which settle against the machine.
local run_tournament

-- Opens the uarch tournament of an mcycle match over the period its claims part ways on, to
-- the holders of the two claims. Its valid claims are restricted to the two contested final
-- states, as validContestedFinalState requires on chain.
-- docs:begin open_uarch_tournament
local function open_uarch_tournament(parent, match, disputed_period, agreed_hash, claim1_next_hash, claim2_next_hash)
    local tournament = {
        level = "uarch",
        height = UARCH_HEIGHT,
        initial_hash = agreed_hash,
        dapp_contract = parent.dapp_contract,
        disputed_period = disputed_period,
        settle = settle_uarch_match,
    }
    story.report_uarch_tournament(tournament, match, disputed_period, agreed_hash)
    local function validate(witness)
        local claim = validate_claim_commitment(witness, UARCH_HEIGHT)
        assert(claim.final_state == claim1_next_hash or claim.final_state == claim2_next_hash)
        return claim
    end
    local claims = open_tournament(
        server:get_subscribers({ match.claim1.computation_hash, match.claim2.computation_hash }),
        validate,
        REQUESTS.commit_uarch_claim,
        disputed_period.input_index,
        disputed_period.period_index,
        claim1_next_hash,
        claim2_next_hash
    )
    tournament.claims = claims
    story.report_claims(tournament, claims)
    return tournament
end
-- docs:end open_uarch_tournament

-- Settles an mcycle match once the walk isolates the divergent leaf: the two claims part
-- ways over what the state hash was after one period of one input. A uarch tournament opens
-- over that period, its holders submit uarch claims, and the uarch winner's final state names
-- the mcycle claim that survives.
-- docs:begin settle_mcycle_match
local function settle_mcycle_match(
    tournament,
    match,
    epoch_period_index,
    agreed_hash,
    claim1_next_hash,
    claim2_next_hash
)
    local disputed_period = {
        input_index = epoch_period_index // PERIODS_PER_INPUT,
        period_index = epoch_period_index % PERIODS_PER_INPUT,
    }
    local uarch_tournament =
        open_uarch_tournament(tournament, match, disputed_period, agreed_hash, claim1_next_hash, claim2_next_hash)
    local uarch_winner = run_tournament(uarch_tournament)
    local survivor = uarch_winner and (uarch_winner.final_state == claim1_next_hash and match.claim1 or match.claim2)
    story.report_uarch_result(match, uarch_winner, survivor)
    return survivor
end
-- docs:end settle_mcycle_match

-- Settles the dispute a match walk isolated: recovers the agreed state before the divergent
-- leaf, when the walk did not expose it, and hands the dispute to the tournament's settle.
-- docs:begin settle_dispute
local function settle_dispute(tournament, match, dispute)
    local agreed_hash = dispute.agreed_hash or wait_for_agreed_hash(match, tournament, dispute.state_index)
    story.report_dispute(match, dispute, agreed_hash)
    if not agreed_hash then
        return nil
    end
    return tournament.settle(
        tournament,
        match,
        dispute.state_index,
        agreed_hash,
        dispute.claim1_next_hash,
        dispute.claim2_next_hash
    )
end
-- docs:end settle_dispute

-- Runs one match to its end and returns the winning claim, or nil when both die. Each round
-- asks the holders of the on-turn claim to open its node, and the walk advances on the first
-- move that validates. A claim nobody opens loses by default.
-- docs:begin run_match
local function run_match(tournament, match)
    while true do
        local conns = server:get_subscribers({ match.turn_claim.computation_hash })
        local move = server:accept_first(conns, function(v)
            return is_valid_move(match, v) and v
        end, REQUESTS.advance, match.turn_claim.computation_hash, match.height, match.index, match.left_node)
        if not move then
            story.report_default_win(match)
            return match.other_claim
        end
        local dispute = advance_match(match, move)
        if dispute then
            return settle_dispute(tournament, match, dispute)
        end
        story.report_match_progress(match)
    end
end
-- docs:end run_match

-- Runs the tasks concurrently, one coroutine each in the referee server's dispatcher, and
-- returns their results once every task has finished, indexed as the tasks were.
local function run_all(tasks)
    local main = coroutine.running()
    local results, pending = {}, 0
    for slot, task in ipairs(tasks) do
        pending = pending + 1
        server.dispatcher:spawn(function()
            results[slot] = task()
            pending = pending - 1
            server.dispatcher:schedule(main, "task_done")
        end)
    end
    while pending > 0 do
        server.dispatcher:wake_when_scheduled()
    end
    return results
end

-- Pairs the surviving claims two by two into the matches of a round, in bracket order.
local function pair_claims(tournament, claims, round)
    local matches = {}
    for i = 1, #claims - 1, 2 do
        local match = new_match(claims[i], claims[i + 1], tournament.height)
        story.report_match(tournament, round, match)
        matches[#matches + 1] = match
    end
    return matches
end

-- Runs one round: pairs the surviving claims, runs their matches at once, and returns the
-- winners, an odd claim out taking a bye to the next round. A match that eliminates both sides
-- leaves neither behind. The round is narrated before and after its matches run, in bracket
-- order, so the transcript never depends on the order the matches happened to finish.
-- docs:begin run_round
local function run_round(tournament, claims, round)
    local matches = pair_claims(tournament, claims, round)
    local bye = #claims % 2 == 1 and claims[#claims] or nil
    local tasks = {}
    for slot, match in ipairs(matches) do
        tasks[slot] = function()
            return run_match(tournament, match)
        end
    end
    local results, winners = run_all(tasks), {}
    story.report_round(tournament, round, matches, results, bye)
    for slot = 1, #matches do
        local winner = results[slot]
        if winner then
            winners[#winners + 1] = winner
        end
    end
    if bye then
        winners[#winners + 1] = bye
    end
    return winners
end
-- docs:end run_round

-- Runs the tournament, eliminating claims round by round until a single one is left. That is
-- all a tournament is: a reduction of the claims to the one that survives every match.
-- docs:begin run_tournament
function run_tournament(tournament)
    local claims = tournament.claims
    local round = 0
    while #claims > 1 do
        round = round + 1
        claims = run_round(tournament, claims, round)
    end
    return claims[1]
end
-- docs:end run_tournament

-- Opens the mcycle tournament to the players that subscribed to its initial state hash and
-- returns it with the resulting claims sorted into a deterministic bracket.
-- docs:begin open_mcycle_tournament
local function open_mcycle_tournament(dapp_contract)
    local claims = open_tournament(
        server:get_subscribers({ dapp_contract.initial_hash }),
        validate_mcycle_claim,
        REQUESTS.commit_mcycle_claim
    )
    local tournament = {
        level = "mcycle",
        height = MCYCLE_HEIGHT,
        initial_hash = dapp_contract.initial_hash,
        dapp_contract = dapp_contract,
        settle = settle_mcycle_match,
        claims = claims,
    }
    story.report_claims(tournament, claims)
    return tournament
end
-- docs:end open_mcycle_tournament

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
    story.report_winner(winner)
    local conns = server:get_subscribers({ winner.computation_hash })
    local result = server:accept_first(conns, function(v)
        return verify_result(v, winner.final_state) and v
    end, REQUESTS.prove_result)
    assert(result, "no result proved against the winning final state")
    story.report_result(result)
    server:collect(nil, REQUESTS.finish)
end
-- docs:end wait_for_result

-- Seen from the referee, the whole game is short. It opens the mcycle tournament, reduces the
-- claims it opened with to the one that survives every match, and settles the epoch on its
-- result. The mcycle tournament packs what the reduction needs: the agreed initial state hash,
-- the dapp contract whose inputs verification trusts, and the way its matches settle.
-- Everything hard, the accept loop, the wire, the coroutine scheduling, runs underneath, in
-- the referee server this is handed to.
-- docs:begin run_referee
local function run_referee(dapp_contract)
    server:accept_subscribers(dapp_contract.initial_hash)
    local winner = run_tournament(open_mcycle_tournament(dapp_contract))
    assert(winner, "the tournament ended with no winner")
    wait_for_result(winner)
end
-- docs:end run_referee

-- Models application deployment, returning the contract context the referee works against. The
-- epoch's inputs are all posted to the blockchain, so the contract holds its own copy of
-- every one, the copy that verification trusts over anything a player commits.
local function deploy(inputs)
    local machine <close> = cartesi.machine(MACHINE_TEMPLATE)
    return {
        initial_hash = machine:get_root_hash(),
        inputs = inputs,
    }
end

-- The referee, standing in for the Dave contracts. Its server hides the accept loop, the wire,
-- and coroutine scheduling; run() drives run_referee against the deployed dapp contract, which
-- holds the agreed initial state hash and epoch inputs.
local function new_referee(server_address)
    server = prtu.new_server(server_address)
    return {
        run = function(_, dapp_contract)
            server:run(function()
                run_referee(dapp_contract)
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
    local dapp_contract = deploy(read_inputs(3))
    local referee = new_referee(server_address)
    referee:run(dapp_contract)
elseif role == "honest" then
    prtu.serve(prt_player.new_player("honest", read_inputs(3), MACHINE_TEMPLATE), server_address)
elseif role == "quitter" then
    local player = prt_player.new_player("quitter", {}, MACHINE_TEMPLATE)
    prt_player.make_quitter(player)
    prtu.serve(player, server_address)
elseif role == "forger" then
    local index = assert(tonumber(arg[3]), "missing forged input index")
    local forged = util.read_file(assert(arg[4], "missing forged input file"))
    local player = prt_player.new_player("forger", read_inputs(5), MACHINE_TEMPLATE)
    prt_player.make_forger(player, index, forged)
    prtu.serve(player, server_address)
elseif role == "tamperer" then
    local input_index = assert(tonumber(arg[3]), "missing tampered input index")
    local entry_offset = assert(tonumber(arg[4]), "missing tamper entry offset")
    local player = prt_player.new_player("tamperer", read_inputs(5), MACHINE_TEMPLATE)
    prt_player.make_tamperer(player, input_index, entry_offset)
    prtu.serve(player, server_address)
elseif role == "fabulist" then
    local input_index = assert(tonumber(arg[3]), "missing lied-about input index")
    local leaf_offset = assert(tonumber(arg[4]), "missing lied-about leaf offset")
    local player = prt_player.new_player("fabulist", read_inputs(5), MACHINE_TEMPLATE)
    prt_player.make_fabulist(player, input_index, leaf_offset)
    prtu.serve(player, server_address)
else
    error("unknown role: " .. role)
end
