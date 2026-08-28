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
-- live in prt-player.lua; the shared protocol, claim trees, referee server, and hidden
-- narration live in prtu.lua.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local prtu = require("prtu")

local keccak = cartesi.keccak256
local get_other_turn = prtu.get_other_turn

-- The seal role carries no dispute: it is the sealer, which closes the initial subscription
-- phase once the last player has connected, then the claims of every tournament as it
-- opens. It needs none of the game geometry.
if arg[1] == "seal" then
    return prtu.serve(prtu.new_sealer(), assert(arg[2], "missing referee address"))
end

local REQUESTS = prtu.REQUESTS
local MCYCLE_HEIGHT, UARCH_HEIGHT = prtu.MCYCLE_HEIGHT, prtu.UARCH_HEIGHT
local PERIODS_PER_INPUT = prtu.PERIODS_PER_INPUT
local UARCH_CYCLES_PER_MCYCLE = prtu.UARCH_CYCLES_PER_MCYCLE
local story = prtu.story
local MACHINE_TEMPLATE = "rolling-calculator-template"

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
-- Match walk
--
-- A match walks two claim trees down to the leaf where they first diverge, the two claims
-- alternating, one response per round, exactly as in Dave's Match.sol. The referee holds one node
-- to open (`turn_parent_node`) and the other claim's standing left and right children. The on-turn
-- node is located by (`height`, `node_index`) in the computation tree; `node_index` is its
-- zero-based index among the nodes at that height, not a state-leaf index. The on-turn
-- claim opens its node, exposing the two children and, above the leaves, the two grandchildren
-- of the side the walk descends into. The walk follows the side where the claims first
-- disagree, converging on the leftmost divergent leaf, and the turn passes to the opponent each
-- round. These functions are pure over the match state and response.
--------------------------------------------------------------------------------

-- Seeds a match over two claims of the given tree height. The first claim opens first, so the walk
-- starts with its computation hash as the node to open and the second claim's join-exposed children standing.
-- docs:begin new_match
local function new_match(claim1, claim2, height)
    return {
        claims = { claim1, claim2 },
        turn = 1,
        turn_parent_node = claim1.computation_hash,
        other_left_node = claim2.computation_hash_left,
        other_right_node = claim2.computation_hash_right,
        height = height,
        node_index = 0,
    }
end
-- docs:end new_match

-- Applies a valid response, descending one height: the on-turn claim's chosen grandchildren become
-- the standing left and right, the other claim's node on the chosen side becomes the next to
-- open, and the turn passes.
-- docs:begin advance_bisection
local function advance_bisection(match, response)
    assert(match.height > 1)
    local descend_left = response.turn_left_node ~= match.other_left_node
    if descend_left then
        match.turn_parent_node, match.node_index = match.other_left_node, 2 * match.node_index
    else
        match.turn_parent_node, match.node_index = match.other_right_node, 2 * match.node_index + 1
    end
    match.other_left_node, match.other_right_node = response.turn_next_left_node, response.turn_next_right_node
    match.height = match.height - 1
    match.turn = get_other_turn(match.turn)
end
-- docs:end advance_bisection

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

-- Validates a claim: its two children establish the computation hash, and its standard proof
-- places the final state at the tree's last leaf. Returns its normalized referee representation.
local function validate_claim(submitted_claim, height)
    local computation_hash = keccak(submitted_claim.computation_hash_left, submitted_claim.computation_hash_right)
    local final_state_hash_proof = submitted_claim.final_state_hash_proof
    assert(final_state_hash_proof.target_address == (1 << height) - 1)
    assert(final_state_hash_proof.log2_target_size == 0)
    assert(final_state_hash_proof.log2_root_size == height)
    assert(#final_state_hash_proof.sibling_hashes == height)
    assert(final_state_hash_proof.root_hash == computation_hash)
    hash_tree.verify_slice(final_state_hash_proof)
    return {
        computation_hash = computation_hash,
        computation_hash_left = submitted_claim.computation_hash_left,
        computation_hash_right = submitted_claim.computation_hash_right,
        final_state_hash = final_state_hash_proof.target_hash,
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

-- Partitions claim responses by computation hash, returning one claim per partition, sorted by
-- that hash. Each sender subscribes to requests for its valid claim. The sort makes the bracket a
-- pure function of the claim set, not of connection order.
-- docs:begin partition_claims
local function partition_claims(responses, validate_submitted_claim)
    local claims, by_hash = {}, {}
    validate_submitted_claim = util.protect(validate_submitted_claim)
    for _, response in ipairs(responses) do
        local claim = validate_submitted_claim(response.value)
        if claim then
            if not by_hash[claim.computation_hash] then
                by_hash[claim.computation_hash] = claim
                claims[#claims + 1] = claim
            end
            server:subscribe(claim.computation_hash, response.connection)
        end
    end
    table.sort(claims, function(a, b)
        return is_hash_less(a.computation_hash, b.computation_hash)
    end)
    return claims
end
-- docs:end partition_claims

-- Opens a tournament to a fixed audience and partitions its valid claims.
local function open_tournament(conns, validate_submitted_claim, request, ...)
    return partition_claims(server:collect_claims(conns, request, ...), validate_submitted_claim)
end

local function validate_mcycle_claim(submitted_claim)
    return validate_claim(submitted_claim, MCYCLE_HEIGHT)
end

-- Verifies the disputed transition's logs on their own, the way the Dave contracts verify
-- them on the blockchain, without ever instantiating a machine. `epoch_period_index` and
-- `state_transition_offset` are the 64-bit-safe split of CartesiStateTransition.sol's epoch-local
-- counter. The counter picks the form: the transition out of an input boundary includes
-- the input the dapp contract holds (never one a player supplies), the transition closing an
-- instruction verifies a step and then the reset, and every other is an ordinary step. Each
-- verification returns the state hash its log provably advances to, and the chain starts
-- from the agreed state hash. Returns the state hash the logs reach, or nil and an error for
-- a bad log.
-- docs:begin verify_state_transition
local function verify_state_transition(
    dapp_contract,
    current_state_hash,
    epoch_period_index,
    state_transition_offset,
    logs
)
    local input_index = epoch_period_index // PERIODS_PER_INPUT
    local period_index = epoch_period_index % PERIODS_PER_INPUT
    local uarch_cycle = state_transition_offset & (UARCH_CYCLES_PER_MCYCLE - 1)
    local obtained_state_hash = current_state_hash
    local data = dapp_contract.inputs[input_index + 1]
    if state_transition_offset == 0 and period_index == 0 and data then
        local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
        local revert_root_hash = current_state_hash
        obtained_state_hash = cartesi.machine:verify_send_cmio_response(
            reason,
            data,
            revert_root_hash,
            logs.send_cmio_log,
            current_state_hash
        )
    end
    obtained_state_hash = cartesi.machine:verify_step_uarch(obtained_state_hash, logs.step_log)
    if uarch_cycle == UARCH_CYCLES_PER_MCYCLE - 1 then
        obtained_state_hash = cartesi.machine:verify_reset_uarch(obtained_state_hash, logs.reset_uarch_log)
    end
    return obtained_state_hash
end
verify_state_transition = util.protect(verify_state_transition)
-- docs:end verify_state_transition

-- Validates an internal-node bisection response.
-- docs:begin validate_bisection_response
local function validate_bisection_response(match, response)
    assert(match.height > 1)
    assert(keccak(response.turn_left_node, response.turn_right_node) == match.turn_parent_node)
    local turn_child_node = (response.turn_left_node ~= match.other_left_node) and response.turn_left_node
        or response.turn_right_node
    assert(keccak(response.turn_next_left_node, response.turn_next_right_node) == turn_child_node)
    return response
end
-- docs:end validate_bisection_response

-- Validates a seal-divergence response and returns the normalized divergence. The leaves must
-- open the on-turn node. At state zero the agreed state is the tournament's initial state;
-- otherwise the on-turn claim must prove the preceding state against its computation hash.
-- docs:begin validate_seal_response
local function validate_seal_response(tournament, match, response)
    assert(match.height == 1)
    assert(keccak(response.turn_left_node, response.turn_right_node) == match.turn_parent_node)
    local descend_left = response.turn_left_node ~= match.other_left_node
    local state_index = 2 * match.node_index + (descend_left and 0 or 1)
    local agreed_state_hash
    if state_index ~= 0 then
        local proof = response.agreed_state_hash_proof
        assert(proof.target_address == state_index - 1)
        assert(proof.log2_target_size == 0)
        assert(proof.log2_root_size == tournament.height)
        assert(#proof.sibling_hashes == tournament.height)
        assert(proof.root_hash == match.claims[match.turn].computation_hash)
        assert(descend_left or proof.target_hash == response.turn_left_node)
        hash_tree.verify_slice(proof)
        agreed_state_hash = proof.target_hash
    else
        agreed_state_hash = tournament.initial_state_hash
    end
    local turn_state_hash = descend_left and response.turn_left_node or response.turn_right_node
    local other_state_hash = descend_left and match.other_left_node or match.other_right_node
    local next_state_hashes = {}
    next_state_hashes[match.turn] = turn_state_hash
    next_state_hashes[get_other_turn(match.turn)] = other_state_hash
    return {
        state_index = state_index,
        agreed_state_hash = agreed_state_hash,
        next_state_hashes = next_state_hashes,
    }
end
-- docs:end validate_seal_response

-- Settles a uarch match once the walk isolates the divergent leaf. The referee asks the
-- holders of both claims for the transition's logs and takes the first answer that verifies
-- against the agreed state hash. The transition out of the agreed state is unique, so any log
-- that verifies reaches the one true next state hash. Returns that hash, or nil when nobody
-- proves a transition.
-- docs:begin settle_uarch_state_hash
local function settle_uarch_state_hash(
    tournament,
    match,
    state_transition_offset,
    current_state_hash,
    next_state_hashes
)
    local conns = server:get_subscribers({ match.claims[1].computation_hash, match.claims[2].computation_hash })
    local obtained_state_hash = server:accept_first_valid(conns, function(response)
        return verify_state_transition(
            tournament.dapp_contract,
            current_state_hash,
            tournament.epoch_period_index,
            state_transition_offset,
            response
        )
    end, REQUESTS.prove_state_transition, tournament.input_index, tournament.period_index, state_transition_offset)
    story.report_state_transition(tournament, match, state_transition_offset, obtained_state_hash, next_state_hashes)
    return obtained_state_hash
end
-- docs:end settle_uarch_state_hash

-- Forward declaration: settling an mcycle match spawns a uarch tournament, which runs
-- matches, which settle against the machine.
local run_tournament

-- Opens the uarch tournament of an mcycle match over the period its claims part ways on, to
-- the holders of the two claims. Its valid claims are restricted to the two contested final
-- states, as validContestedFinalState requires on chain.
-- docs:begin open_uarch_tournament
local function open_uarch_tournament(
    mcycle_tournament,
    mcycle_match,
    epoch_period_index,
    agreed_state_hash,
    next_state_hashes
)
    local input_index = epoch_period_index // PERIODS_PER_INPUT
    local period_index = epoch_period_index % PERIODS_PER_INPUT
    local function validate_uarch_claim(submitted_claim)
        local claim = validate_claim(submitted_claim, UARCH_HEIGHT)
        assert(claim.final_state_hash == next_state_hashes[1] or claim.final_state_hash == next_state_hashes[2])
        return claim
    end
    local claims = open_tournament(
        server:get_subscribers({ mcycle_match.claims[1].computation_hash, mcycle_match.claims[2].computation_hash }),
        validate_uarch_claim,
        REQUESTS.commit_uarch_claim,
        input_index,
        period_index,
        next_state_hashes
    )
    local tournament = {
        level = "uarch",
        height = UARCH_HEIGHT,
        initial_state_hash = agreed_state_hash,
        dapp_contract = mcycle_tournament.dapp_contract,
        settle_state_hash = settle_uarch_state_hash,
        claims = claims,
        epoch_period_index = epoch_period_index,
        input_index = input_index,
        period_index = period_index,
    }
    story.report_uarch_tournament(tournament, mcycle_match, agreed_state_hash)
    story.report_claims(tournament)
    return tournament
end
-- docs:end open_uarch_tournament

-- Settles an mcycle match once the walk isolates the divergent leaf: the two claims part
-- ways over what the state hash was after one period of one input. A uarch tournament opens
-- over that period, its holders submit uarch claims, and the uarch winner's final state settles
-- the disputed state hash.
-- docs:begin settle_mcycle_state_hash
local function settle_mcycle_state_hash(
    mcycle_tournament,
    mcycle_match,
    epoch_period_index,
    agreed_state_hash,
    next_state_hashes
)
    local uarch_tournament =
        open_uarch_tournament(mcycle_tournament, mcycle_match, epoch_period_index, agreed_state_hash, next_state_hashes)
    local uarch_winner = run_tournament(uarch_tournament)
    story.report_uarch_result(mcycle_match, uarch_winner, next_state_hashes)
    return uarch_winner and uarch_winner.final_state_hash
end
-- docs:end settle_mcycle_state_hash

-- Settles a match from its sealed divergence, handing the agreed and contested state hashes
-- to the tournament's level-specific settler.
-- docs:begin settle_match
local function settle_match(tournament, match, divergence)
    story.report_divergence(match, divergence)
    local settled_state_hash = tournament:settle_state_hash(
        match,
        divergence.state_index,
        divergence.agreed_state_hash,
        divergence.next_state_hashes
    )
    for claim_index = 1, 2 do
        if settled_state_hash == divergence.next_state_hashes[claim_index] then
            return claim_index
        end
    end
    return 0
end
-- docs:end settle_match

-- Runs one match to its end and returns the winning claim index: one or two for a winner, zero
-- when both die. Each round
-- asks the holders of the on-turn claim to open its node, and the walk advances on the first
-- response that validates. A claim nobody opens loses by default.
-- docs:begin run_match
local function run_match(tournament, match)
    while match.height > 1 do
        local turn_claim = match.claims[match.turn]
        local response = server:accept_first_valid(
            server:get_subscribers({ turn_claim.computation_hash }),
            function(response)
                return validate_bisection_response(match, response)
            end,
            REQUESTS.reveal_bisection,
            turn_claim.computation_hash,
            match.height,
            match.node_index,
            match.other_left_node
        )
        if not response then
            story.report_default_win(match)
            return get_other_turn(match.turn)
        end
        advance_bisection(match, response)
        story.report_match_progress(match)
    end
    local turn_claim = match.claims[match.turn]
    local divergence = server:accept_first_valid(
        server:get_subscribers({ turn_claim.computation_hash }),
        function(response)
            return validate_seal_response(tournament, match, response)
        end,
        REQUESTS.seal_divergence,
        turn_claim.computation_hash,
        match.node_index,
        match.other_left_node
    )
    if not divergence then
        story.report_default_win(match)
        return get_other_turn(match.turn)
    end
    return settle_match(tournament, match, divergence)
end
-- docs:end run_match

-- Runs the matches concurrently, one coroutine each in the referee server's dispatcher, and
-- records their winners once every match has finished.
local function run_matches(tournament, matches)
    local round_coroutine = coroutine.running()
    local unfinished_matches = 0
    for _, match in ipairs(matches) do
        unfinished_matches = unfinished_matches + 1
        server.dispatcher:spawn(function()
            match.winner = run_match(tournament, match)
            unfinished_matches = unfinished_matches - 1
            server.dispatcher:schedule(round_coroutine, "match_done")
        end)
    end
    while unfinished_matches > 0 do
        server.dispatcher:wake_when_scheduled()
    end
end

-- Pairs the surviving claims two by two into the matches of a round, in bracket order.
local function pair_claims(tournament, round)
    local claims = tournament.claims
    local matches = {}
    for i = 1, #claims - 1, 2 do
        local match = new_match(claims[i], claims[i + 1], tournament.height)
        story.report_match(tournament, round, match)
        matches[#matches + 1] = match
    end
    return matches
end

-- Runs one round: pairs the surviving claims, runs their matches at once, and replaces the
-- tournament's claims with the survivors, an unmatched claim advancing first into the next
-- round. A match that eliminates both sides leaves neither behind. The round is narrated before
-- and after its matches run, in bracket order, so the transcript never depends on finish order.
-- docs:begin run_round
local function run_round(tournament, round)
    local claims = tournament.claims
    local matches = pair_claims(tournament, round)
    local unmatched_claim = #claims % 2 == 1 and claims[#claims] or nil
    run_matches(tournament, matches)
    story.report_round(tournament, round, matches, unmatched_claim)
    local surviving_claims = { unmatched_claim }
    for _, match in ipairs(matches) do
        surviving_claims[#surviving_claims + 1] = match.claims[match.winner]
    end
    tournament.claims = surviving_claims
end
-- docs:end run_round

-- Runs the tournament, eliminating claims round by round until a single one is left. That is
-- all a tournament is: a reduction of the claims to the one that survives every match.
-- docs:begin run_tournament
function run_tournament(tournament)
    local round = 0
    while #tournament.claims > 1 do
        round = round + 1
        run_round(tournament, round)
    end
    return tournament.claims[1]
end
-- docs:end run_tournament

-- Opens the mcycle tournament to the players that subscribed to its initial state hash and
-- returns it with the resulting claims sorted into a deterministic bracket.
-- docs:begin open_mcycle_tournament
local function open_mcycle_tournament(dapp_contract)
    local claims = open_tournament(
        server:get_subscribers({ dapp_contract.initial_state_hash }),
        validate_mcycle_claim,
        REQUESTS.commit_mcycle_claim
    )
    local tournament = {
        level = "mcycle",
        height = MCYCLE_HEIGHT,
        initial_state_hash = dapp_contract.initial_state_hash,
        dapp_contract = dapp_contract,
        settle_state_hash = settle_mcycle_state_hash,
        claims = claims,
    }
    story.report_claims(tournament)
    return tournament
end
-- docs:end open_mcycle_tournament

-- Verifies an epoch result against the settled final state, the way the Dave contracts would on
-- the blockchain. The outputs Merkle root proof must be whole-machine, sit at the tx-buffer
-- word, and roll up to the final state. The output proof's root must be the value that word
-- holds, and its target the hash of the output itself. Returns whether it all holds.
local function verify_result(result, final_state_hash)
    local state_hash_proof, output_proof = result.outputs_merkle_root_proof, result.output_proof
    assert(state_hash_proof.root_hash == final_state_hash)
    assert(state_hash_proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE)
    assert(state_hash_proof.target_address == cartesi.AR_CMIO_TX_BUFFER_START)
    assert(state_hash_proof.log2_target_size == cartesi.HASH_TREE_LOG2_WORD_SIZE)
    hash_tree.verify_slice(state_hash_proof)
    assert(keccak(output_proof.root_hash) == state_hash_proof.target_hash)
    hash_tree.verify_slice(output_proof)
    assert(keccak(result.output) == output_proof.target_hash)
    return true
end
verify_result = util.protect(verify_result)

-- Waits on the settled claim, the one the tournament leaves standing. Since the claim commits
-- only to the epoch's final state hash, waits for the epoch's actual output,
-- proved against that hash. The referee takes the first posted result that verifies, from any
-- holder of the winning claim, since a wrong result cannot match.
-- docs:begin wait_for_result
local function wait_for_result(winner)
    local conns = server:get_subscribers({ winner.computation_hash })
    local result = server:accept_first_valid(conns, function(response)
        return verify_result(response, winner.final_state_hash) and response
    end, REQUESTS.prove_result)
    story.report_result(result)
end
-- docs:end wait_for_result

-- Seen from the referee, the whole game is short. It opens the mcycle tournament, reduces the
-- claims it opened with, and, if one survives every match, settles the epoch on its result.
-- The mcycle tournament packs what the reduction needs: the agreed initial state hash,
-- the dapp contract whose inputs verification trusts, and the way its matches settle.
-- Everything hard, the accept loop, the wire, the coroutine scheduling, runs underneath, in
-- the referee server this is handed to.
-- docs:begin run_referee
local function run_referee(dapp_contract)
    server:accept_subscribers(dapp_contract.initial_state_hash)
    local winner = run_tournament(open_mcycle_tournament(dapp_contract))
    story.report_winner(winner)
    if winner then
        wait_for_result(winner)
    end
end
-- docs:end run_referee

-- Models application deployment, returning the contract context the referee works against. The
-- epoch's inputs are all posted to the blockchain, so the contract holds its own copy of
-- every one, the copy that verification trusts over anything a player commits.
local function deploy(inputs)
    local machine <close> = cartesi.machine(MACHINE_TEMPLATE)
    return {
        initial_state_hash = machine:get_root_hash(),
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

-- Requiring this script from prt-test.lua exposes the referee walk without running a CLI role.
if ... == "prt" then
    return {
        new_match = new_match,
        validate_bisection_response = validate_bisection_response,
        advance_bisection = advance_bisection,
        validate_seal_response = validate_seal_response,
    }
end

--------------------------------------------------------------------------------
-- Role dispatch
--------------------------------------------------------------------------------

local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")
local prt_player = role ~= "referee" and require("prt-player") or nil

if role == "referee" then
    local dapp_contract = deploy(read_inputs(3))
    local referee = new_referee(server_address)
    referee:run(dapp_contract)
elseif role == "honest" then
    prtu.serve(prt_player.new_honest(read_inputs(3), MACHINE_TEMPLATE), server_address)
elseif role == "quitter" then
    prtu.serve(prt_player.new_quitter(), server_address)
elseif role == "forger" then
    local index = assert(tonumber(arg[3]), "missing forged input index")
    local forged = util.read_file(assert(arg[4], "missing forged input file"))
    prtu.serve(prt_player.new_forger(read_inputs(5), MACHINE_TEMPLATE, index, forged), server_address)
elseif role == "tamperer" then
    local input_index = assert(tonumber(arg[3]), "missing tampered input index")
    local entry_offset = assert(tonumber(arg[4]), "missing tamper entry offset")
    prtu.serve(prt_player.new_tamperer(read_inputs(5), MACHINE_TEMPLATE, input_index, entry_offset), server_address)
elseif role == "fabulist" then
    local input_index = assert(tonumber(arg[3]), "missing lied-about input index")
    local leaf_offset = assert(tonumber(arg[4]), "missing lied-about leaf offset")
    prtu.serve(prt_player.new_fabulist(read_inputs(5), MACHINE_TEMPLATE, input_index, leaf_offset), server_address)
else
    error("unknown role: " .. role)
end
