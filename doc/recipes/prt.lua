-- A model of a Permissionless Refereed Tournament (PRT) over an epoch of a Rolling Cartesi
-- Machine.
--
-- A referee, standing in for the Dave contracts on the blockchain, resolves a dispute among
-- any number of players over the epoch's history. Where the verification game bisected live,
-- PRT has each player commit upfront to a computation hash, the root of a Merkle tree of
-- machine state hashes sampled along the whole computation, and the dispute walks down the
-- two trees. Claims are what matter, not players: any player may answer any event concerning
-- any claim, every answer carries its own proof, and the referee takes the first answer that
-- verifies. Unanswered openings are followed by timeout-win and elimination requests.
--
-- The dispute has two levels, one per cycle counter. An mcycle claim commits to the machine
-- state hash every 2^p mcycles across the epoch (the mcycle computation hash of
-- cartesi-machine.lua). When two mcycle claims diverge at a leaf, each side commits to a
-- uarch claim over that one period, the state hash after every uarch transition of its 2^p
-- instructions (the uarch cycle computation hash), and the walk repeats. The uarch leaf it
-- isolates is a single state transition, settled by verifying access logs, exactly as in the
-- verification games.
--
-- Roles, selected by the first argument. Every game role takes the referee address, the
-- epoch's initial state hash, and the epoch's input files, from which each process builds
-- the same dapp contract, standing in for reading it off the chain. A machine-holding
-- player finds its own snapshot of the initial machine stored under that hash name. The
-- referee is never told how many players to expect: it accepts subscribers until a
-- phase-closer connection closes that phase, then emits the tournament event to those
-- subscribers. The referee sorts the claims it gathers, so the bracket and the whole narration are a pure
-- function of the claims and prescribed responses or skips, independent of connection order.
--   prt.lua referee  <address> <initial-state-hash> <input> [<input> ...]
--   prt.lua honest   <address> <initial-state-hash> <output-index> <input> [<input> ...]
--   prt.lua phase_closer <address> [stop]
--
-- The phase closer closes initial subscriptions once every player is in, then disconnects.
-- A later invocation with stop ends the example through the server, including pending proof waits.
-- Mcycle and uarch tournaments gather claims from fixed audiences in a logical block.
-- Claim collection closes at the next block. Wall-clock computation speed does not consume
-- a protocol allowance.
--
-- The referee, honest player, machines, and computation hashes live here. The shared
-- protocol, claim trees, referee server, and hidden narration live in prtu.lua.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local prtu = require("prtu")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local format_short_hash = prtu.format_short_hash
local new_tree = prtu.new_tree

local keccak = cartesi.keccak256
local get_other_turn = prtu.get_other_turn
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
local WORD_MASK = WORD_SIZE - 1
local IFLAGS_Y_ADDRESS = cartesi.machine:get_reg_address("iflags_Y")
local HTIF_TOHOST_ADDRESS = cartesi.machine:get_reg_address("htif_tohost")
local CMIO_TX_BUFFER_ADDRESS = cartesi.AR_CMIO_TX_BUFFER_START

-- The phase closer carries no dispute. It closes the initial subscription phase once the last
-- player has connected. Tournament claim collection then uses logical time. It needs none
-- of the game geometry.
if arg[1] == "phase_closer" then
    return prtu.run_client(prtu.new_phase_closer(arg[3]), assert(arg[2], "missing referee address"))
end

local EVERYONE = prtu.EVERYONE
local EVENTS = prtu.EVENTS
local story = prtu.story

-- Reads one epoch input from each command-line filename.
local function read_inputs(...)
    local inputs = {}
    for index, path in ipairs({ ... }) do
        inputs[index] = util.read_file(path)
    end
    return inputs
end

------------------------------------------------------------
-- Match walk
--
-- A match walks two claim trees down to the leaf where they first diverge, the two claims
-- alternating, one response per round, exactly as in Dave's Match.sol. The referee holds one node
-- to open (`turn_parent_node`) and the other claim's standing left and right children. The on-turn
-- node is located by (`position`, `height`) in the computation tree; `position` is the index
-- of its first covered state leaf and is aligned to 2^height. The on-turn claim opens its node,
-- exposing the two children and, above the leaves, the two grandchildren of the side the walk
-- descends into. The walk follows the side where the claims first disagree, converging on the
-- leftmost divergent leaf, and the turn passes to the opponent each round. These functions are
-- pure over the match state and response.
------------------------------------------------------------

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
        position = 0,
    }
end
-- docs:end new_match

-- Applies a valid response, descending one height: the on-turn claim's chosen grandchildren become
-- the standing left and right, the other claim's node on the chosen side becomes the next to
-- open, and the turn passes.
-- docs:begin advance_bisection
local function advance_bisection(match, response)
    assert(match.height > 1)
    match.height = match.height - 1
    local descend_left = response.turn_left_node ~= match.other_left_node
    if descend_left then
        match.turn_parent_node = match.other_left_node
    else
        match.turn_parent_node = match.other_right_node
        match.position = match.position + (1 << match.height)
    end
    match.other_left_node, match.other_right_node = response.turn_next_left_node, response.turn_next_right_node
    match.turn = get_other_turn(match.turn)
end
-- docs:end advance_bisection

-- =============================================================================
-- Referee
--
-- The referee holds only what the blockchain would: the agreed initial state hash, the
-- deployed dapp contract with the epoch's inputs, and the geometry. During a match it
-- tracks one node hash per claim as it walks the two trees down, so it stores nothing of
-- the claims but the path in dispute. It never narrates who holds a claim: the transcript
-- is about claims, and the players announce their own claims on their own stderr.
-- =============================================================================

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

-- A claim's subscription hash combines its computation hash with its tournament ID.
-- The mcycle tournament's ID is the initial state hash. A uarch tournament's ID is the
-- hash of the two mcycle claims whose match opened it, as Match.sol identifies a match.
-- This keeps holders of equal computation hashes in different tournaments separate.
local function subscription_hash(tournament_id, claim)
    return keccak(tournament_id, claim.computation_hash)
end

-- Partitions claim responses by computation hash, returning one claim per partition, sorted by
-- that hash. Each sender subscribes to events concerning its valid claim, under the given
-- tournament ID. The sort makes the bracket a pure function of the claim set, not of
-- connection order.
-- docs:begin partition_claims
local function partition_claims(responses, tournament_id)
    local claims, by_hash = {}, {}
    for _, response in ipairs(responses) do
        local claim = response.value
        if not by_hash[claim.computation_hash] then
            by_hash[claim.computation_hash] = claim
            claims[#claims + 1] = claim
        end
        server:subscribe_connection(subscription_hash(tournament_id, claim), response.connection)
    end
    table.sort(claims, function(a, b)
        return is_hash_less(a.computation_hash, b.computation_hash)
    end)
    return claims
end
-- docs:end partition_claims

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
    local periods_per_input = dapp_contract.geometry.periods_per_input
    local input_index = epoch_period_index // periods_per_input
    local period_index = epoch_period_index % periods_per_input
    local uarch_cycle = state_transition_offset & cartesi.UARCH_CYCLE_MAX
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
    if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
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
    local state_index = match.position + (descend_left and 0 or 1)
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

local function validate_claim_children(children, computation_hash)
    assert(keccak(children.computation_hash_left, children.computation_hash_right) == computation_hash)
end

-- Requests the waiting claim's response at the timeout block.
local function emit_schedule_match_timeout_win(tournament, match, deadline)
    local other_turn = get_other_turn(match.turn)
    local other_claim = match.claims[other_turn]
    return server:request_first_valid(
        subscription_hash(tournament.id, other_claim),
        EVENTS.schedule_match_timeout_win,
        { deadline, other_claim.computation_hash },
        function(response)
            assert(server:get_time() >= deadline and server:get_time() < deadline + 1)
            validate_claim_children(response, other_claim.computation_hash)
            story.report_timeout_win(match)
            return other_turn
        end
    )
end

local function emit_schedule_match_elimination(match, deadline)
    return server:request_first_valid(EVERYONE, EVENTS.schedule_match_elimination, { deadline }, function(response)
        assert(server:get_time() >= deadline and response == true)
        story.report_match_eliminated(match)
        return 0
    end)
end

-- Settles a uarch match once the walk isolates the divergent leaf. The referee emits the
-- disputed transition to both claims' holders and takes the first answer that verifies
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
    local subscriptions = {
        subscription_hash(tournament.id, match.claims[1]),
        subscription_hash(tournament.id, match.claims[2]),
    }
    local deadline = server:request_block() + 1
    local elimination <close> = server:request_first_valid(
        EVERYONE,
        EVENTS.schedule_match_elimination,
        { deadline },
        function(response)
            assert(server:get_time() >= deadline and response == true)
            return true
        end
    )
    local proof <close> = server:request_first_valid(
        subscriptions,
        EVENTS.prove_state_transition,
        { tournament.input_index, tournament.period_index, state_transition_offset },
        function(response)
            assert(server:get_time() < deadline)
            return verify_state_transition(
                tournament.dapp_contract,
                current_state_hash,
                tournament.epoch_period_index,
                state_transition_offset,
                response
            )
        end
    )
    local obtained_state_hash = proof:wait(deadline)
    if not obtained_state_hash then
        elimination:wait()
    end
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
    local geometry = mcycle_tournament.dapp_contract.geometry
    local input_index = epoch_period_index // geometry.periods_per_input
    local period_index = epoch_period_index % geometry.periods_per_input
    local mcycle_tournament_id = mcycle_tournament.id
    local tournament_id = keccak(mcycle_match.claims[1].computation_hash, mcycle_match.claims[2].computation_hash)
    local close_block = server:request_block() + 1
    local collection <close> = server:request_all(
        {
            subscription_hash(mcycle_tournament_id, mcycle_match.claims[1]),
            subscription_hash(mcycle_tournament_id, mcycle_match.claims[2]),
        },
        EVENTS.commit_uarch_claim,
        { input_index, period_index, next_state_hashes },
        function(response)
            local claim = validate_claim(response, geometry.uarch_height)
            assert(claim.final_state_hash == next_state_hashes[1] or claim.final_state_hash == next_state_hashes[2])
            return claim
        end
    )
    local responses = collection:wait(close_block)
    server:wait_until(close_block)
    local claims = partition_claims(responses, tournament_id)
    local tournament = {
        level = "uarch",
        id = tournament_id,
        height = geometry.uarch_height,
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

-- Applies the uarch tournament result directly to the mcycle match.
local function propagate_uarch_result(mcycle_match, winner, next_state_hashes)
    -- With a winner, Dave's equivalent request/wait flow would look like the sketch below.
    -- It also takes the enclosing mcycle tournament and winner_expires_at from Dave's clocks,
    -- not a fresh propagation allowance. These illustrative events are omitted from the Lua protocol.
    --[[
    local function propagate_winner(mcycle_tournament, winner_expires_at)
        local claim_index = winner.final_state_hash == next_state_hashes[1] and 1 or 2
        assert(winner.final_state_hash == next_state_hashes[claim_index])
        local mcycle_claim = mcycle_match.claims[claim_index]
        local elimination <close> = server:request_first_valid(
            EVERYONE, EVENTS.schedule_uarch_result_elimination, { winner_expires_at },
            function(response)
                assert(server:get_time() >= winner_expires_at and response == true)
                return true
            end
        )
        local propagation <close> = server:request_first_valid(
            subscription_hash(mcycle_tournament.id, mcycle_claim),
            EVENTS.propagate_uarch_result, { mcycle_claim.computation_hash },
            function(response)
                assert(server:get_time() < winner_expires_at)
                validate_claim_children(response, mcycle_claim.computation_hash)
                return winner.final_state_hash
            end
        )
        if not propagation:wait(winner_expires_at) then
            elimination:wait()
            -- Both mcycle claims are eliminated despite the uarch tournament having a winner.
            -- Report this expiry separately from a uarch tournament that had no winner.
            return nil
        end
        -- Leaving the scope cancels the remaining callbacks.
        return winner.final_state_hash
    end
    ]]
    -- Without a uarch winner, Dave would request elimination immediately and wait for it.
    -- The Lua referee already has the result and needs neither exchange.
    story.report_uarch_result(mcycle_match, winner, next_state_hashes)
    return winner and winner.final_state_hash
end

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
    return propagate_uarch_result(mcycle_match, uarch_winner, next_state_hashes)
end
-- docs:end settle_mcycle_state_hash

-- Settles a match from its sealed divergence, handing the agreed and contested state hashes
-- to the tournament's level-specific settler.
-- docs:begin settle_divergence
local function settle_divergence(tournament, match, divergence)
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
-- docs:end settle_divergence

-- Reveals the path to the divergent leaves. Returns a winner or elimination on timeout,
-- or nil when the match is ready to seal. Each move owns its futures until it completes.
-- docs:begin reveal_divergence
local function reveal_divergence(tournament, match)
    while match.height > 1 do
        local turn_claim = match.claims[match.turn]
        local deadline = server:request_block() + 1
        local timeout <close> = emit_schedule_match_timeout_win(tournament, match, deadline)
        local elimination <close> = emit_schedule_match_elimination(match, deadline + 1)
        local reveal <close> = server:request_first_valid(
            subscription_hash(tournament.id, turn_claim),
            EVENTS.reveal_bisection,
            { turn_claim.computation_hash, match.position, match.height, match.other_left_node },
            function(response)
                assert(server:get_time() < deadline)
                return validate_bisection_response(match, response)
            end
        )
        local response = reveal:wait(deadline)
        if not response then
            return timeout:wait(deadline + 1) or elimination:wait()
        end
        advance_bisection(match, response)
        story.report_match_progress(match)
    end
end
-- docs:end reveal_divergence

-- Proves the divergent leaves and the agreed state before them. Returns the sealed
-- divergence, or nil and the winner or elimination if no valid seal arrives in time.
-- docs:begin seal_divergence
local function seal_divergence(tournament, match)
    local turn_claim = match.claims[match.turn]
    local deadline = server:request_block() + 1
    local timeout <close> = emit_schedule_match_timeout_win(tournament, match, deadline)
    local elimination <close> = emit_schedule_match_elimination(match, deadline + 1)
    local seal <close> = server:request_first_valid(
        subscription_hash(tournament.id, turn_claim),
        EVENTS.seal_divergence,
        { turn_claim.computation_hash, match.position, match.other_left_node },
        function(response)
            assert(server:get_time() < deadline)
            return validate_seal_response(tournament, match, response)
        end
    )
    local divergence = seal:wait(deadline)
    if not divergence then
        return nil, timeout:wait(deadline + 1) or elimination:wait()
    end
    return divergence
end
-- docs:end seal_divergence

-- Runs one match to its end. One or two names a winner, zero eliminates both.
-- docs:begin run_match
local function run_match(tournament, match)
    local winner = reveal_divergence(tournament, match)
    if winner then
        return winner
    end
    local divergence
    divergence, winner = seal_divergence(tournament, match)
    if winner then
        return winner
    end
    return settle_divergence(tournament, match, divergence)
end
-- docs:end run_match

-- Runs the matches concurrently and waits until all their winners have been recorded.
local function run_matches(tournament, matches)
    local functions = {}
    for _, match in ipairs(matches) do
        functions[#functions + 1] = function()
            match.winner = run_match(tournament, match)
        end
    end
    local completed <close> = server:run_all(functions)
    completed:wait()
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
    local geometry = dapp_contract.geometry
    local tournament_id = dapp_contract.initial_state_hash
    local close_block = server:request_block() + 1
    local collection <close> = server:request_all(
        dapp_contract.initial_state_hash,
        EVENTS.commit_mcycle_claim,
        {},
        function(response)
            return validate_claim(response, geometry.mcycle_height)
        end
    )
    local responses = collection:wait(close_block)
    server:wait_until(close_block)
    local claims = partition_claims(responses, tournament_id)
    local tournament = {
        level = "mcycle",
        id = tournament_id,
        height = geometry.mcycle_height,
        initial_state_hash = dapp_contract.initial_state_hash,
        dapp_contract = dapp_contract,
        settle_state_hash = settle_mcycle_state_hash,
        claims = claims,
    }
    story.report_claims(tournament)
    return tournament
end
-- docs:end open_mcycle_tournament

-- Authenticates the complete data at one expected machine-tree location. Its size follows the
-- proof, while this protocol requires every machine-validity target to be exactly one word.
local function verify_machine_word(data, proof, address, final_state_hash)
    assert(proof.root_hash == final_state_hash)
    assert(proof.log2_root_size == cartesi.HASH_TREE_LOG2_ROOT_SIZE)
    assert(proof.target_address == (address & ~WORD_MASK))
    assert(proof.log2_target_size == cartesi.HASH_TREE_LOG2_WORD_SIZE)
    assert(#data == 1 << proof.log2_target_size)
    assert(hash_tree.get_data_root_hash(data, proof.log2_target_size) == proof.target_hash)
    hash_tree.verify_slice(proof)
end

-- Reads a little-endian 64-bit integer at a zero-based byte offset.
local function get_uint64(data, offset)
    return string.unpack("<I8", data, 1 + offset)
end

local function split_tohost(tohost)
    local dev = (tohost & cartesi.HTIF_DEV_MASK) >> cartesi.HTIF_DEV_SHIFT
    local cmd = (tohost & cartesi.HTIF_CMD_MASK) >> cartesi.HTIF_CMD_SHIFT
    local reason = (tohost & cartesi.HTIF_REASON_MASK) >> cartesi.HTIF_REASON_SHIFT
    return dev, cmd, reason
end

-- Establishes that the settled machine is yielded manually with RX_ACCEPTED, then returns the
-- outputs Merkle root authenticated at its tx-buffer word, matching Dave's machine validity proof.
local function verify_outputs_merkle_root(result, final_state_hash)
    verify_machine_word(result.iflags_y_data, result.iflags_y_proof, IFLAGS_Y_ADDRESS, final_state_hash)
    assert(get_uint64(result.iflags_y_data, IFLAGS_Y_ADDRESS & WORD_MASK) ~= 0)

    verify_machine_word(result.htif_tohost_data, result.htif_tohost_proof, HTIF_TOHOST_ADDRESS, final_state_hash)
    local htif_tohost = get_uint64(result.htif_tohost_data, HTIF_TOHOST_ADDRESS & WORD_MASK)
    local dev, cmd, reason = split_tohost(htif_tohost)
    assert(dev == cartesi.HTIF_DEV_YIELD)
    assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL)
    assert(reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)

    verify_machine_word(result.tx_buffer_data, result.tx_buffer_proof, CMIO_TX_BUFFER_ADDRESS, final_state_hash)
    return result.tx_buffer_data
end

local function verify_output(output, outputs_merkle_root)
    local output_proof = output.output_proof
    assert(output.output_index == output_proof.target_address)
    assert(output_proof.log2_target_size == 0)
    assert(output_proof.log2_root_size == cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT)
    assert(output_proof.root_hash == outputs_merkle_root)
    assert(keccak(output.output) == output_proof.target_hash)
    hash_tree.verify_slice(output_proof)
    return true
end

-- Waits on the settled claim, the one the tournament leaves standing. It first establishes the
-- outputs Merkle root committed by the winning final state, then repeatedly asks for an output
-- and checks each offer against that root. The player chooses which output to offer.
-- An epoch with no output therefore still settles its outputs root without inventing an output.
-- docs:begin wait_for_outputs
local function wait_for_outputs(tournament, winner)
    local subscription = subscription_hash(tournament.id, winner)
    local root_proof <close> = server:request_first_valid(
        subscription,
        EVENTS.prove_outputs_merkle_root,
        {},
        function(response)
            return verify_outputs_merkle_root(response, winner.final_state_hash)
        end
    )
    local outputs_merkle_root = root_proof:wait()
    local accepted_output_indices = {}
    while true do
        local output_proof <close> = server:request_first_valid(
            subscription,
            EVENTS.prove_output,
            {},
            function(response)
                if not accepted_output_indices[response.output_index] then
                    return verify_output(response, outputs_merkle_root) and response
                end
            end
        )
        local output = output_proof:wait()
        accepted_output_indices[output.output_index] = true
        story.report_output(output)
    end
end
-- docs:end wait_for_outputs

-- Seen from the referee, the whole game is short. It opens the mcycle tournament, reduces the
-- claims it opened with, and, if one survives every match, settles the epoch on its result.
-- The mcycle tournament packs what the reduction needs: the agreed initial state hash,
-- the dapp contract whose inputs verification trusts, and the way its matches settle.
-- Everything hard, the accept loop, the wire, the coroutine scheduling, runs underneath, in
-- the referee server this is handed to.
-- docs:begin run_referee
local function run_referee(dapp_contract)
    server:accept_subscribers(dapp_contract.initial_state_hash)
    local tournament = open_mcycle_tournament(dapp_contract)
    local winner = run_tournament(tournament)
    story.report_winner(winner)
    if winner then
        wait_for_outputs(tournament, winner)
    end
end
-- docs:end run_referee

-- The dispute geometry the contract fixes at deployment. Its one free parameter is the mcycle
-- period, log2 of the mcycles between two samples of an mcycle claim. The remaining values
-- follow from it and the emulator's rollup constants. The referee and players use this same
-- geometry.
-- docs:begin new_geometry
local function new_geometry(log2_mcycles_per_period)
    local mcycle_height = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
        + cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
        - log2_mcycles_per_period
    local uarch_height = log2_mcycles_per_period + cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    assert(mcycle_height < 63 and uarch_height < 63, "claim leaf counts must fit in signed 64-bit integers")
    return {
        log2_mcycles_per_period = log2_mcycles_per_period,
        mcycles_per_period = 1 << log2_mcycles_per_period,
        mcycle_height = mcycle_height,
        uarch_height = uarch_height,
        periods_per_input = 1 << (cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_mcycles_per_period),
    }
end
-- docs:end new_geometry

-- Builds the contract context the referee and players read from the chain.
-- The initial state hash is announced at deployment, and the epoch's inputs are all posted
-- to the blockchain, so the contract holds its own copy of every one, the copy that
-- verification trusts over anything a player commits. The geometry is fixed here too, with
-- the documentation's period of 2^10 mcycles.
local function make_dapp_contract(initial_state_hash, inputs)
    return {
        initial_state_hash = initial_state_hash,
        inputs = inputs,
        geometry = new_geometry(10),
    }
end

-- The referee, standing in for the Dave contracts. Like a player constructor, this binds the
-- role's game logic to the deployed dapp contract without creating or running its transport.
local function new_referee(dapp_contract)
    return {
        dapp_contract = dapp_contract,
        run = function(self, referee_server)
            server = referee_server
            run_referee(self.dapp_contract)
        end,
    }
end

-- =============================================================================
-- Player
-- =============================================================================

local function write_stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

------------------------------------------------------------
-- Geometry
--
-- The epoch spans 2^24 inputs of 2^48 mcycles each, and every mcycle expands into 2^20
-- uarch transitions, the same three coordinates as the rolling verification game. The mcycle
-- claim samples the epoch every 2^LOG2_MCYCLES_PER_PERIOD mcycles. The uarch claim expands one mcycle
-- period into its uarch transitions. Each claim is stored bundled: the machine delivers one
-- subtree root per 2^bundle_height leaves, so the stored tree is that much shallower, and queries
-- below a bundle are answered by refining it.
------------------------------------------------------------

local LOG2_BUNDLE_MCYCLE_COUNT = 4
local LOG2_BUNDLE_UARCH_CYCLE_COUNT = 16
local LOG2_HASHES_PER_CHUNK = 8
local LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE = 10 -- assume about 1024 uarch cycles per mcycle
local MAX_MCYCLES_PER_ADVANCE_STATE = 1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local DEFAULT_MACHINE_CACHE_CAPACITY = 8
local DEFAULT_MACHINE_CACHE_INPUT_GAP = 1

-- Cycle targets use the machine's unsigned 64-bit coordinate.
local function umin(a, b)
    return math.ult(a, b) and a or b
end

local function usaturating_add(a, b, maximum)
    maximum = maximum or cartesi.MCYCLE_MAX
    if math.ult(maximum, b) or math.ult(maximum - b, a) then
        return maximum
    end
    return a + b
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

-- Limits each collection call to the mcycle span of 2^LOG2_HASHES_PER_CHUNK bundle roots,
-- bounding temporary hash storage. Caps the span at MCYCLE_MAX to avoid shift overflow.
local function mcycle_hashes_chunk_size(log2_period, log2_bundle_mcycle_count)
    local log2_chunk_size = log2_period + log2_bundle_mcycle_count + LOG2_HASHES_PER_CHUNK
    if log2_chunk_size >= 64 then
        return cartesi.MCYCLE_MAX
    end
    return 1 << log2_chunk_size
end

-- Forks a machine's server. The fork is shut down when the object holding it is closed or
-- collected, so a player leaves no server behind when it exits, even on an error.
local function fork_server(machine)
    local fork = assert(machine:fork_server())
    fork:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    return fork
end

-- Loads the initial machine snapshot from content-addressed local storage into a freshly
-- spawned server, and verifies that the stored machine actually has the requested state hash.
-- A spawned server shuts down when its handle is closed or collected, including after an error.
local function new_machine(initial_state_hash)
    local machine = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    machine:load(cartesi.tohex(initial_state_hash))
    assert(machine:get_root_hash() == initial_state_hash, "initial machine snapshot hash mismatch")
    return machine
end

------------------------------------------------------------
-- Machine checkpoint cache
--
-- A checkpoint is the virgin machine at an input boundary, before delivery, indexed by the input.
-- Callers request a boundary, not a retained checkpoint. The cache selects and clones a checkpoint,
-- then uses the forward build's driver to replay any intervening inputs.
--
-- The cache is only an optimization. Its first checkpoint is the content-addressed initial
-- machine at input zero. Cached machines are immutable: callers receive independent machines
-- and closeable owners. This implementation uses forks for clones and snapshots; another cache
-- can implement the same lifetime and replay contract with stored machines.
------------------------------------------------------------

local machine_cache_meta = { __index = {} }
local machine_owner_meta = { __index = {} }

-- Owners carry lifetime, never execution context. The cache also retains the owners so closing
-- it releases even a clone whose caller has not yet closed its owner.
function machine_owner_meta.__index:close()
    if not self.machine then
        return
    end
    local machine <close> = self.machine
    local backup <close> = self.backup -- luacheck: ignore 211
    self.cache.machines[machine] = nil
    self.machine, self.backup = nil, nil
end
machine_owner_meta.__close = machine_owner_meta.__index.close

-- Transfer ownership out of a <close> local without closing the machine on return.
function machine_owner_meta.__index:move()
    assert(self.machine, "machine owner is closed")
    local owner = setmetatable({ cache = self.cache, machine = self.machine, backup = self.backup }, machine_owner_meta)
    self.cache.machines[self.machine] = owner
    self.machine, self.backup = nil, nil
    return owner
end

local function new_machine_owner(cache, machine)
    local owner = setmetatable({ cache = cache, machine = machine }, machine_owner_meta)
    cache.machines[machine] = owner
    return machine, owner
end

function machine_cache_meta.__index:close()
    self.closed = true
    for _, owner in pairs(self.machines) do
        owner:close()
    end
    self.checkpoints = {}
end
machine_cache_meta.__close = machine_cache_meta.__index.close

function machine_cache_meta.__index:snapshot(machine)
    local owner = assert(self.machines[machine], "machine is not owned by this cache")
    assert(not owner.backup, "machine already has a snapshot")
    owner.backup = fork_server(machine)
end

function machine_cache_meta.__index:commit(machine)
    local owner = assert(self.machines[machine], "machine is not owned by this cache")
    local backup <close> = owner.backup -- luacheck: ignore 211
    owner.backup = nil
end

function machine_cache_meta.__index:revert(machine)
    local owner = assert(self.machines[machine], "machine is not owned by this cache")
    local backup <close> = assert(owner.backup, "no snapshot to revert to")
    owner.backup = nil
    machine:shutdown_server()
    machine:swap(backup)
end

-- Spreads a bounded number of checkpoints across the epoch to shorten replay when refining claims.
-- As the epoch advances, doubles the input gap and replaces closely spaced checkpoints with later
-- ones, preserving the initial machine so every input boundary remains reachable.
-- Only the forward claim build offers checkpoints, so the list remains ordered.
function machine_cache_meta.__index:consider(input_index, machine)
    assert(not self.closed, "machine cache is closed")
    local checkpoints = self.checkpoints
    local latest = checkpoints[#checkpoints]
    assert(input_index > latest.input_index, "machine checkpoints are not ordered")
    -- Ignore offers that are not far enough from the previous checkpoint.
    if input_index - latest.input_index < self.input_gap then
        return
    end
    -- Evict the next checkpoint that is too close to its predecessor.
    local replace_index
    if #checkpoints == self.capacity then
        replace_index = self.replace_cursor
        while replace_index <= #checkpoints do
            local previous = checkpoints[replace_index - 1].input_index
            if checkpoints[replace_index].input_index - previous < self.input_gap then
                break
            end
            replace_index = replace_index + 1
        end
        -- Every retained gap is large enough. Double the gap and restart the search.
        if replace_index > #checkpoints then
            self.input_gap = self.input_gap << 1
            self.replace_cursor = 2
            return
        end
    end
    if replace_index then
        local replaced = table.remove(checkpoints, replace_index)
        replaced.owner:close()
        self.replace_cursor = replace_index
    end
    -- Add the new checkpoint.
    local clone, owner <close> = new_machine_owner(self, fork_server(machine))
    checkpoints[#checkpoints + 1] = {
        input_index = input_index,
        machine = clone,
        owner = owner:move(),
    }
end

-- Selection is private: callers always receive the requested virgin boundary, not merely the
-- closest retained one. The owner closes the clone if replay fails before it can be returned.
function machine_cache_meta.__index:clone_at_input_boundary(input_index, replay)
    assert(not self.closed, "machine cache is closed")
    local closest = self.checkpoints[1]
    for i = 2, #self.checkpoints do
        if self.checkpoints[i].input_index > input_index then
            break
        end
        closest = self.checkpoints[i]
    end
    local machine, owner <close> = new_machine_owner(self, fork_server(closest.machine))
    replay(machine, closest.input_index, input_index)
    return machine, owner:move()
end

local function new_machine_cache(initial_machine, capacity, initial_input_gap)
    capacity = capacity or DEFAULT_MACHINE_CACHE_CAPACITY
    assert(capacity > 0, "machine cache capacity must include its initial checkpoint")
    local input_gap = initial_input_gap or DEFAULT_MACHINE_CACHE_INPUT_GAP
    local cache = setmetatable({
        capacity = capacity,
        checkpoints = {},
        machines = {},
        input_gap = input_gap,
        replace_cursor = 2,
    }, machine_cache_meta)
    local machine, owner = new_machine_owner(cache, initial_machine)
    cache.checkpoints[1] = { input_index = 0, machine = machine, owner = owner }
    return cache
end

-- Advances through a runner's run(mcycle_end) method, returning the first non-automatic break
-- reason. The runner is the machine itself for plain execution, or a computation-hash collector.
-- Automatic yields are read from the machine and passed to the optional callback; without one,
-- they are ignored. A terminal manual yield remains unread for the caller to handle.
local function run_to_stop(machine, mcycle_end, runner, on_yield_automatic)
    while true do
        local break_reason = runner:run(mcycle_end)
        if not is_yielded_automatic(break_reason) then
            return break_reason
        end
        if on_yield_automatic then
            local yield_reason, data = receive_cmio_request(machine)
            on_yield_automatic(yield_reason, data)
        end
    end
end

-- Delivers an input at an rx-accepted boundary, recording the root a rejection reverts to.
local function load_cmio_input(machine, data, revert_root_hash)
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
end

------------------------------------------------------------
-- Mcycle computation hashes
--
-- The player advances the whole epoch once, collecting the machine state hash every period
-- as bundle roots, one per 2^LOG2_BUNDLE_MCYCLE_COUNT samples. A machine stopped at a
-- manual yield, halt, or mcycle overflow repeats its state hash to the end of its input's span, and
-- the machine pads the stream accordingly, so each input contributes a short prefix of real bundles
-- followed by one enormous repetition. A machine that halted, overflowed, or yielded with an
-- exception takes no later input, so it repeats its state hash through every later span as
-- well. Each accepted input offers its final machine to a bounded cache as the next input's
-- virgin boundary. Later re-runs start from the closest input boundary its policy retained.
------------------------------------------------------------

-- Plain replay has the same input lifecycle as a sampled run.
local function noop() end
local function new_null_computation_hash(machine)
    return {
        begin_epoch = noop,
        begin_input = noop,
        end_input = noop,
        end_epoch = noop,
        run = function(_, mcycle_end)
            return machine:run(mcycle_end)
        end,
    }
end

local function mcycle_computation_hash_push_collected(claim, collected)
    local count = math.min(#collected.hashes, claim.input_entry_capacity - claim.input_entry_count)
    hash_tree.frontier_forest_append(claim.frontier, collected.hashes, 1, count)
    claim.next_leaf = claim.next_leaf + (count << claim.bundle_height)
    claim.input_entry_count = claim.input_entry_count + count
    if not is_at_fixed_point(collected.break_reason) then
        return
    end
    assert(#collected.hashes > 0, "fixed-point mcycle collection has no final bundle")
    claim.pad_bundle = collected.hashes[#collected.hashes]
    local pad_count = claim.input_entry_capacity - claim.input_entry_count
    hash_tree.frontier_forest_pad_back(claim.frontier, claim.pad_bundle, pad_count)
    claim.next_leaf = claim.next_leaf + (pad_count << claim.bundle_height)
    claim.input_entry_count = claim.input_entry_capacity
end

local function mcycle_computation_hash_begin_epoch(claim)
    claim.frontier = hash_tree.frontier_forest(claim.height - claim.bundle_height, "keccak256")
    claim.next_leaf = claim.window and claim.window.first_leaf or 0
    claim.input_entry_count = nil
    claim.pad_bundle = nil
end

local function mcycle_computation_hash_begin_input(claim, input_index, input_base)
    claim.input_index = input_index
    claim.next_leaf = claim.window and claim.window.first_leaf or input_index * claim.geometry.periods_per_input
    claim.input_entry_count = 0
    claim.mcycle_phase = 0
    claim.partial_bundle = nil
    claim.input_base = input_base
    claim.input_mcycle_end = usaturating_add(claim.input_base, MAX_MCYCLES_PER_ADVANCE_STATE)
end

-- Only the forward build offers checkpoints. An accepted yield is the next input's virgin
-- boundary. A rejected yield offers nothing, since the state after it is the input's own boundary.
local function consider_mcycle_machine(claim, collected)
    if not claim.cache_machine or not is_yielded_manual(collected.break_reason) then
        return
    end
    local yield_reason = receive_cmio_request(claim.machine)
    if is_rx_accepted(yield_reason) then
        claim.machine_cache:consider(claim.input_index + 1, claim.machine)
    end
end

local function mcycle_computation_hash_run(claim, mcycle_end)
    mcycle_end = umin(mcycle_end, claim.input_mcycle_end)
    local collected = { mcycle_phase = claim.mcycle_phase, partial_bundle = claim.partial_bundle }
    repeat
        local chunk_end = usaturating_add(claim.machine:read_reg("mcycle"), claim.chunk_size, mcycle_end)
        collected = claim.machine:collect_mcycle_root_hashes(
            chunk_end,
            claim.log2_period,
            collected.mcycle_phase,
            claim.bundle_height,
            collected.partial_bundle
        )
        mcycle_computation_hash_push_collected(claim, collected)
        consider_mcycle_machine(claim, collected)
    until not is_target_mcycle(collected.break_reason) or claim.machine:read_reg("mcycle") == mcycle_end
    claim.mcycle_phase, claim.partial_bundle = collected.mcycle_phase, collected.partial_bundle
    return collected.break_reason
end

local function mcycle_computation_hash_end_input(claim)
    if claim.input_entry_count == nil then
        return
    end
    assert(claim.input_entry_count == claim.input_entry_capacity, "mcycle computation hash input is incomplete")
    claim.input_entry_count = nil
end

local function mcycle_computation_hash_end_epoch(claim)
    claim:end_input()
    local end_leaf = claim.window and claim.window.first_leaf + (1 << claim.window.log2_leaf_count)
        or (1 << claim.geometry.mcycle_height)
    if claim.next_leaf == end_leaf then
        return claim.frontier
    end
    if not claim.pad_bundle then
        local collected = claim.machine:collect_mcycle_root_hashes(
            claim.machine:read_reg("mcycle"),
            claim.log2_period,
            0,
            claim.bundle_height
        )
        assert(is_at_fixed_point(collected.break_reason), "mcycle computation hash ended outside a fixed point")
        claim.pad_bundle = assert(collected.hashes[#collected.hashes], "fixed point has no padding bundle")
    end
    hash_tree.frontier_forest_pad_back(
        claim.frontier,
        claim.pad_bundle,
        (end_leaf - claim.next_leaf) >> claim.bundle_height
    )
    claim.next_leaf = end_leaf
    return claim.frontier
end

-- A window is an aligned logical leaf range, independent of where its stopped
-- machine physically stands. Omitting it selects the full epoch, bundled by default.
local function new_mcycle_computation_hash(geometry, machine_cache, machine, window)
    local log2_bundle_mcycle_count = window and window.log2_bundle_mcycle_count or LOG2_BUNDLE_MCYCLE_COUNT
    local height = window and window.log2_leaf_count or geometry.mcycle_height
    return {
        geometry = geometry,
        machine_cache = machine_cache,
        machine = machine,
        window = window,
        height = height,
        bundle_height = log2_bundle_mcycle_count,
        log2_period = geometry.log2_mcycles_per_period,
        chunk_size = mcycle_hashes_chunk_size(geometry.log2_mcycles_per_period, log2_bundle_mcycle_count),
        input_entry_capacity = window and (1 << (height - log2_bundle_mcycle_count))
            or (geometry.periods_per_input >> LOG2_BUNDLE_MCYCLE_COUNT),
        cache_machine = not window,
        begin_epoch = mcycle_computation_hash_begin_epoch,
        begin_input = mcycle_computation_hash_begin_input,
        run = mcycle_computation_hash_run,
        end_input = mcycle_computation_hash_end_input,
        end_epoch = mcycle_computation_hash_end_epoch,
    }
end

------------------------------------------------------------
-- Uarch computation hashes
------------------------------------------------------------

local function uarch_hashes_chunk_size(log2_bundle_uarch_cycle_count)
    local cycle_bundle_count = log2_bundle_uarch_cycle_count < LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE
            and (1 << (LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE - log2_bundle_uarch_cycle_count))
        or 1
    return math.max(1, (1 << LOG2_HASHES_PER_CHUNK) // (cycle_bundle_count + 2))
end

local function uarch_mcycle_forest(hashes, first, last, log2_bundle_uarch_cycle_count)
    local height = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - log2_bundle_uarch_cycle_count
    local capacity = 1 << height
    local real = last - first - 1
    assert(real >= 0 and real <= capacity - 1, "too many uarch cycles in an instruction")
    local forest = hash_tree.frontier_forest(height, "keccak256")
    hash_tree.frontier_forest_append(forest, hashes, first, last - 2)
    hash_tree.frontier_forest_pad_back(forest, hashes[last - 1], capacity - 1 - real)
    hash_tree.frontier_forest_push_back(forest, hashes[last])
    return forest
end

-- The unbundled window intersects real cycles, halt repetitions, and the reset.
local function append_uarch_window(claim, hashes, first, last)
    local capacity = 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local real = last - first - 1
    assert(real >= 0 and real <= capacity - 1, "too many uarch cycles in an instruction")
    local start = claim.window.first_leaf & (capacity - 1)
    local stop = start + (1 << claim.window.log2_leaf_count)
    if start < math.min(stop, real) then
        hash_tree.frontier_forest_append(claim.frontier, hashes, first + start, first + math.min(stop, real) - 1)
    end
    local halt_start, halt_end = math.max(start, real), math.min(stop, capacity - 1)
    if halt_start < halt_end then
        hash_tree.frontier_forest_pad_back(claim.frontier, hashes[last - 1], halt_end - halt_start)
    end
    if stop == capacity then
        hash_tree.frontier_forest_push_back(claim.frontier, hashes[last])
    end
    claim.next_leaf = claim.end_leaf
end

local function uarch_computation_hash_begin_input(claim, input_index, input_base)
    claim.input_index = input_index
    claim.input_base = input_base
    claim.revert_uarch_tail = claim.machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0).hashes
    local mcycle_offset = claim.window.first_leaf >> cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    claim.target_start =
        usaturating_add(claim.input_base, claim.period_index * claim.geometry.mcycles_per_period + mcycle_offset)
    local count = claim.window.log2_bundle_uarch_cycle_count == 0 and 1
        or (1 << (claim.window.log2_leaf_count - cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE))
    claim.target_end =
        usaturating_add(claim.target_start, count, usaturating_add(claim.input_base, MAX_MCYCLES_PER_ADVANCE_STATE))
end

local function uarch_computation_hash_run(claim, mcycle_end)
    local machine = claim.machine
    if math.ult(machine:read_reg("mcycle"), claim.target_start) then
        local reason = machine:run(umin(mcycle_end, claim.target_start))
        if not is_target_mcycle(reason) then
            return reason
        end
        if math.ult(mcycle_end, claim.target_start) then
            return reason
        end
    end
    local reason
    repeat
        local target = usaturating_add(machine:read_reg("mcycle"), claim.chunk_size, umin(mcycle_end, claim.target_end))
        local collected = machine:collect_uarch_cycle_root_hashes(target, claim.bundle_height, claim.revert_uarch_tail)
        local offsets = collected.mcycle_hash_offsets
        local available = #offsets - 1
        if claim.bundle_height == 0 then
            if available > 0 then
                append_uarch_window(claim, collected.hashes, offsets[1], offsets[2] - 1)
            end
        else
            local wanted = math.min(
                available,
                (claim.end_leaf - claim.next_leaf) >> cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
            )
            local group
            for i = 1, wanted do
                group = uarch_mcycle_forest(collected.hashes, offsets[i], offsets[i + 1] - 1, claim.bundle_height)
                hash_tree.frontier_forest_push_back(claim.frontier, group)
                claim.next_leaf = claim.next_leaf + (1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE)
            end
            if is_at_fixed_point(collected.break_reason) and claim.next_leaf < claim.end_leaf then
                assert(group, "fixed-point collection has no padding period")
                hash_tree.frontier_forest_pad_back(
                    claim.frontier,
                    group,
                    (claim.end_leaf - claim.next_leaf) >> cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
                )
                claim.next_leaf = claim.end_leaf
            end
        end
        reason = collected.break_reason
    until not is_target_mcycle(reason)
        or claim.next_leaf == claim.end_leaf
        or machine:read_reg("mcycle") == mcycle_end
    return reason
end

local function uarch_computation_hash_end_input(claim)
    if claim.next_leaf < claim.end_leaf then
        -- A yield before the selected window is now a fixed point. On rejection,
        -- collection uses the pre-delivery tail to reproduce the reverted state.
        claim.target_start = claim.machine:read_reg("mcycle")
        claim.target_end = cartesi.MCYCLE_MAX
        claim:run(cartesi.MCYCLE_MAX)
    end
    assert(claim.next_leaf == claim.end_leaf, "uarch computation hash window is incomplete")
end

local function uarch_computation_hash_begin_epoch(claim)
    claim.frontier = hash_tree.frontier_forest(claim.window.log2_leaf_count - claim.bundle_height, "keccak256")
    claim.next_leaf = claim.window.first_leaf
end

local function new_uarch_computation_hash(geometry, machine, window)
    return {
        geometry = geometry,
        machine = machine,
        window = window,
        period_index = window.epoch_period_index % geometry.periods_per_input,
        end_leaf = window.first_leaf + (1 << window.log2_leaf_count),
        bundle_height = window.log2_bundle_uarch_cycle_count,
        chunk_size = uarch_hashes_chunk_size(window.log2_bundle_uarch_cycle_count),
        begin_epoch = uarch_computation_hash_begin_epoch,
        begin_input = uarch_computation_hash_begin_input,
        run = uarch_computation_hash_run,
        end_input = uarch_computation_hash_end_input,
        end_epoch = function(self)
            self:end_input()
            return self.frontier
        end,
    }
end

------------------------------------------------------------
-- Event responses
--
-- The handlers below produce responses to events emitted by the referee. A player follows one
-- claim lineage: its mcycle claim, and, while that claim's match is suspended in a uarch
-- tournament, the uarch claim it committed there. Computation requests go to holders
-- of the relevant claim. Eliminate instructions need no machine and go to every player.
------------------------------------------------------------

local handlers = {}

-- The claim in the player's lineage with the given root.
local function get_claim_tree(player, computation_hash)
    for _, tree in ipairs({ player.mcycle_claim, player.uarch_claim }) do
        if tree:get_root() == computation_hash then
            return tree
        end
    end
    error("event concerns a claim this player does not hold: " .. format_short_hash(computation_hash))
end

function handlers.get_claim_children(player, computation_hash)
    local tree = get_claim_tree(player, computation_hash)
    local left, right = tree:get_children(0, tree.height)
    return { computation_hash_left = left, computation_hash_right = right }
end

function handlers.schedule_match_timeout_win(player, _, computation_hash)
    return function()
        return player:get_claim_children(computation_hash)
    end
end

function handlers.schedule_match_elimination(player)
    return function()
        write_stderr("%s: returning eliminate_match\n", player.label)
        return true
    end
end

-- A claim: the computation hash's two children and the standard proof of its final state,
-- the last leaf. Producing the proof explicitly opens the last stored bundle.
local function make_claim(tree)
    local final_state_index = (1 << tree.height) - 1
    if tree.bundle_height > 0 then
        tree:open_bundle(final_state_index >> tree.bundle_height)
    end
    local computation_hash_left, computation_hash_right = tree:get_children(0, tree.height)
    return {
        computation_hash_left = computation_hash_left,
        computation_hash_right = computation_hash_right,
        final_state_hash_proof = tree:prove(final_state_index),
    }
end

-- The player's opening mcycle claim. The player announces its root, so a transcript can be
-- read against the players, without the referee ever narrating who holds what.
function handlers.commit_mcycle_claim(player)
    write_stderr("%s: building mcycle claim\n", player.label)
    player.mcycle_claim = player:make_mcycle_tree()
    local claim = make_claim(player.mcycle_claim)
    write_stderr(
        "%s: posted claim %s with final state %s\n",
        player.label,
        format_short_hash(player.mcycle_claim:get_root()),
        format_short_hash(claim.final_state_hash_proof.target_hash)
    )
    return claim
end

-- Reveals the nodes the referee needs for one bisection advance: the claim's node at
-- (position, height), and the children of the node the walk descends into. Either node can
-- cross into a stored bundle here because the claims alternate turns; crossing reconstructs
-- and authenticates that complete bundle before the walk continues through it.
function handlers.reveal_bisection(player, computation_hash, position, height, other_left_node)
    assert(height > 1)
    local tree = get_claim_tree(player, computation_hash)
    if height == tree.bundle_height then
        tree:open_bundle(position >> tree.bundle_height)
    end
    local turn_left_node, turn_right_node = tree:get_children(position, height)
    local descend_left = turn_left_node ~= other_left_node
    local child_position = descend_left and position or position + (1 << (height - 1))
    if height - 1 == tree.bundle_height then
        tree:open_bundle(child_position >> tree.bundle_height)
    end
    local turn_next_left_node, turn_next_right_node = tree:get_children(child_position, height - 1)
    return {
        turn_left_node = turn_left_node,
        turn_right_node = turn_right_node,
        turn_next_left_node = turn_next_left_node,
        turn_next_right_node = turn_next_right_node,
    }
end

-- Seals the leftmost divergence: exposes the final leaves and proves the agreed state
-- immediately before them, except at state zero where the referee already knows that state.
-- At the first leaf of a bundle, the proof explicitly opens the preceding bundle too.
function handlers.seal_divergence(player, computation_hash, position, other_left_node)
    local tree = get_claim_tree(player, computation_hash)
    local turn_left_node, turn_right_node = tree:get_children(position, 1)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= other_left_node
    local state_index = position + (descend_left and 0 or 1)
    if state_index ~= 0 then
        local agreed_state_index = state_index - 1
        if tree.bundle_height > 0 then
            tree:open_bundle(agreed_state_index >> tree.bundle_height)
        end
        response.agreed_state_hash_proof = tree:prove(agreed_state_index)
        assert(
            descend_left or response.agreed_state_hash_proof.target_hash == turn_left_node,
            "right divergence has the wrong agreed state"
        )
    end
    return response
end

-- Joins the uarch tournament over one mcycle period that the player's mcycle claim is
-- disputed in, with a uarch claim whose final state must be one of the two contested values.
-- The uarch claim becomes the nested claim of the player's lineage, replacing any earlier
-- one, since the parent match is suspended until the uarch tournament ends. The input index
-- and the period index are 0-based, as the referee counts them. A holder whose uarch claim
-- ends in neither contested value cannot defend its parent claim, and dies on the
-- contradiction.
function handlers.commit_uarch_claim(player, input_index, period_index, next_state_hashes)
    write_stderr("%s: building uarch claim for input %d, period %d\n", player.label, input_index, period_index)
    player.uarch_claim = player:make_uarch_tree(input_index + 1, period_index)
    local claim = make_claim(player.uarch_claim)
    local final_state_hash = claim.final_state_hash_proof.target_hash
    assert(
        final_state_hash == next_state_hashes[1] or final_state_hash == next_state_hashes[2],
        string.format(
            "%s: uarch final %s matches neither contested final %s nor %s",
            player.label,
            format_short_hash(final_state_hash),
            format_short_hash(next_state_hashes[1]),
            format_short_hash(next_state_hashes[2])
        )
    )
    write_stderr("%s: uarch claim ready\n", player.label)
    return claim
end

-- Inputs and cache belong to the caller. Strategy constructors configure them before
-- these operations capture their dependencies. Each replay still has its own machine.
local function new_player(geometry, inputs, machine_cache, options)
    options = options or {}
    options.new_mcycle_computation_hash = options.new_mcycle_computation_hash or new_mcycle_computation_hash
    options.new_uarch_computation_hash = options.new_uarch_computation_hash or new_uarch_computation_hash
    options.new_null_computation_hash = options.new_null_computation_hash or new_null_computation_hash
    local player = { label = options.label or "honest" }
    for name, handler in pairs(handlers) do
        player[name] = handler
    end

    -- Run one input from its virgin boundary. Both full epochs and partial replay use
    -- the same delivery and rollback rules. Only accepted inputs publish their outputs.
    -- Delivery is the protocol's no-op except at an rx-accepted yield, so a machine at any other
    -- fixed point, or an input beyond the posted ones, idles through the input's span.
    local function run_advance_state_input(machine, input_index, claim, offset, revert_root_hash, on_accepted)
        local base = machine:read_reg("mcycle")
        claim:begin_input(input_index, base)
        machine_cache:snapshot(machine)
        local break_reason = run_to_stop(machine, base, machine)
        assert(is_at_fixed_point(break_reason), "input boundary is not at a fixed point")
        local data = inputs[input_index + 1]
        if data and is_yielded_manual(break_reason) then
            local yield_reason = receive_cmio_request(machine)
            if is_rx_accepted(yield_reason) then
                load_cmio_input(machine, data, revert_root_hash)
            end
        end
        local pending = {}
        break_reason = run_to_stop(machine, usaturating_add(base, offset), claim, function(yield_reason, output)
            if on_accepted and is_tx_output(yield_reason) then
                pending[#pending + 1] = output
            end
        end)
        local yield_reason, reported_root
        if is_yielded_manual(break_reason) then
            yield_reason, reported_root = receive_cmio_request(machine)
        end
        if is_at_fixed_point(break_reason) then
            claim:end_input()
        end
        if is_rx_rejected(yield_reason) then
            machine_cache:revert(machine)
            assert(machine:get_root_hash() == revert_root_hash, "rollback did not restore the input boundary")
        else
            if is_rx_accepted(yield_reason) and on_accepted then
                on_accepted(pending, reported_root)
            end
            -- Acceptance, sticky stops, and partial replay all retain the running machine.
            machine_cache:commit(machine)
        end
        return break_reason, yield_reason, base
    end

    -- Runs the explicit input range [input_index_begin, input_index_end), limited to posted inputs.
    -- A sticky fixed point ends the range early, since every later input idles.
    local function run_advance_state_epoch(machine, claim, input_index_begin, input_index_end, on_accepted)
        input_index_end = math.min(input_index_end, #inputs)
        -- Keep the expected boundary across rejections. Only acceptance establishes a new one.
        local revert_root_hash = machine:get_root_hash()
        claim:begin_epoch()
        for input_index = input_index_begin, input_index_end - 1 do
            local break_reason, yield_reason = run_advance_state_input(
                machine,
                input_index,
                claim,
                MAX_MCYCLES_PER_ADVANCE_STATE,
                revert_root_hash,
                on_accepted
            )
            if is_rx_accepted(yield_reason) then
                revert_root_hash = machine:get_root_hash()
            elseif not is_rx_rejected(yield_reason) then
                assert(is_at_fixed_point(break_reason), "input stopped outside a fixed point")
                break
            end
        end
        return claim:end_epoch()
    end

    local function replay(machine, input_index_begin, input_index_end)
        local claim = options.new_null_computation_hash(machine)
        return run_advance_state_epoch(machine, claim, input_index_begin, input_index_end)
    end

    -- docs:begin build_mcycle_claim
    local function build_mcycle_claim()
        local machine, owner <close> = machine_cache:clone_at_input_boundary(0, replay) -- luacheck: ignore 211
        local claim = options.new_mcycle_computation_hash(geometry, machine_cache, machine)
        return run_advance_state_epoch(machine, claim, 0, #inputs)
    end
    -- docs:end build_mcycle_claim

    -- docs:begin refine_mcycle_claim
    local function refine_mcycle_claim(bundle_index)
        local first_leaf = bundle_index << LOG2_BUNDLE_MCYCLE_COUNT
        local input_index = first_leaf // geometry.periods_per_input
        local period_index = first_leaf % geometry.periods_per_input
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, replay)
        local revert_root_hash = machine:get_root_hash()
        local claim = options.new_null_computation_hash(machine)
        local break_reason, _, base = run_advance_state_input(
            machine,
            input_index,
            claim,
            period_index * geometry.mcycles_per_period,
            revert_root_hash
        )
        claim = options.new_mcycle_computation_hash(
            geometry,
            machine_cache,
            machine,
            { first_leaf = first_leaf, log2_leaf_count = LOG2_BUNDLE_MCYCLE_COUNT, log2_bundle_mcycle_count = 0 }
        )
        claim:begin_epoch()
        if is_at_fixed_point(break_reason) then
            return claim:end_epoch()
        end
        claim:begin_input(input_index, base)
        run_to_stop(
            machine,
            usaturating_add(base, (period_index + (1 << LOG2_BUNDLE_MCYCLE_COUNT)) * geometry.mcycles_per_period),
            claim
        )
        return claim:end_epoch()
    end
    -- docs:end refine_mcycle_claim

    local function run_uarch_window(window)
        local input_index = window.epoch_period_index // geometry.periods_per_input
        local period_index = window.epoch_period_index % geometry.periods_per_input
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, replay)
        local revert_root_hash = machine:get_root_hash()
        local claim = options.new_uarch_computation_hash(geometry, machine, window)
        claim:begin_epoch()
        run_advance_state_input(
            machine,
            input_index,
            claim,
            (period_index + 1) * geometry.mcycles_per_period,
            revert_root_hash
        )
        return claim:end_epoch()
    end

    -- docs:begin build_uarch_claim
    local function build_uarch_claim(input_index, period_index)
        return run_uarch_window({
            epoch_period_index = (input_index - 1) * geometry.periods_per_input + period_index,
            first_leaf = 0,
            log2_leaf_count = geometry.uarch_height,
            log2_bundle_uarch_cycle_count = LOG2_BUNDLE_UARCH_CYCLE_COUNT,
        })
    end
    -- docs:end build_uarch_claim

    local function collect_uarch_window(epoch_period_index, first_leaf, log2_count)
        return run_uarch_window({
            epoch_period_index = epoch_period_index,
            first_leaf = first_leaf,
            log2_leaf_count = log2_count,
            log2_bundle_uarch_cycle_count = 0,
        })
    end

    -- docs:begin refine_uarch_claim
    local function refine_uarch_claim(input_index, period_index, bundle_index)
        return collect_uarch_window(
            (input_index - 1) * geometry.periods_per_input + period_index,
            bundle_index << LOG2_BUNDLE_UARCH_CYCLE_COUNT,
            LOG2_BUNDLE_UARCH_CYCLE_COUNT
        )
    end
    -- docs:end refine_uarch_claim

    -- The disputed transition's access logs, produced by positioning a fresh fork at the
    -- transition and logging it, whatever claim is under dispute. The transition out of an
    -- input boundary includes the input, when the epoch has one, before the first uarch step.
    -- The transition closing an instruction executes one more step, by then a fixed point, and
    -- the reset. Every other transition is an ordinary uarch step.
    -- docs:begin prove_state_transition
    function player.prove_state_transition(_, input_index, period_index, state_transition_offset)
        local mcycle_offset = state_transition_offset >> cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
        local uarch_cycle = state_transition_offset & cartesi.UARCH_CYCLE_MAX
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, replay)
        local revert_root_hash = machine:get_root_hash()
        local data = inputs[input_index + 1]
        if state_transition_offset == 0 and period_index == 0 and data then
            local send_cmio_log =
                machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
            return { send_cmio_log = send_cmio_log, step_log = machine:log_step_uarch() }
        end
        local claim = options.new_null_computation_hash(machine)
        run_advance_state_input(
            machine,
            input_index,
            claim,
            period_index * geometry.mcycles_per_period + mcycle_offset,
            revert_root_hash
        )
        machine:run_uarch(uarch_cycle)
        if uarch_cycle == cartesi.UARCH_CYCLE_MAX then
            local step_log = machine:log_step_uarch()
            return { step_log = step_log, reset_uarch_log = machine:log_reset_uarch() }
        end
        return { step_log = machine:log_step_uarch() }
    end
    -- docs:end prove_state_transition

    -- A machine leaf proof includes the complete target data, separately from the standard proof
    -- that authenticates its hash. Machine registers may sit within a word, so the proof starts at
    -- the containing word boundary.
    local function get_machine_leaf(machine, address)
        local target_address = address & ~WORD_MASK
        return machine:read_memory(target_address, WORD_SIZE),
            machine:get_proof(target_address, cartesi.HASH_TREE_LOG2_WORD_SIZE)
    end

    -- Re-runs the whole epoch on a fresh machine, collecting its outputs separately from the three
    -- final-machine leaves Dave uses to validate an epoch result. A rejected input reverts to the
    -- pre-feed snapshot, exactly as a Cartesi Node rolls back. A machine that halted, overflowed,
    -- or threw an exception takes no later input, and its terminal state is the one Dave checks.
    local function compute_epoch_results()
        if player.outputs_merkle_root_result then
            return
        end
        local machine, owner <close> = machine_cache:clone_at_input_boundary(0, replay) -- luacheck: ignore 211
        local genesis_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
        local frontier = hash_tree.frontier_copy(genesis_frontier)
        local outputs, leaves = {}, {}
        local claim = options.new_null_computation_hash(machine)
        run_advance_state_epoch(machine, claim, 0, #inputs, function(pending, reported_root)
            for _, output in ipairs(pending) do
                outputs[#outputs + 1] = output
                leaves[#leaves + 1] = keccak(output)
                hash_tree.frontier_push_back(frontier, leaves[#leaves])
            end
            assert(hash_tree.frontier_get_root_hash(frontier) == reported_root, "outputs Merkle root mismatch")
        end)
        local iflags_y_data, iflags_y_proof = get_machine_leaf(machine, IFLAGS_Y_ADDRESS)
        local htif_tohost_data, htif_tohost_proof = get_machine_leaf(machine, HTIF_TOHOST_ADDRESS)
        local tx_buffer_data, tx_buffer_proof = get_machine_leaf(machine, CMIO_TX_BUFFER_ADDRESS)
        player.outputs_merkle_root_result = {
            iflags_y_data = iflags_y_data,
            iflags_y_proof = iflags_y_proof,
            htif_tohost_data = htif_tohost_data,
            htif_tohost_proof = htif_tohost_proof,
            tx_buffer_data = tx_buffer_data,
            tx_buffer_proof = tx_buffer_proof,
        }
        local output_index = options.output_index or #outputs - 1
        player.output = {
            output_index = output_index >= 0 and output_index or nil,
            output = outputs[output_index + 1],
            output_proof = hash_tree.frontier_next_proofs(genesis_frontier, leaves)[output_index + 1],
        }
    end

    -- Proves that the settled final state is yielded manually with RX_ACCEPTED and authenticates
    -- the word whose data is the outputs Merkle root.
    -- docs:begin prove_outputs_merkle_root
    function player.prove_outputs_merkle_root()
        compute_epoch_results()
        return player.outputs_merkle_root_result
    end
    -- docs:end prove_outputs_merkle_root

    -- Offers the output chosen by this player, defaulting to the last output. The referee supplies
    -- no index or acceptance information. An empty table is no offer when the output does not exist.
    function player.prove_output()
        compute_epoch_results()
        local output = player.output
        if not output.output then
            return {}
        end
        return output
    end

    function player.make_mcycle_tree()
        return new_tree(
            geometry.mcycle_height,
            LOG2_BUNDLE_MCYCLE_COUNT,
            build_mcycle_claim(),
            function(_, bundle_index)
                return refine_mcycle_claim(bundle_index)
            end
        )
    end
    function player.make_uarch_tree(_, input_index, period_index)
        return new_tree(
            geometry.uarch_height,
            LOG2_BUNDLE_UARCH_CYCLE_COUNT,
            build_uarch_claim(input_index, period_index),
            function(_, bundle_index)
                return refine_uarch_claim(input_index, period_index, bundle_index)
            end
        )
    end
    function player.refine_mcycle_claim(_, bundle_index)
        return refine_mcycle_claim(bundle_index)
    end
    function player.refine_uarch_claim(_, input_index, period_index, bundle_index)
        return refine_uarch_claim(input_index, period_index, bundle_index)
    end
    return player
end

-- Module loading exposes the shared implementation without starting a CLI role.
if ... == "prt" then
    return {
        LOG2_BUNDLE_MCYCLE_COUNT = LOG2_BUNDLE_MCYCLE_COUNT,
        LOG2_BUNDLE_UARCH_CYCLE_COUNT = LOG2_BUNDLE_UARCH_CYCLE_COUNT,
        new_player = new_player,
        new_machine = new_machine,
        new_null_computation_hash = new_null_computation_hash,
        new_mcycle_computation_hash = new_mcycle_computation_hash,
        new_uarch_computation_hash = new_uarch_computation_hash,
        umin = umin,
        usaturating_add = usaturating_add,
        is_target_mcycle = is_target_mcycle,
        is_at_fixed_point = is_at_fixed_point,
        consider_mcycle_machine = consider_mcycle_machine,
        uarch_mcycle_forest = uarch_mcycle_forest,
        new_machine_cache = new_machine_cache,
        player_handlers = handlers,
        new_match = new_match,
        new_referee = new_referee,
        new_geometry = new_geometry,
        validate_bisection_response = validate_bisection_response,
        advance_bisection = advance_bisection,
        validate_seal_response = validate_seal_response,
    }
end

-- =============================================================================
-- Role dispatch
-- =============================================================================

local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")
local next_argument = 3

local function take_argument(message)
    local value = assert(arg[next_argument], message)
    next_argument = next_argument + 1
    return value
end

local function take_remaining_arguments()
    local first = next_argument
    next_argument = #arg + 1
    return table.unpack(arg, first, #arg)
end

local initial_state_hash = cartesi.fromhex(take_argument("missing initial state hash"))
assert(#initial_state_hash == 32, "invalid initial state hash")

local run_role
if role == "referee" then
    run_role = function(dapp_contract)
        prtu.run_server(new_referee(dapp_contract), server_address)
    end
elseif role == "honest" then
    local output_index = tonumber(take_argument("missing output index"))
    assert(math.type(output_index) == "integer" and output_index >= 0, "invalid output index")
    run_role = function(dapp_contract)
        local inputs = { table.unpack(dapp_contract.inputs) }
        local cache <close> = new_machine_cache(new_machine(dapp_contract.initial_state_hash))
        local player = new_player(dapp_contract.geometry, inputs, cache, { output_index = output_index })
        prtu.run_client(player, server_address)
    end
else
    error("unknown role: " .. role)
end

local dapp_contract = make_dapp_contract(initial_state_hash, read_inputs(take_remaining_arguments()))
run_role(dapp_contract)
