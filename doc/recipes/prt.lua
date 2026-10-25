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
-- Roles, selected by the first argument. Every game role takes the referee address and the
-- epoch's initial state hash. Only the referee role's runner takes input files: it simulates
-- blockchain input_added and epoch_sealed events before running the tournament referee.
-- A machine-holding player finds its own initial snapshot stored under that hash name. The
-- referee is never told how many players to expect: it accepts subscribers until a
-- phase-closer connection closes that phase, then emits the tournament event to those
-- subscribers. The referee pairs claims in the order their posters joined, so the bracket and
-- the whole narration are a function of the claims, the join order, and prescribed responses
-- or skips.
--   prt.lua referee  <address> <initial-state-hash> <input> [<input> ...]
--   prt.lua honest   <address> <initial-state-hash> [<label> [<epoch-directory>]]
--   prt.lua phase_closer <address> [stop]
--
-- A player's label names it in the story and defaults to its role. An existing epoch directory
-- makes the player run on stored machines kept there instead of forked servers.
-- The phase closer closes initial subscriptions once every player is in, then disconnects.
-- A later invocation with stop ends the example through the server, including pending proof waits.
-- Mcycle and uarch tournaments gather claims from fixed audiences while their allowance of
-- logical blocks lasts. Wall-clock computation speed does not consume a protocol allowance.
--
-- The referee, honest player, machines, claim trees, and computation hashes live here.
-- The shared protocol, referee server, and hidden narration live in prtu.lua.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prtu = require("prtu")
local cartesi_jsonrpc = require("cartesi.jsonrpc")

local keccak = cartesi.keccak256
local get_other_turn_index = prtu.get_other_turn_index
local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
local WORD_MASK = WORD_SIZE - 1
local IFLAGS_Y_ADDRESS = cartesi.machine:get_reg_address("iflags_Y")
local HTIF_TOHOST_ADDRESS = cartesi.machine:get_reg_address("htif_tohost")
local CMIO_TX_BUFFER_ADDRESS = cartesi.AR_CMIO_TX_BUFFER_START
local LOG2_MAX_ADVANCE_STATES_PER_EPOCH = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH
local LOG2_MAX_MCYCLES_PER_ADVANCE_STATE = cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
local LOG2_MAX_UARCH_CYCLES_PER_MCYCLE = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local UARCH_CYCLE_MAX = cartesi.UARCH_CYCLE_MAX
local HTIF_YIELD_REASON_ADVANCE_STATE = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE

-- The phase closer carries no dispute. It closes the initial subscription phase once the last
-- player has connected. Tournament claim collection then uses logical time. It needs none
-- of the game geometry.
if arg[1] == "phase_closer" then
    return prtu.run_client(prtu.new_phase_closer(arg[3]), assert(arg[2], "missing referee address"))
end

local EVERYONE = prtu.EVERYONE
local FOREVER = nil
local EVENTS = prtu.EVENTS
local story = prtu.story

-- Transform values while preserving their keys.
local function map(values, transform)
    local result = {}
    for key, value in pairs(values) do
        result[key] = transform(value)
    end
    return result
end

-- Protocol offsets are zero-based and scoped to their epoch, input, or period.
-- Machine mcycle boundaries are absolute counter values. Keep the epoch period offset separate
-- from the uarch transition offset because their combined counter would exceed 64 bits.
local function split_epoch_period_offset(periods_per_input, epoch_period_offset)
    return epoch_period_offset // periods_per_input, epoch_period_offset % periods_per_input
end

local function combine_epoch_period_offset(periods_per_input, epoch_input_offset, input_period_offset)
    return epoch_input_offset * periods_per_input + input_period_offset
end

local function split_state_transition_offset(state_transition_offset)
    return state_transition_offset >> LOG2_MAX_UARCH_CYCLES_PER_MCYCLE, state_transition_offset & UARCH_CYCLE_MAX
end

local function combine_input_mcycle_offset(mcycles_per_period, input_period_offset, period_mcycle_offset)
    return input_period_offset * mcycles_per_period + period_mcycle_offset
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
        turn_index = 1,
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
    assert(match.height > 1, "match not bisecting")
    match.height = match.height - 1
    local descend_left = response.turn_left_node ~= match.other_left_node
    if descend_left then
        match.turn_parent_node = match.other_left_node
    else
        match.turn_parent_node = match.other_right_node
        match.position = match.position + (1 << match.height)
    end
    match.other_left_node = response.turn_next_left_node
    match.other_right_node = response.turn_next_right_node
    match.turn_index = get_other_turn_index(match.turn_index)
end
-- docs:end advance_bisection

-- =============================================================================
-- Referee
--
-- The referee holds only what the blockchain would: the agreed initial state hash, the
-- deployed dapp contract with the epoch's inputs, and the geometry. During a match it
-- tracks one node hash per claim as it walks the two trees down, and each claim's clock, so
-- it stores nothing of the claims but the path in dispute and the time they have left. It
-- narrates each claim with the labels that posted it, which never influence protocol state
-- or ordering.
-- =============================================================================

-- The referee server and its coroutine dispatcher, built with the referee and shared by every
-- coroutine of its logic.
local server

-- Blockchain operations; the simulation transport stays outside the algorithm excerpts.
local function notify_all(subscriptions, event, arguments)
    server:notify_all(subscriptions, event, arguments)
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

local function subscribe_connection(hash, connection)
    return server:subscribe_connection(hash, connection)
end

local function wait_until(block)
    return server:wait_until(block)
end

local function run_all(functions)
    return server:run_all(functions)
end

-- The block of the transaction in flight, whether it opens a tournament or carries a response
-- being validated. Windows are measured in logical blocks from it.
local function current_time()
    return server:get_time()
end

-- Validates a claim: its two children establish the computation hash, and its standard proof
-- places the final state at the tree's last leaf. Returns its normalized referee representation.
local function validate_claim_response(submitted_claim, height)
    local computation_hash = keccak(submitted_claim.computation_hash_left, submitted_claim.computation_hash_right)
    local final_state_hash_proof = submitted_claim.final_state_hash_proof
    assert(final_state_hash_proof.target_address == (1 << height) - 1, "final state proof not at last leaf")
    assert(final_state_hash_proof.log2_target_size == 0, "final state proof target not a leaf")
    assert(final_state_hash_proof.log2_root_size == height, "final state proof height mismatch")
    assert(#final_state_hash_proof.sibling_hashes == height, "final state proof sibling count mismatch")
    assert(final_state_hash_proof.root_hash == computation_hash, "final state proof root mismatch")
    hash_tree.verify_slice(final_state_hash_proof)
    return {
        computation_hash = computation_hash,
        computation_hash_left = submitted_claim.computation_hash_left,
        computation_hash_right = submitted_claim.computation_hash_right,
        final_state_hash = final_state_hash_proof.target_hash,
    }
end

-- A claim's subscription hash combines its computation hash with its tournament ID.
-- The mcycle tournament's ID is the initial state hash. A uarch tournament's ID is the
-- hash of the two mcycle claims whose match opened it, as Match.sol identifies a match.
-- This keeps holders of equal computation hashes in different tournaments separate.
local function subscription_hash(tournament_id, claim)
    return keccak(tournament_id, claim.computation_hash)
end

-- Partitions claim responses by computation hash. The server supplies the join
-- order of their senders, so claims come out in the order their first posters joined,
-- and each sender subscribes to its claim under the given tournament ID.
-- Pairing in join order is what Dave's dangling slot does,
-- and it makes the bracket a function of the claims and of the order the players joined, which
-- the recipe fixes. Each claim's clock starts as the tournament's allowance less the blocks
-- since the tournament opened.
-- docs:begin partition_claims
local function partition_claims(responses, order, tournament_id, start_instant, allowance)
    local claims = {}
    local by_hash = {}
    for _, sender in ipairs(order) do
        local response = responses[sender]
        local claim = by_hash[response.claim.computation_hash]
        if not claim then
            claim = response.claim
            claim.allowance = allowance - (response.received_at - start_instant)
            by_hash[claim.computation_hash] = claim
            claims[#claims + 1] = claim
        end
        subscribe_connection(subscription_hash(tournament_id, claim), response.connection)
    end
    return claims
end
-- docs:end partition_claims

-- Verifies the disputed transition's logs on their own, the way the Dave contracts verify
-- them on the blockchain, without ever instantiating a machine. `epoch_period_offset` and
-- `state_transition_offset` are the 64-bit-safe split of CartesiStateTransition.sol's epoch-local
-- counter. The counter picks the form: the transition out of an input boundary includes
-- the input the dapp contract holds (never one a player supplies), the transition closing an
-- instruction verifies a step and then the reset, and every other is an ordinary step. Each
-- verification returns the state hash its log provably advances to, and the chain starts
-- from the agreed state hash. Returns the state hash the logs reach; invalid logs raise an
-- error, which the request dispatcher rejects through its protected validator callback.
-- docs:begin validate_state_transition_response
local function validate_state_transition_response(
    dapp_contract,
    root_hash_before,
    epoch_period_offset,
    state_transition_offset,
    response
)
    local periods_per_input = dapp_contract.geometry.periods_per_input
    local epoch_input_offset, input_period_offset = split_epoch_period_offset(periods_per_input, epoch_period_offset)
    local _, uarch_cycle = split_state_transition_offset(state_transition_offset)
    local obtained_root_hash = root_hash_before
    local input_data = dapp_contract.inputs[epoch_input_offset + 1]
    if state_transition_offset == 0 and input_period_offset == 0 and input_data then
        obtained_root_hash = cartesi.machine:verify_send_cmio_response(
            HTIF_YIELD_REASON_ADVANCE_STATE,
            input_data,
            root_hash_before,
            response.send_cmio_log,
            root_hash_before
        )
    end
    obtained_root_hash = cartesi.machine:verify_step_uarch(obtained_root_hash, response.step_log)
    if uarch_cycle == UARCH_CYCLE_MAX then
        obtained_root_hash = cartesi.machine:verify_reset_uarch(obtained_root_hash, response.reset_uarch_log)
    end
    return obtained_root_hash
end
-- docs:end validate_state_transition_response

-- Validates an internal-node bisection response.
-- docs:begin validate_bisection_response
local function validate_bisection_response(match, response)
    assert(match.height > 1, "match not bisecting")
    assert(keccak(response.turn_left_node, response.turn_right_node) == match.turn_parent_node, "wrong children")
    local turn_child_node = (response.turn_left_node ~= match.other_left_node) and response.turn_left_node
        or response.turn_right_node
    assert(keccak(response.turn_next_left_node, response.turn_next_right_node) == turn_child_node, "wrong next nodes")
    return response
end
-- docs:end validate_bisection_response

-- Validates a seal-divergence response and returns the normalized divergence. The leaves must
-- open the on-turn node. At leaf zero the agreed state is the tournament's initial state;
-- otherwise the on-turn claim must prove the preceding state against its computation hash.
-- docs:begin validate_seal_response
local function validate_seal_response(tournament, match, response)
    assert(match.height == 1, "match not ready to seal")
    assert(keccak(response.turn_left_node, response.turn_right_node) == match.turn_parent_node, "wrong leaves")
    local descend_left = response.turn_left_node ~= match.other_left_node
    local leaf_index = match.position + (descend_left and 0 or 1)
    local agreed_state_hash
    if leaf_index ~= 0 then
        local proof = response.agreed_state_hash_proof
        assert(proof.target_address == leaf_index - 1, "agreed state proof not at leaf before divergence")
        assert(proof.log2_target_size == 0, "agreed state proof target not a leaf")
        assert(proof.log2_root_size == tournament.height, "agreed state proof height mismatch")
        assert(#proof.sibling_hashes == tournament.height, "agreed state proof sibling count mismatch")
        assert(proof.root_hash == match.claims[match.turn_index].computation_hash, "agreed state proof root mismatch")
        assert(descend_left or proof.target_hash == response.turn_left_node, "wrong agreed state")
        hash_tree.verify_slice(proof)
        agreed_state_hash = proof.target_hash
    else
        agreed_state_hash = tournament.initial_state_hash
    end
    local turn_state_hash = descend_left and response.turn_left_node or response.turn_right_node
    local other_state_hash = descend_left and match.other_left_node or match.other_right_node
    local next_state_hashes = {}
    next_state_hashes[match.turn_index] = turn_state_hash
    next_state_hashes[get_other_turn_index(match.turn_index)] = other_state_hash
    return {
        leaf_index = leaf_index,
        agreed_state_hash = agreed_state_hash,
        next_state_hashes = next_state_hashes,
    }
end
-- docs:end validate_seal_response

local function validate_timeout_win_response(children, computation_hash)
    local left = children.computation_hash_left
    local right = children.computation_hash_right
    assert(keccak(left, right) == computation_hash, "wrong children")
end

------------------------------------------------------------
-- Match clocks
--
-- Each claim carries a clock, its remaining allowance in blocks, and the referee runs the two
-- clocks of a match against each other. Expiry is inclusive: a deadline is the first block at
-- which a clock has timed out, so a response must arrive before it.
------------------------------------------------------------

-- docs:begin match_clocks
-- Charges the on-turn claim for blocks beyond the response budget after a valid response.
local function charge_turn_time(tournament, match, start_instant)
    local turn_claim = match.claims[match.turn_index]
    local elapsed = current_time() - start_instant
    turn_claim.allowance = turn_claim.allowance - math.max(elapsed - tournament.dapp_contract.response_budget, 0)
end

-- docs:end match_clocks

-- Requests the waiting claim's response for the timeout-win window, which opens at the on-turn
-- claim's deadline and closes once the match is eliminable.
local function emit_win_match_by_timeout(tournament, match, responder_deadline, eliminable_at)
    local other_turn_index = get_other_turn_index(match.turn_index)
    local other_claim = match.claims[other_turn_index]
    return request_first_valid(
        subscription_hash(tournament.id, other_claim),
        EVENTS.win_match_by_timeout,
        { other_claim.computation_hash },
        function(response, _, received_at)
            assert(received_at >= responder_deadline and received_at < eliminable_at, "timeout win outside its window")
            validate_timeout_win_response(response, other_claim.computation_hash)
            story.report_timeout_win(match)
            return other_turn_index
        end
    )
end

local function emit_eliminate_match(match, eliminable_at)
    return request_first_valid(EVERYONE, EVENTS.eliminate_match, {}, function(_, sender, received_at)
        assert(received_at >= eliminable_at, "early elimination")
        story.report_match_eliminated(match, sender.label)
        return 0
    end)
end

-- Settles a turn whose response did not arrive in time. The waiting claim may win until the
-- match becomes eliminable, then anyone may eliminate it.
-- docs:begin settle_timeout
local function settle_timeout(tournament, match, responder_deadline, eliminable_at)
    local timeout <close> = emit_win_match_by_timeout(tournament, match, responder_deadline, eliminable_at)
    local winner = timeout:wait_at_most(eliminable_at)
    if winner then
        return winner
    end
    local elimination <close> = emit_eliminate_match(match, eliminable_at)
    return elimination:wait_at_most(FOREVER)
end
-- docs:end settle_timeout

-- Settles a uarch match once the walk isolates the divergent leaf. The referee emits the
-- disputed transition to both claims' holders and takes the first answer that verifies
-- against the agreed state hash. The transition out of the agreed state is unique, so any log
-- that verifies reaches the one true next state hash. Returns that hash, or nil when nobody
-- proves a transition.
-- docs:begin settle_uarch_state_hash
local function settle_uarch_state_hash(tournament, match, state_transition_offset, root_hash_before, next_state_hashes)
    local subscriptions = {
        subscription_hash(tournament.id, match.claims[1]),
        subscription_hash(tournament.id, match.claims[2]),
    }
    local start_instant = current_time()
    local deadline_one = start_instant + match.claims[1].allowance
    local deadline_two = start_instant + match.claims[2].allowance
    local proof_deadline = math.min(deadline_one, deadline_two)
    local eliminable_at = math.max(deadline_one, deadline_two)
    local proof <close> = request_first_valid(
        subscriptions,
        EVENTS.prove_state_transition,
        { tournament.epoch_input_offset, tournament.input_period_offset, state_transition_offset },
        function(response, _, received_at)
            assert(received_at < proof_deadline, "late state transition proof")
            return validate_state_transition_response(
                tournament.dapp_contract,
                root_hash_before,
                tournament.epoch_period_offset,
                state_transition_offset,
                response
            )
        end
    )
    local obtained_root_hash = proof:wait_at_most(proof_deadline)
    if not obtained_root_hash then
        wait_until(eliminable_at)
        local elimination <close> = request_first_valid(
            EVERYONE,
            EVENTS.eliminate_match,
            {},
            function(_, _, received_at)
                assert(received_at >= eliminable_at, "early elimination")
                return true
            end
        )
        elimination:wait_at_most(FOREVER)
    end
    story.report_state_transition(tournament, match, state_transition_offset, obtained_root_hash, next_state_hashes)
    return obtained_root_hash
end
-- docs:end settle_uarch_state_hash

-- Forward declaration: settling an mcycle match spawns a uarch tournament, which runs
-- matches, which settle against the machine.
local run_tournament

-- Opens the uarch tournament of an mcycle match over the period its claims part ways on, to
-- the holders of the two claims. Its valid claims are restricted to the two contested final
-- states, as validContestedFinalState requires on chain. Its allowance is the larger clock the
-- mcycle match leaves paused, not a fresh one.
-- docs:begin open_uarch_tournament
local function open_uarch_tournament(
    mcycle_tournament,
    mcycle_match,
    epoch_period_offset,
    agreed_state_hash,
    next_state_hashes
)
    local geometry = mcycle_tournament.dapp_contract.geometry
    local epoch_input_offset, input_period_offset =
        split_epoch_period_offset(geometry.periods_per_input, epoch_period_offset)
    local mcycle_tournament_id = mcycle_tournament.id
    local tournament_id = keccak(mcycle_match.claims[1].computation_hash, mcycle_match.claims[2].computation_hash)
    local start_instant = current_time()
    local allowance = math.max(mcycle_match.claims[1].allowance, mcycle_match.claims[2].allowance)
    local joining_deadline = start_instant + allowance
    local collection <close> = request_all(
        {
            subscription_hash(mcycle_tournament_id, mcycle_match.claims[1]),
            subscription_hash(mcycle_tournament_id, mcycle_match.claims[2]),
        },
        EVENTS.commit_uarch_claim,
        { epoch_input_offset, input_period_offset, next_state_hashes },
        function(response, connection, received_at)
            local claim = validate_claim_response(response, geometry.uarch_height)
            local final = claim.final_state_hash
            assert(final == next_state_hashes[1] or final == next_state_hashes[2], "final state not contested")
            return { claim = claim, connection = connection, received_at = received_at }
        end
    )
    local responses, order = collection:wait_at_most(joining_deadline)
    wait_until(joining_deadline)
    local claims = partition_claims(responses, order, tournament_id, start_instant, allowance)
    local tournament = {
        level = "uarch",
        id = tournament_id,
        height = geometry.uarch_height,
        initial_state_hash = agreed_state_hash,
        dapp_contract = mcycle_tournament.dapp_contract,
        settle_state_hash = settle_uarch_state_hash,
        claims = claims,
        epoch_period_offset = epoch_period_offset,
        epoch_input_offset = epoch_input_offset,
        input_period_offset = input_period_offset,
    }
    story.report_uarch_tournament(tournament, mcycle_match, agreed_state_hash)
    story.report_claims(tournament, responses, order)
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
        local propagation <close> = request_first_valid(
            subscription_hash(mcycle_tournament.id, mcycle_claim),
            EVENTS.propagate_uarch_result, { mcycle_claim.computation_hash },
            function(response, _, received_at)
                assert(received_at < winner_expires_at)
                assert(keccak(response.computation_hash_left, response.computation_hash_right)
                    == mcycle_claim.computation_hash)
                return winner.final_state_hash
            end
        )
        if not propagation:wait_at_most(winner_expires_at) then
            local elimination <close> = request_first_valid(
                EVERYONE, EVENTS.eliminate_uarch_result, {},
                function(_, _, received_at)
                    assert(received_at >= winner_expires_at)
                    return true
                end
            )
            elimination:wait_at_most(FOREVER)
            -- Both mcycle claims are eliminated despite the uarch tournament having a winner.
            -- Report this expiry separately from a uarch tournament that had no winner.
            return nil
        end
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
    epoch_period_offset,
    agreed_state_hash,
    next_state_hashes
)
    local uarch_tournament = open_uarch_tournament(
        mcycle_tournament,
        mcycle_match,
        epoch_period_offset,
        agreed_state_hash,
        next_state_hashes
    )
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
        divergence.leaf_index,
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
        local turn_claim = match.claims[match.turn_index]
        local start_instant = current_time()
        local responder_deadline = start_instant + turn_claim.allowance
        local eliminable_at = responder_deadline + match.claims[get_other_turn_index(match.turn_index)].allowance
        local reveal <close> = request_first_valid(
            subscription_hash(tournament.id, turn_claim),
            EVENTS.reveal_bisection,
            { turn_claim.computation_hash, match.position, match.height, match.other_left_node },
            function(response, _, received_at)
                assert(received_at < responder_deadline, "late bisection")
                return validate_bisection_response(match, response)
            end
        )
        local response = reveal:wait_at_most(responder_deadline)
        if not response then
            return settle_timeout(tournament, match, responder_deadline, eliminable_at)
        end
        charge_turn_time(tournament, match, start_instant)
        advance_bisection(match, response)
        story.report_match_progress(match)
    end
end
-- docs:end reveal_divergence

-- Proves the divergent leaves and the agreed state before them. Returns the sealed
-- divergence, or nil and the winner or elimination if no valid seal arrives in time.
-- docs:begin seal_divergence
local function seal_divergence(tournament, match)
    local turn_claim = match.claims[match.turn_index]
    local start_instant = current_time()
    local responder_deadline = start_instant + turn_claim.allowance
    local eliminable_at = responder_deadline + match.claims[get_other_turn_index(match.turn_index)].allowance
    local seal <close> = request_first_valid(
        subscription_hash(tournament.id, turn_claim),
        EVENTS.seal_divergence,
        { turn_claim.computation_hash, match.position, match.other_left_node },
        function(response, _, received_at)
            assert(received_at < responder_deadline, "late seal")
            return validate_seal_response(tournament, match, response)
        end
    )
    local divergence = seal:wait_at_most(responder_deadline)
    if not divergence then
        return nil, settle_timeout(tournament, match, responder_deadline, eliminable_at)
    end
    charge_turn_time(tournament, match, start_instant)
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
    local completed <close> = run_all(functions)
    completed:wait_at_most(FOREVER)
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
    local surviving_claims = { unmatched_claim } -- unmatched_claim may be nil
    for _, match in ipairs(matches) do
        surviving_claims[#surviving_claims + 1] = match.claims[match.winner] -- match.claims[match.winner] may be nil
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
    local start_instant = current_time()
    local max_allowance = dapp_contract.max_allowance
    local joining_deadline = start_instant + max_allowance
    local collection <close> = request_all(
        dapp_contract.initial_state_hash,
        EVENTS.commit_mcycle_claim,
        {},
        function(response, connection, received_at)
            return {
                claim = validate_claim_response(response, geometry.mcycle_height),
                connection = connection,
                received_at = received_at,
            }
        end
    )
    local responses, order = collection:wait_at_most(joining_deadline)
    wait_until(joining_deadline)
    local claims = partition_claims(responses, order, tournament_id, start_instant, max_allowance)
    local tournament = {
        level = "mcycle",
        id = tournament_id,
        height = geometry.mcycle_height,
        initial_state_hash = dapp_contract.initial_state_hash,
        dapp_contract = dapp_contract,
        settle_state_hash = settle_mcycle_state_hash,
        claims = claims,
    }
    story.report_claims(tournament, responses, order)
    return tournament
end
-- docs:end open_mcycle_tournament

local output_verifier = require("game-output")
local validate_outputs_merkle_root_response = output_verifier.validate_outputs_merkle_root_response
local validate_output_response = output_verifier.validate_output_response

-- Waits on the settled final state hash. It first establishes the outputs Merkle root committed
-- by that state, then repeatedly asks for an output and checks each offer against that root.
-- Offers are validated against the settled hash, so anyone may answer. The player chooses which
-- output to offer. An epoch with no output therefore still settles its outputs root without
-- inventing an output.
-- docs:begin wait_for_outputs
local function wait_for_outputs(final_state_hash)
    local root_proof <close> = request_first_valid(
        EVERYONE,
        EVENTS.prove_outputs_merkle_root,
        { final_state_hash },
        function(response)
            return validate_outputs_merkle_root_response(response, final_state_hash)
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
                    return validate_output_response(response, outputs_merkle_root)
                end
            end
        )
        local output = output_proof:wait_at_most(FOREVER)
        accepted_output_indices[output.output_index] = true
        story.report_output(output)
    end
end
-- docs:end wait_for_outputs

-- Simulate blockchain publication, waiting for each event's handlers before proceeding.
local function run_epoch(dapp_contract, subscribers)
    for index, path in ipairs(dapp_contract.input_paths) do
        notify_all(subscribers, EVENTS.input_added, { index - 1, path })
    end
    notify_all(subscribers, EVENTS.epoch_sealed, { #dapp_contract.inputs })
end

-- Seen from the referee, the whole game is short. It opens the mcycle tournament, reduces the
-- claims it opened with, and, if one survives every match, settles the epoch on its result.
-- The mcycle tournament packs what the reduction needs: the agreed initial state hash,
-- the dapp contract whose inputs verification trusts, and the way its matches settle.
-- Everything hard, the accept loop, the wire, the coroutine scheduling, runs underneath, in
-- the referee server this is handed to.
-- docs:begin run_referee
local function run_referee(dapp_contract)
    local tournament = open_mcycle_tournament(dapp_contract)
    local winner = run_tournament(tournament)
    story.report_winner(winner)
    if winner then
        wait_for_outputs(winner.final_state_hash)
    end
end
-- docs:end run_referee

-- The dispute geometry the contract fixes at deployment. Its one free parameter is the mcycle
-- period, log2 of the mcycles between two samples of an mcycle claim. The remaining values
-- follow from it and the emulator's rollup constants. The referee and players use this same
-- geometry.
-- docs:begin new_geometry
local function new_geometry(log2_mcycles_per_period)
    local mcycle_height = LOG2_MAX_ADVANCE_STATES_PER_EPOCH
        + LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
        - log2_mcycles_per_period
    local uarch_height = log2_mcycles_per_period + LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    assert(mcycle_height < 63 and uarch_height < 63, "claim leaf counts must fit in signed 64-bit integers")
    return {
        log2_mcycles_per_period = log2_mcycles_per_period,
        mcycles_per_period = 1 << log2_mcycles_per_period,
        mcycle_height = mcycle_height,
        uarch_height = uarch_height,
        periods_per_input = 1 << (LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_mcycles_per_period),
    }
end
-- docs:end new_geometry

-- Builds the contract context the referee and players read from the chain.
-- The initial state hash is announced at deployment, and the epoch's inputs are all posted
-- to the blockchain, so the contract holds its own copy of every one, the copy that
-- verification trusts over anything a player commits. The geometry is fixed here too, with
-- the documentation's period of 2^10 mcycles, and so are the clocks. A tournament's allowance
-- is four blocks. A claim's clock is that allowance less the blocks since the tournament
-- opened, and a uarch tournament inherits the remaining mcycle clock, so a claim joining a
-- block after either opening has three blocks at the mcycle level and two at the uarch level,
-- the least that lets it see an event in one block and answer in the next under inclusive
-- expiry. The response budget equals the allowance, so no response is ever charged. Input
-- events carry filenames readable by every player; the referee retains its own bytes for
-- verification.
local function new_dapp_contract(initial_state_hash, input_paths)
    local max_allowance = 4
    return {
        initial_state_hash = initial_state_hash,
        inputs = map(input_paths, fs.read_file),
        input_paths = input_paths,
        geometry = new_geometry(10),
        max_allowance = max_allowance,
        response_budget = max_allowance,
    }
end

-- The role's runner simulates the epoch before starting its tournament referee.
-- Construction binds the deployed dapp contract without creating or running the transport.
local function new_referee(dapp_contract)
    return {
        dapp_contract = dapp_contract,
        run = function(self, referee_server)
            server = referee_server
            local subscribers = accept_subscribers(self.dapp_contract.initial_state_hash)
            run_epoch(self.dapp_contract, subscribers)
            run_referee(self.dapp_contract)
        end,
    }
end

-- =============================================================================
-- Player
-- =============================================================================

------------------------------------------------------------
-- Geometry
--
-- The epoch spans 2^24 inputs of 2^48 mcycles each, and every mcycle expands into 2^20
-- uarch transitions, the same three coordinates as the verification game. The mcycle
-- claim samples the epoch every 2^LOG2_MCYCLES_PER_PERIOD mcycles. The uarch claim expands one mcycle
-- period into its uarch transitions. Each claim is stored bundled: the machine delivers one
-- subtree root per 2^bundle_height leaves, stored at its logical height, and queries
-- below a bundle are answered by opening it.
------------------------------------------------------------

local LOG2_BUNDLE_MCYCLE_COUNT = 4
-- A uarch bundle is one whole mcycle, so a uarch claim stores one hash per mcycle.
local LOG2_BUNDLE_UARCH_CYCLE_COUNT = LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
local LOG2_HASHES_PER_COLLECTION = 8
local LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE = 10 -- assume about 1024 uarch cycles per mcycle
local MAX_MCYCLES_PER_ADVANCE_STATE = 1 << LOG2_MAX_MCYCLES_PER_ADVANCE_STATE
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

-- Check the initial yield through its header registers without reading an output payload.
local function assert_rolling_template(machine)
    assert(
        machine:read_reg("iflags_Y") ~= 0
            and machine:read_reg("htif_tohost_dev") == cartesi.HTIF_DEV_YIELD
            and machine:read_reg("htif_tohost_cmd") == cartesi.HTIF_YIELD_CMD_MANUAL
            and machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED,
        "initial machine is not waiting on an rx-accepted manual yield"
    )
end

-- Returns the yield reason and data.
local function receive_cmio_request(machine)
    local cmd, reason, data = machine:receive_cmio_request()
    assert(cmd == cartesi.HTIF_YIELD_CMD_MANUAL or cmd == cartesi.HTIF_YIELD_CMD_AUTOMATIC, "unexpected yield command")
    return reason, data
end

-- Limits each collection call to the mcycle span of 2^LOG2_HASHES_PER_COLLECTION bundle roots,
-- bounding temporary hash storage. Caps the span at MCYCLE_MAX to avoid shift overflow.
local function mcycle_hashes_collection_chunk_size(log2_period, log2_bundle_mcycle_count)
    local log2_collection_chunk_size = log2_period + log2_bundle_mcycle_count + LOG2_HASHES_PER_COLLECTION
    if log2_collection_chunk_size >= 64 then
        return cartesi.MCYCLE_MAX
    end
    return 1 << log2_collection_chunk_size
end

local function move_machine(machine)
    local moved = cartesi.new()
    machine:swap(moved)
    return moved
end

-- Forks a machine's server. The fork is shut down when the object holding it is closed or
-- collected, so a player leaves no server behind when it exits, even on an error.
local function fork_server(machine)
    local fork = assert(machine:fork_server())
    fork:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    return fork
end

-- Loads an explicit snapshot directory or the content-addressed default into a freshly
-- spawned server, and verifies that the stored machine actually has the requested state hash.
-- The sharing mode defaults to keeping changes in memory. A spawned server shuts down when its
-- handle is closed or collected, including after an error.
local function new_machine(initial_state_hash, directory, sharing)
    local machine <close> = assert(cartesi_jsonrpc.spawn_server("127.0.0.1:0"))
    machine:load(directory or cartesi.tohex(initial_state_hash), nil, sharing)
    assert(machine:get_root_hash() == initial_state_hash, "initial machine snapshot hash mismatch")
    return move_machine(machine)
end

-- Loads a stored machine into this process, sharing every change with its directory, and checks its
-- state hash. Its locks go with the process, so a player that crashes leaves no machine holding them.
local function new_stored_machine(state_hash, directory)
    local machine <close> = cartesi.new()
    machine:load(directory, nil, cartesi.SHARING_ALL)
    assert(machine:get_root_hash() == state_hash, "stored machine hash mismatch")
    return move_machine(machine)
end

-- A machine pair owns its working machine and optional rollback snapshot.
-- Collection state belongs to builders; input execution locals belong to the driver.
local function shallow_move(values)
    local moved = {}
    for name, value in pairs(values) do
        moved[name] = value
    end
    for name in pairs(values) do
        values[name] = nil
    end
    return moved
end

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

function machine_pair_methods:snapshot()
    assert(not self.backup_machine, "machine already has a snapshot")
    self.backup_machine = fork_server(self.machine)
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

-- Takes over a stored machine that clone_stored just created, which removes a clone that fails
-- partway itself, and removes it if an error closes the owner before move() hands its directory over.
local temporary_stored_machine_meta = { __index = {} }
function temporary_stored_machine_meta.__index:close()
    if self.directory then
        cartesi.machine:remove_stored(self.directory)
        self.directory = nil
    end
end
temporary_stored_machine_meta.__close = temporary_stored_machine_meta.__index.close

function temporary_stored_machine_meta.__index:move()
    local directory = self.directory
    self.directory = nil
    return directory
end

local function new_temporary_stored_machine(directory)
    return setmetatable({ directory = directory }, temporary_stored_machine_meta)
end

-- A loaded directory is locked, so its machine is destroyed around the clone and reloaded after.
-- Returns the clone's directory once it is synced and the machine is reloaded.
local function clone_loaded_directory(machine, directory, clone_directory)
    machine:destroy()
    machine:clone_stored(directory, clone_directory)
    local clone <close> = new_temporary_stored_machine(clone_directory)
    machine:sync_stored(clone_directory)
    machine:load(directory, nil, cartesi.SHARING_ALL)
    return clone:move()
end

-- Removes a stored machine that a crash or an earlier pair may have left, possibly incomplete, which
-- remove_stored may not recognize.
local function remove_leftover_stored_machine(directory)
    if pcall(cartesi.machine.remove_stored, cartesi.machine, directory) then
        return
    end
    for _, name in ipairs(fs.list_directory(directory)) do
        fs.remove_file(directory .. "/" .. name)
    end
    fs.remove_directory(directory)
end

-- A stored pair runs its machine directly on the backing stores of its directory, loaded with
-- SHARING_ALL, and snapshots by cloning that directory, like the command-line utility's
-- --revert-mode=stored. Nothing is removed eagerly. Committing only syncs, and the next snapshot
-- replaces the committed one. Closing only releases the machine, so an error leaves the disk as a
-- crash would. Leftover scratch is replaced when next created, and the player's state decides on
-- reopen which directories matter.
local stored_machine_pair_meta = { __index = setmetatable({}, { __index = machine_pair_methods }) }
local stored_machine_pair_methods = stored_machine_pair_meta.__index
function stored_machine_pair_methods:close()
    if self.machine then
        self.machine:destroy()
        self.machine = nil
    end
end
stored_machine_pair_meta.__close = stored_machine_pair_methods.close

function stored_machine_pair_methods:move()
    return setmetatable(shallow_move(self), stored_machine_pair_meta)
end

function stored_machine_pair_methods:snapshot()
    if self.backup_directory and self.backup_committed then
        self.machine:remove_stored(self.backup_directory)
        self.backup_directory = nil
    end
    assert(not self.backup_directory, "machine already has a snapshot")
    self.backup_directory = clone_loaded_directory(self.machine, self.directory, self.directory .. ".revert")
    self.backup_committed = false
end

function stored_machine_pair_methods:commit()
    self.machine:sync_stored(self.directory)
    self.backup_committed = true
end

function stored_machine_pair_methods:revert()
    local backup_directory = assert(self.backup_directory, "no snapshot to revert to")
    assert(not self.backup_committed, "cannot revert a committed input")
    local machine = self.machine
    machine:destroy()
    machine:remove_stored(self.directory)
    machine:rename_stored(backup_directory, self.directory)
    self.backup_directory = nil
    machine:load(self.directory, nil, cartesi.SHARING_ALL)
    assert(machine:get_root_hash() == self.revert_root_hash, "rollback did not restore the input boundary")
end

local function new_stored_machine_pair(machine, directory)
    local pair <close> = setmetatable({ machine = machine, directory = directory }, stored_machine_pair_meta)
    pair.revert_root_hash = machine:get_root_hash()
    return pair:move()
end

-- An entry is the machine at an input base, before delivery, indexed by the input. The first
-- entry is the initial machine at input zero and is always retained. The epoch run considers
-- every later input base, and the cache retains a bounded set of forks. When the cache is full,
-- a new entry replaces the first one closer than the input gap to its predecessor. If there
-- is none, the gap doubles, so entries spread across the epoch as it grows.
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
        entries = { { epoch_input_offset = 0, machine = initial_machine } },
    }, machine_cache_meta)
    assert(math.type(capacity) == "integer" and capacity > 0, "invalid machine cache capacity")
    assert(math.type(input_gap) == "integer" and input_gap > 0, "invalid machine cache input gap")
    return cache:move()
end

function machine_cache_methods:close()
    for _, entry in ipairs(self.entries or {}) do
        entry.machine:shutdown_server()
    end
    self.entries = nil
end
machine_cache_meta.__close = machine_cache_methods.close

function machine_cache_methods:move()
    return setmetatable(shallow_move(self), machine_cache_meta)
end

-- An entry holds a fork of the machine at its input boundary.
function machine_cache_methods:new_entry(epoch_input_offset, machine) -- luacheck: ignore 212 self
    return { epoch_input_offset = epoch_input_offset, machine = fork_server(machine) }
end

function machine_cache_methods:remove_entry(entry) -- luacheck: ignore 212 self
    entry.machine:shutdown_server()
end

function machine_cache_methods:new_machine_pair_from_entry(entry) -- luacheck: ignore 212 self
    return new_machine_pair(fork_server(entry.machine))
end

function machine_cache_methods:consider(epoch_input_offset, machine)
    local entries = assert(self.entries, "machine cache is closed or moved")
    assert(epoch_input_offset > self.last_epoch_input_offset, "cache entries are not ordered")
    self.last_epoch_input_offset = epoch_input_offset
    if epoch_input_offset - entries[#entries].epoch_input_offset < self.input_gap then
        return
    end
    local replace_index
    if #entries == self.capacity then
        replace_index = self.replace_cursor
        while replace_index <= #entries do
            local previous = entries[replace_index - 1].epoch_input_offset
            if entries[replace_index].epoch_input_offset - previous < self.input_gap then
                break
            end
            replace_index = replace_index + 1
        end
        if replace_index > #entries then
            self.input_gap = self.input_gap << 1
            self.replace_cursor = 2
            return
        end
    end
    entries[#entries + 1] = self:new_entry(epoch_input_offset, machine)
    if replace_index then
        self:remove_entry(table.remove(entries, replace_index))
        self.replace_cursor = replace_index
    end
end

local function find_nearest_entry(cache, epoch_input_offset)
    local entries = assert(cache.entries, "machine cache is closed or moved")
    assert(epoch_input_offset >= 0, "invalid epoch input offset")
    local nearest
    for _, entry in ipairs(entries) do
        if entry.epoch_input_offset > epoch_input_offset then
            break
        end
        nearest = entry
    end
    return nearest
end

-- Fork the nearest retained input boundary not past the requested offset.
function machine_cache_methods:nearest_not_past_epoch_input_offset(epoch_input_offset)
    local entry = find_nearest_entry(self, epoch_input_offset)
    local pair <close> = self:new_machine_pair_from_entry(entry)
    return pair:move(), entry.epoch_input_offset
end

-- Take ownership of the received pair and keep it unless a retained entry is strictly nearer.
function machine_cache_methods:nearer_not_past_epoch_input_offset_or(
    pair,
    pair_epoch_input_offset,
    epoch_input_offset_end
)
    local received_pair <close> = assert(pair, "missing machine pair")
    local entry = find_nearest_entry(self, epoch_input_offset_end)
    assert(pair_epoch_input_offset <= epoch_input_offset_end, "pair is past desired input")
    if entry.epoch_input_offset <= pair_epoch_input_offset then
        return received_pair:move(), pair_epoch_input_offset
    end
    local advancing_pair <close>, cached_epoch_input_offset =
        self:nearest_not_past_epoch_input_offset(epoch_input_offset_end)
    received_pair:close()
    return advancing_pair:move(), cached_epoch_input_offset
end

-- Writes a file through a temporary file in the same directory, synced before the rename. The
-- caller syncs the directory.
local function write_durable_file(contents, path)
    local directory, name = path:match("^(.*)/([^/]*)$")
    local temporary <close> = fs.new_temporary_file(directory, name .. ".tmp.")
    temporary.file:write(contents)
    fs.sync_file(temporary.file)
    temporary:rename(path)
end

-- A stored cache keeps its entries as stored machines under entries/ in the epoch directory, next
-- to the epoch machine's own directory. A temporary pair runs on a clone of its entry in pair/,
-- since a player has at most one at a time, replacing what an earlier pair left there. Closing the
-- cache leaves the entries on disk. An evicted entry is removed only by remove_evicted, once the
-- player's state no longer lists it.
local stored_machine_cache_meta = { __index = setmetatable({}, { __index = machine_cache_methods }) }
local stored_machine_cache_methods = stored_machine_cache_meta.__index

function stored_machine_cache_methods:close()
    self.entries = nil
end
stored_machine_cache_meta.__close = stored_machine_cache_methods.close

function stored_machine_cache_methods:move()
    return setmetatable(shallow_move(self), stored_machine_cache_meta)
end

function stored_machine_cache_methods:new_entry(epoch_input_offset, machine)
    local directory = clone_loaded_directory(
        machine,
        self.machine_directory,
        self.epoch_directory .. "/entries/" .. epoch_input_offset
    )
    return { epoch_input_offset = epoch_input_offset, directory = directory, root_hash = machine:get_root_hash() }
end

function stored_machine_cache_methods:remove_entry(entry)
    self.evicted[#self.evicted + 1] = entry.directory
end

function stored_machine_cache_methods:remove_evicted()
    for _, directory in ipairs(self.evicted) do
        cartesi.machine:remove_stored(directory)
    end
    self.evicted = {}
end

function stored_machine_cache_methods:new_machine_pair_from_entry(entry)
    local directory = self.epoch_directory .. "/pair"
    for _, leftover in ipairs({ directory, directory .. ".revert" }) do
        if fs.exists(leftover) then
            remove_leftover_stored_machine(leftover)
        end
    end
    cartesi.machine:clone_stored(entry.directory, directory)
    local clone <close> = new_temporary_stored_machine(directory)
    local machine = new_stored_machine(entry.root_hash, directory)
    return new_stored_machine_pair(machine, clone:move())
end

-- The epoch machine is loaded from machine_directory. Entry zero is cloned from it.
local function new_stored_machine_cache(epoch_directory, machine_directory, machine)
    local cache <close> = setmetatable({
        capacity = DEFAULT_MACHINE_CACHE_CAPACITY,
        input_gap = DEFAULT_MACHINE_CACHE_INPUT_GAP,
        replace_cursor = 2,
        last_epoch_input_offset = 0,
        epoch_directory = epoch_directory,
        machine_directory = machine_directory,
        entries = {},
        evicted = {},
    }, stored_machine_cache_meta)
    cache.entries[1] = cache:new_entry(0, machine)
    return cache:move()
end

-- Reopens a cache stored by stored_machine_cache_methods:store, with its policy and entries.
local function load_stored_machine_cache(epoch_directory, machine_directory, path)
    local stored = cartesi.fromjson(fs.read_file(path))
    local cache <close> = setmetatable({
        capacity = stored.capacity,
        input_gap = stored.input_gap,
        replace_cursor = stored.replace_cursor,
        last_epoch_input_offset = stored.last_epoch_input_offset,
        epoch_directory = epoch_directory,
        machine_directory = machine_directory,
        entries = {},
        evicted = {},
    }, stored_machine_cache_meta)
    assert(math.type(cache.capacity) == "integer" and cache.capacity > 0, "invalid machine cache capacity")
    assert(math.type(cache.input_gap) == "integer" and cache.input_gap > 0, "invalid machine cache input gap")
    assert(math.type(cache.replace_cursor) == "integer", "invalid machine cache replace cursor")
    assert(math.type(cache.last_epoch_input_offset) == "integer", "invalid machine cache input offset")
    assert(#stored.entries > 0, "machine cache has no entries")
    for i, entry in ipairs(stored.entries) do
        cache.entries[i] = {
            epoch_input_offset = entry.epoch_input_offset,
            directory = epoch_directory .. "/entries/" .. entry.epoch_input_offset,
            root_hash = cartesi.fromhex(entry.root_hash),
        }
    end
    return cache:move()
end

-- Stores the cache's policy and entries in a file, for load_stored_machine_cache, and syncs its
-- directory.
function stored_machine_cache_methods:store(path)
    local entries = {}
    for i, entry in ipairs(self.entries) do
        entries[i] = { epoch_input_offset = entry.epoch_input_offset, root_hash = cartesi.tohex(entry.root_hash) }
    end
    write_durable_file(cartesi.tojson({
        capacity = self.capacity,
        input_gap = self.input_gap,
        replace_cursor = self.replace_cursor,
        last_epoch_input_offset = self.last_epoch_input_offset,
        entries = entries,
    }, 2) .. "\n", path)
    fs.sync_directory(path:match("^(.*)/[^/]*$"))
end

-- Advances through a builder's run(machine, mcycle_end) method until a fixed point or the target mcycle,
-- returning the break reason. A null builder delegates plain replay to the supplied machine.
-- Automatic yields are read from the machine and passed to the optional callback; without one,
-- they are ignored. A terminal manual yield remains unread for the caller to handle.
local function run_to_stop(builder, machine, mcycle_end, on_yield_automatic)
    while true do
        local break_reason = builder:run(machine, mcycle_end)
        if is_at_fixed_point(break_reason) or is_target_mcycle(break_reason) then
            return break_reason
        elseif is_yielded_automatic(break_reason) then
            if on_yield_automatic then
                local yield_reason, data = receive_cmio_request(machine)
                on_yield_automatic(yield_reason, data)
            end
        end
        -- Other reasons (soft yields or console breaks) just keep going.
    end
end

-- Retain only accepted outputs and check their cumulative root. Pending outputs from other
-- outcomes are discarded when the input driver returns.
local function flush_pending_outputs(pending_outputs, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
    if not outputs or not is_rx_accepted(yield_reason) then
        return
    end
    for _, output_data in ipairs(pending_outputs) do
        outputs[#outputs + 1] = output_data
        hash_tree.frontier_push_back(outputs_frontier, keccak(output_data))
    end
    assert(hash_tree.frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")
end

-- Delivers a posted input, recording the root a rejection reverts to. The machine and
-- logged transition both leave inapplicable deliveries unchanged.
local function load_cmio_input(machine, input_data, revert_root_hash)
    if input_data ~= nil then
        machine:send_cmio_response(HTIF_YIELD_REASON_ADVANCE_STATE, input_data, revert_root_hash)
    end
end

-- Input preparation is shared by mcycle replay, uarch replay, and native bundle
-- collection. Each invocation begins at the input boundary.
local function begin_input(builder, pair, epoch_input_offset, input_data)
    local machine = pair.machine
    local input_mcycle_base = machine:read_reg("mcycle")
    builder:begin_input(machine, epoch_input_offset, input_mcycle_base)
    pair:snapshot()
    load_cmio_input(machine, input_data, pair.revert_root_hash)
    return input_mcycle_base
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
-- well. Each completed input offers its final machine to a bounded cache as the next input's
-- virgin boundary. Later re-runs start from the closest input boundary its policy retained.
------------------------------------------------------------

-- Plain replay has the same input lifecycle as a sampled run.
local function noop() end
local function new_null_computation_hash_builder()
    return {
        begin_epoch = noop,
        begin_input = noop,
        run = function(_, machine, mcycle_end)
            return machine:run(mcycle_end)
        end,
        end_input = noop,
        end_epoch = noop,
    }
end

local function mcycle_computation_hash_push_collected(builder, collected)
    local count = #collected.hashes
    local at_fixed_point = is_at_fixed_point(collected.break_reason)
    if at_fixed_point then
        -- The last root describes the fixed-point repetition, not additional coverage.
        builder.pad_bundle = collected.hashes[count]
        count = count - 1
    end
    assert(
        count <= builder.max_bundles_per_input - builder.input_bundle_count,
        "mcycle collection exceeds the input's bundle capacity"
    )
    hash_tree.frontier_forest_append(builder.frontier, collected.hashes, 1, count + 1, builder.bundle_height)
    builder.input_bundle_count = builder.input_bundle_count + count
    if at_fixed_point then
        local pad_count = builder.max_bundles_per_input - builder.input_bundle_count
        hash_tree.frontier_forest_pad_back(builder.frontier, builder.pad_bundle, pad_count, builder.bundle_height)
        builder.input_bundle_count = builder.max_bundles_per_input
    end
end

local function mcycle_computation_hash_begin_epoch(builder, machine)
    builder.frontier = hash_tree.frontier_forest(builder.height, "keccak256")
    builder.input_bundle_count = 0
    local collected =
        machine:collect_mcycle_root_hashes(machine:read_reg("mcycle"), builder.log2_period, 0, builder.bundle_height)
    assert(is_at_fixed_point(collected.break_reason), "mcycle computation hash started outside a fixed point")
    builder.pad_bundle = collected.hashes[#collected.hashes]
end

local function mcycle_computation_hash_begin_input(builder, _, epoch_input_offset)
    builder.epoch_input_offset = epoch_input_offset
    assert(
        hash_tree.frontier_forest_get_leaf_count(builder.frontier) == epoch_input_offset * builder.periods_per_input,
        "mcycle computation hash input is out of order"
    )
    builder.input_bundle_count = 0
    builder.mcycle_phase = 0
    builder.partial_bundle = nil
end

local function mcycle_computation_hash_run(builder, machine, mcycle_end)
    local collected = { mcycle_phase = builder.mcycle_phase, partial_bundle = builder.partial_bundle }
    local chunk_end = machine:read_reg("mcycle")
    repeat
        chunk_end = usaturating_add(chunk_end, builder.collection_chunk_size, mcycle_end)
        collected = machine:collect_mcycle_root_hashes(
            chunk_end,
            builder.log2_period,
            collected.mcycle_phase,
            builder.bundle_height,
            collected.partial_bundle
        )
        mcycle_computation_hash_push_collected(builder, collected)
    until not is_target_mcycle(collected.break_reason) or chunk_end == mcycle_end
    builder.mcycle_phase = collected.mcycle_phase
    builder.partial_bundle = collected.partial_bundle
    return collected.break_reason
end

local function mcycle_computation_hash_end_input(builder)
    assert(builder.input_bundle_count == builder.max_bundles_per_input, "mcycle computation hash input is incomplete")
    builder.input_bundle_count = 0
end

local function mcycle_computation_hash_end_epoch(builder)
    assert(builder.input_bundle_count == 0, "mcycle computation hash input was not closed")
    hash_tree.frontier_forest_pad_back(builder.frontier, builder.pad_bundle, nil, builder.bundle_height)
    return builder.frontier
end

-- Collect the full epoch as roots of bundles of 2^LOG2_BUNDLE_MCYCLE_COUNT period samples.
-- Per-input counts measure bundles at bundle_height.
-- The forest owns total coverage.
local function new_mcycle_computation_hash_builder(log2_mcycles_per_period)
    local log2_periods_per_input = LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_mcycles_per_period
    local height = LOG2_MAX_ADVANCE_STATES_PER_EPOCH + log2_periods_per_input
    return {
        periods_per_input = 1 << log2_periods_per_input,
        height = height,
        bundle_height = LOG2_BUNDLE_MCYCLE_COUNT,
        log2_period = log2_mcycles_per_period,
        collection_chunk_size = mcycle_hashes_collection_chunk_size(log2_mcycles_per_period, LOG2_BUNDLE_MCYCLE_COUNT),
        max_bundles_per_input = (1 << log2_periods_per_input) >> LOG2_BUNDLE_MCYCLE_COUNT,
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

-- Chooses an mcycle span targeting about 2^LOG2_HASHES_PER_COLLECTION returned hashes.
-- Each mcycle contributes an estimated number of execution bundles plus the all-halted
-- and reset-ending bundles. Always collects at least one mcycle.
local function uarch_hashes_collection_chunk_size(log2_bundle_uarch_cycle_count)
    local cycle_bundle_count = log2_bundle_uarch_cycle_count < LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE
            and (1 << (LOG2_ESTIMATED_UARCH_CYCLES_PER_MCYCLE - log2_bundle_uarch_cycle_count))
        or 1
    return math.max(1, (1 << LOG2_HASHES_PER_COLLECTION) // (cycle_bundle_count + 2))
end

-- Append execution bundles, halt repetitions, and the reset-ending bundle for one mcycle.
local function uarch_computation_hash_push_mcycle(builder, frontier, hashes, mcycle_hashes_begin, mcycle_hashes_end)
    local halt_hash = hashes[mcycle_hashes_end - 2]
    local reset_hash = hashes[mcycle_hashes_end - 1]
    local height = LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - builder.bundle_height
    local bundles_per_mcycle = 1 << height
    local transient_bundle_count = mcycle_hashes_end - mcycle_hashes_begin - 2
    hash_tree.frontier_forest_append(
        frontier,
        hashes,
        mcycle_hashes_begin,
        mcycle_hashes_end - 2,
        builder.bundle_height
    )
    hash_tree.frontier_forest_pad_back(
        frontier,
        halt_hash,
        bundles_per_mcycle - 1 - transient_bundle_count,
        builder.bundle_height
    )
    hash_tree.frontier_forest_push_back(frontier, reset_hash, builder.bundle_height)
end

-- Append the ordinary mcycle groups, then repeat the final group at a fixed point.
-- Retain its forest so repetitions remain queryable below their roots during a dispute.
local function uarch_computation_hash_push_collected(builder, collected)
    local offsets = collected.mcycle_hash_offsets
    local available = #offsets - 1
    local log2_cycles = LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local remaining = builder.mcycles_per_period - builder.mcycle_count
    local count = available
    local at_fixed_point = is_at_fixed_point(collected.break_reason)
    if at_fixed_point then
        count = count - 1
    end
    assert(count <= remaining, "uarch collection exceeds the claim's mcycle capacity")
    for i = 1, count do
        uarch_computation_hash_push_mcycle(builder, builder.frontier, collected.hashes, offsets[i], offsets[i + 1])
    end
    builder.mcycle_count = builder.mcycle_count + count
    if not at_fixed_point or builder.mcycle_count == builder.mcycles_per_period then
        return
    end
    local pad_frontier = hash_tree.frontier_forest(log2_cycles, "keccak256")
    uarch_computation_hash_push_mcycle(
        builder,
        pad_frontier,
        collected.hashes,
        offsets[available],
        offsets[available + 1]
    )
    hash_tree.frontier_forest_pad_back(builder.frontier, pad_frontier)
    builder.mcycle_count = builder.mcycles_per_period
end

local function uarch_computation_hash_begin_input(builder, machine, epoch_input_offset, input_mcycle_base)
    builder.epoch_input_offset = epoch_input_offset
    builder.input_mcycle_base = input_mcycle_base
    local collected = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
    builder.revert_uarch_tail = collected.hashes
    builder.collection_mcycle_begin = usaturating_add(
        builder.input_mcycle_base,
        combine_input_mcycle_offset(builder.mcycles_per_period, builder.input_period_offset, 0)
    )
    builder.collection_mcycle_end = usaturating_add(
        builder.collection_mcycle_begin,
        builder.mcycles_per_period,
        usaturating_add(builder.input_mcycle_base, MAX_MCYCLES_PER_ADVANCE_STATE)
    )
end

-- Keep plain replay here so it shares input preparation and rejection handling with collection.
local function uarch_computation_hash_run(builder, machine, mcycle_end)
    mcycle_end = umin(mcycle_end, builder.collection_mcycle_end)
    local chunk_end = machine:read_reg("mcycle")
    if math.ult(chunk_end, builder.collection_mcycle_begin) then
        local wanted_mcycle = umin(mcycle_end, builder.collection_mcycle_begin)
        local break_reason = machine:run(wanted_mcycle)
        if not is_target_mcycle(break_reason) or wanted_mcycle ~= builder.collection_mcycle_begin then
            return break_reason
        end
        chunk_end = builder.collection_mcycle_begin
    end
    local collected
    repeat
        chunk_end = usaturating_add(chunk_end, builder.collection_chunk_size, mcycle_end)
        collected = machine:collect_uarch_cycle_root_hashes(chunk_end, builder.bundle_height, builder.revert_uarch_tail)
        builder:push_collected(collected)
    until not is_target_mcycle(collected.break_reason) or chunk_end == mcycle_end
    return collected.break_reason
end

local function uarch_computation_hash_end_input(builder, machine)
    if builder.mcycle_count < builder.mcycles_per_period then
        -- An input stopped before the selected period contributes its fixed-point history.
        -- Rejection has already restored the pre-delivery boundary.
        builder:push_collected(machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, builder.bundle_height))
    end
    assert(builder.mcycle_count == builder.mcycles_per_period, "uarch computation hash is incomplete")
end

local function uarch_computation_hash_begin_epoch(builder)
    builder.frontier = hash_tree.frontier_forest(builder.height, "keccak256")
    builder.mcycle_count = 0
end

-- Before delivery at the selected input's virgin boundary,
-- begin_input saves its uarch tail for rejection; run replays to the selected period and
-- collects one root per mcycle, its bundle.
-- A fixed point before the selected period supplies its history without reaching the target.
local function new_uarch_cycle_computation_hash_builder(log2_mcycles_per_period, epoch_period_offset)
    local periods_per_input = 1 << (LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_mcycles_per_period)
    local _, input_period_offset = split_epoch_period_offset(periods_per_input, epoch_period_offset)
    local height = log2_mcycles_per_period + LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    return {
        mcycles_per_period = 1 << log2_mcycles_per_period,
        height = height,
        input_period_offset = input_period_offset,
        bundle_height = LOG2_BUNDLE_UARCH_CYCLE_COUNT,
        collection_chunk_size = uarch_hashes_collection_chunk_size(LOG2_BUNDLE_UARCH_CYCLE_COUNT),
        begin_epoch = uarch_computation_hash_begin_epoch,
        begin_input = uarch_computation_hash_begin_input,
        run = uarch_computation_hash_run,
        push_collected = uarch_computation_hash_push_collected,
        end_input = uarch_computation_hash_end_input,
        end_epoch = function(self)
            return self.frontier
        end,
    }
end

--------------------------------------------------------------------------------
-- Claim trees
--
-- A claim commits to 2^height leaves. The forest stores bundle roots at their logical
-- heights. Opening a bundle reconstructs its individual state hashes and expands its
-- opaque leaf after verifying the root. Implicit repetitions share the expanded subtree.
--------------------------------------------------------------------------------

local tree_meta = { __index = {} }

-- Called only after a forest query reports an opaque path at a valid position.
local function open_bundle(tree, position)
    local bundle_index = position >> tree.bundle_height
    local bundle = tree:collect_bundle(bundle_index)
    hash_tree.frontier_forest_expand_leaf(tree.forest, bundle_index << tree.bundle_height, bundle)
end

-- Node hash queries open their bundle only when its contents are needed.
-- docs:begin get_tree_node_hash
function tree_meta.__index:get_node_hash(position, height)
    local hash = hash_tree.frontier_forest_get_node_hash(self.forest, position, height)
    if not hash then
        open_bundle(self, position)
        hash = assert(hash_tree.frontier_forest_get_node_hash(self.forest, position, height))
    end
    return hash
end
-- docs:end get_tree_node_hash

function tree_meta.__index:get_root_hash()
    return hash_tree.frontier_forest_get_root_hash(self.forest)
end

-- A proof query opens its bundle only when the sibling path reaches an opaque hash.
-- The forest authenticates the reconstructed subtree before installing it. Subsequent
-- queries reuse that subtree, including its occurrences in implicit padding.
-- docs:begin get_proof
function tree_meta.__index:get_proof(position, height)
    height = height or 0
    local siblings = hash_tree.frontier_forest_get_siblings(self.forest, position, height)
    if not siblings then
        open_bundle(self, position)
        siblings = assert(hash_tree.frontier_forest_get_siblings(self.forest, position, height))
    end
    return {
        target_address = position,
        log2_target_size = height,
        target_hash = self:get_node_hash(position, height),
        log2_root_size = self.height,
        root_hash = self:get_root_hash(),
        sibling_hashes = siblings,
    }
end
-- docs:end get_proof

-- The two child hashes, opening a bundle only if a node query needs it.
function tree_meta.__index:get_child_hashes(position, height)
    local child_height = height - 1
    return self:get_node_hash(position, child_height), self:get_node_hash(position + (1 << child_height), child_height)
end

-- A claim tree of 2^height leaves, with collect_bundle reconstructing one bundle on demand.
local function new_tree(height, bundle_height, forest, collect_bundle)
    assert(forest.height == height, "the forest does not match the claim height")
    return setmetatable({
        height = height,
        bundle_height = bundle_height,
        forest = forest,
        collect_bundle = collect_bundle,
    }, tree_meta)
end

------------------------------------------------------------
-- Event responses
--
-- The handlers below produce responses to events emitted by the referee. A player follows one
-- claim lineage: its mcycle claim, and, while that claim's match is suspended in a uarch
-- tournament, the uarch claim it committed there. Computation requests go to holders
-- of the relevant claim. Eliminate instructions need no machine and go to every player.
------------------------------------------------------------

-- Forward declarations, since the epoch directory's functions follow the player.
local store_input, commit_epoch_state, seal_epoch_state, store_uarch_claim, store_checkpoint
local get_input_path, get_output_path, get_outputs_log_path

local event_handler = {}

function event_handler.win_match_by_timeout(self, computation_hash)
    local tree = self.trees[computation_hash]
    local left, right = tree:get_child_hashes(0, tree.height)
    return { computation_hash_left = left, computation_hash_right = right }
end

-- Eliminating a match needs no payload.
function event_handler.eliminate_match(self) -- luacheck: ignore 212 self
    return "nothing"
end

-- A claim: the computation hash's two children and the standard proof of its final state,
-- the last leaf. The proof query opens the last stored bundle if needed.
local function new_claim(tree)
    local final_leaf_index = (1 << tree.height) - 1
    local computation_hash_left, computation_hash_right = tree:get_child_hashes(0, tree.height)
    local final_state_hash_proof = tree:get_proof(final_leaf_index)
    return {
        computation_hash_left = computation_hash_left,
        computation_hash_right = computation_hash_right,
        final_state_hash_proof = final_state_hash_proof,
    }
end

-- The player's opening mcycle claim.
function event_handler.commit_mcycle_claim(self)
    local tree = self:new_mcycle_tree()
    self.trees[tree:get_root_hash()] = tree
    return new_claim(tree)
end

-- Reveals the nodes the referee needs for one bisection advance: the claim's node at
-- (position, height), and the children of the node the walk descends into. Either node can
-- cross into a stored bundle here because the claims alternate turns; crossing reconstructs
-- and authenticates that complete bundle before the walk continues through it.
-- docs:begin reveal_bisection
function event_handler.reveal_bisection(self, computation_hash, position, height, other_left_node)
    local tree = self.trees[computation_hash]
    local turn_left_node, turn_right_node = tree:get_child_hashes(position, height)
    local descend_left = turn_left_node ~= other_left_node
    local child_position = descend_left and position or position + (1 << (height - 1))
    local turn_next_left_node, turn_next_right_node = tree:get_child_hashes(child_position, height - 1)
    return {
        turn_left_node = turn_left_node,
        turn_right_node = turn_right_node,
        turn_next_left_node = turn_next_left_node,
        turn_next_right_node = turn_next_right_node,
    }
end
-- docs:end reveal_bisection

-- Seals the leftmost divergence: exposes the final leaves and proves the agreed state
-- immediately before them, except at leaf zero where the referee already knows that state.
-- At the first leaf of a bundle, the proof explicitly opens the preceding bundle too.
function event_handler.seal_divergence(self, computation_hash, position, other_left_node)
    local tree = self.trees[computation_hash]
    local turn_left_node, turn_right_node = tree:get_child_hashes(position, 1)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= other_left_node
    local leaf_index = position + (descend_left and 0 or 1)
    if leaf_index ~= 0 then
        local agreed_leaf_index = leaf_index - 1
        response.agreed_state_hash_proof = tree:get_proof(agreed_leaf_index)
        assert(
            descend_left or response.agreed_state_hash_proof.target_hash == turn_left_node,
            "right divergence has the wrong agreed state"
        )
    end
    return response
end

-- Joins the uarch tournament over one mcycle period that the player's mcycle claim is
-- disputed in, with a uarch claim whose final state must be one of the two contested values.
-- The player stores the uarch tree by its computation hash alongside its earlier claims.
-- The parent match is suspended until the uarch tournament ends. The epoch input offset
-- and input period offset are zero-based, as the referee counts them. The referee checks
-- that the submitted final state matches one of the contested values.
function event_handler.commit_uarch_claim(self, epoch_input_offset, input_period_offset)
    -- A restarted bridge may deliver this event again for a claim a reopened player already stored.
    for _, claim in ipairs(self.uarch_claims) do
        if claim.epoch_input_offset == epoch_input_offset and claim.input_period_offset == input_period_offset then
            return new_claim(claim.tree)
        end
    end
    local tree = self:new_uarch_tree(epoch_input_offset, input_period_offset)
    local claim = { epoch_input_offset = epoch_input_offset, input_period_offset = input_period_offset, tree = tree }
    self.uarch_claims[#self.uarch_claims + 1] = claim
    if self.epoch_directory then
        store_uarch_claim(self, claim)
    end
    self.trees[tree:get_root_hash()] = tree
    return new_claim(tree)
end

-- The disputed transition's access logs, produced by positioning a fresh fork at the
-- transition and logging it, whatever claim is under dispute. The transition out of an
-- input boundary includes the input, when the epoch has one, before the first uarch step.
-- The transition closing an instruction executes one more step, by then a fixed point, and
-- the reset. Every other transition is an ordinary uarch step.
-- docs:begin prove_state_transition
function event_handler.prove_state_transition(self, epoch_input_offset, input_period_offset, state_transition_offset)
    local period_mcycle_offset, uarch_cycle = split_state_transition_offset(state_transition_offset)
    local pair <close> = self:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local machine = pair.machine
    local input_data = self:read_input(epoch_input_offset)
    if state_transition_offset == 0 and input_period_offset == 0 and input_data then
        -- Logging never fails. A machine that is not waiting for the input logs the no-op delivery.
        local send_cmio_log =
            machine:log_send_cmio_response(HTIF_YIELD_REASON_ADVANCE_STATE, input_data, pair.revert_root_hash)
        return { send_cmio_log = send_cmio_log, step_log = machine:log_step_uarch() }
    end
    local builder = self:new_null_computation_hash_builder()
    local input_mcycle_offset =
        combine_input_mcycle_offset(self.geometry.mcycles_per_period, input_period_offset, period_mcycle_offset)
    self:run_to_input_mcycle_offset(builder, pair, epoch_input_offset, input_data, input_mcycle_offset)
    self:run_to_uarch_cycle(builder, pair, epoch_input_offset, input_data, input_mcycle_offset, uarch_cycle)
    if uarch_cycle == UARCH_CYCLE_MAX then
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

-- Proves that the settled final state is yielded manually with RX_ACCEPTED and authenticates
-- the word whose data is the outputs Merkle root.
-- docs:begin prove_outputs_merkle_root
local function get_outputs_merkle_root_proof(machine)
    local iflags_y_data, iflags_y_proof = get_machine_leaf(machine, IFLAGS_Y_ADDRESS)
    local htif_tohost_data, htif_tohost_proof = get_machine_leaf(machine, HTIF_TOHOST_ADDRESS)
    local tx_buffer_data, tx_buffer_proof = get_machine_leaf(machine, CMIO_TX_BUFFER_ADDRESS)
    return {
        iflags_y_data = iflags_y_data,
        iflags_y_proof = iflags_y_proof,
        htif_tohost_data = htif_tohost_data,
        htif_tohost_proof = htif_tohost_proof,
        tx_buffer_data = tx_buffer_data,
        tx_buffer_proof = tx_buffer_proof,
    }
end

function event_handler.prove_outputs_merkle_root(self)
    return self.outputs_merkle_root_proof
end
-- docs:end prove_outputs_merkle_root

-- Offer the last output for this demonstration. The referee supplies no index.
function event_handler.prove_output(self)
    return self:prove_output(hash_tree.frontier_get_leaf_count(self.outputs_frontier) - 1)
end

local player_meta = { __index = {} }

-- The player owns its epoch pair and entries. Temporary pairs own their scopes.
function player_meta.__close(self)
    if self.epoch_pair then
        self.epoch_pair:close()
        self.epoch_pair = nil
    end
    if self.machine_cache then
        self.machine_cache:close()
        self.machine_cache = nil
    end
    self.epoch_builder = nil
end

-- Transfer construction state out of a <close> local without closing its resources.
function player_meta.__index:move()
    local player = setmetatable({}, player_meta)
    for name, value in pairs(self) do
        player[name] = value
    end
    for name in pairs(self) do
        self[name] = nil
    end
    return player
end

-- Builders use the player's geometry and own only collection state.
function player_meta.__index:new_mcycle_computation_hash_builder()
    return new_mcycle_computation_hash_builder(self.geometry.log2_mcycles_per_period)
end

function player_meta.__index:new_uarch_cycle_computation_hash_builder(epoch_period_offset)
    return new_uarch_cycle_computation_hash_builder(self.geometry.log2_mcycles_per_period, epoch_period_offset)
end

function player_meta.__index:new_null_computation_hash_builder() -- luacheck: ignore 212 self
    return new_null_computation_hash_builder()
end

-- Obtain an exact input boundary without exposing entry selection to callers.
function player_meta.__index:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local pair <close>, cached_epoch_input_offset =
        self.machine_cache:nearest_not_past_epoch_input_offset(epoch_input_offset)
    self:run_to_epoch_input_offset(pair, cached_epoch_input_offset, epoch_input_offset)
    return pair:move()
end

-- Run from an input boundary to the requested logical mcycle offset or its fixed point.
-- Outputs remain local until acceptance; there is no continuation across driver calls.
-- luacheck: push ignore self
function player_meta.__index:run_to_input_mcycle_offset(
    builder,
    pair,
    epoch_input_offset,
    input_data,
    input_mcycle_offset,
    outputs,
    outputs_frontier
)
    if input_mcycle_offset == 0 then
        return
    end
    local machine = pair.machine
    local input_mcycle_base = begin_input(builder, pair, epoch_input_offset, input_data)
    local pending_outputs = {}
    local on_yield_automatic
    if outputs then
        function on_yield_automatic(yield_reason, output_data)
            if is_tx_output(yield_reason) then
                pending_outputs[#pending_outputs + 1] = output_data
            end
        end
    end
    local mcycle_end = usaturating_add(input_mcycle_base, input_mcycle_offset)
    local break_reason = run_to_stop(builder, machine, mcycle_end, on_yield_automatic)
    if not is_at_fixed_point(break_reason) then
        return break_reason, nil, input_mcycle_base
    end
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
    builder:end_input(machine)
    return break_reason, yield_reason, input_mcycle_base
end

function player_meta.__index:run_to_uarch_cycle(
    builder,
    pair,
    epoch_input_offset,
    input_data,
    input_mcycle_offset,
    uarch_cycle
)
    local machine = pair.machine
    assert(machine:read_reg("uarch_cycle") <= uarch_cycle, "machine is past desired state")
    if uarch_cycle == 0 then
        return
    end
    if input_mcycle_offset == 0 then
        begin_input(builder, pair, epoch_input_offset, input_data)
    end
    return machine:run_uarch(uarch_cycle)
end

-- luacheck: pop

-- Replay completed inputs, leaving the target input undelivered.
function player_meta.__index:run_to_epoch_input_offset(pair, epoch_input_offset_begin, epoch_input_offset_end)
    local builder = self:new_null_computation_hash_builder()
    builder:begin_epoch(pair.machine)
    for epoch_input_offset = epoch_input_offset_begin, math.min(epoch_input_offset_end, self.input_count) - 1 do
        local input_data = self:read_input(epoch_input_offset)
        local break_reason, yield_reason = self:run_to_input_mcycle_offset(
            builder,
            pair,
            epoch_input_offset,
            input_data,
            MAX_MCYCLES_PER_ADVANCE_STATE
        )
        if not is_rx_accepted(yield_reason) and not is_rx_rejected(yield_reason) then
            assert(is_at_fixed_point(break_reason), "input stopped outside a fixed point")
            break
        end
    end
    return builder:end_epoch()
end

-- The persistent epoch pair advances once per input. Scope it during execution so
-- errors release the working machine and any pending rollback snapshot immediately.
function event_handler.input_added(self, epoch_input_offset, path)
    -- A reopened player ignores events for inputs it already applied, which a restarted bridge delivers again.
    if self.epoch_directory and epoch_input_offset < self.input_count then
        return
    end
    local pair <close> = assert(self.epoch_pair, "epoch is not open")
    local builder = self.epoch_builder
    self.epoch_pair, self.epoch_builder = nil, nil
    assert(epoch_input_offset == self.input_count, "input events are not ordered")
    -- A player without an epoch directory keeps the input's bytes, so the file need not outlive the event.
    if self.epoch_directory then
        store_input(self, epoch_input_offset, path)
    else
        self.inputs[epoch_input_offset + 1] = fs.read_file(path)
    end
    self.input_count = epoch_input_offset + 1
    local outputs = {}
    if not self.epoch_stopped then
        local break_reason, yield_reason = self:run_to_input_mcycle_offset(
            builder,
            pair,
            epoch_input_offset,
            self:read_input(epoch_input_offset),
            MAX_MCYCLES_PER_ADVANCE_STATE,
            outputs,
            self.outputs_frontier
        )
        if not is_rx_accepted(yield_reason) and not is_rx_rejected(yield_reason) then
            assert(is_at_fixed_point(break_reason), "input stopped outside a fixed point")
            self.epoch_stopped = true
        end
    end
    assert(not pair.backup_machine, "input stopped before completion")
    self.machine_cache:consider(epoch_input_offset + 1, pair.machine)
    local output_count = self.output_count
    self.output_count = output_count + #outputs
    if self.epoch_directory then
        commit_epoch_state(self, pair, builder, outputs)
    else
        table.move(outputs, 1, #outputs, output_count + 1, self.outputs)
    end
    self.epoch_pair, self.epoch_builder = pair:move(), builder
end

-- Retain the final machine before closing execution so the next player can
-- accumulate inputs while this player disputes the sealed epoch.
function event_handler.epoch_sealed(self, input_count, checkpoint_directory)
    -- A restarted bridge may deliver the seal again to a reopened sealed player.
    if self.epoch_directory and self.mcycle_forest then
        return
    end
    assert(input_count == nil or input_count == self.input_count, "sealed input count mismatch")
    local pair <close> = assert(self.epoch_pair, "epoch is not open")
    self.epoch_pair = nil
    assert(not pair.backup_machine, "cannot seal an unfinished input")
    self.outputs_merkle_root_proof = get_outputs_merkle_root_proof(pair.machine)
    self.final_state_hash = pair.machine:get_root_hash()
    local builder = self.epoch_builder
    self.epoch_builder = nil
    self.mcycle_forest = builder:end_epoch()
    -- The checkpoint is stored while this player still owns the exact final machine, before the seal
    -- is committed, so a seal resent after a crash stores it again.
    if checkpoint_directory then
        store_checkpoint(self, pair.machine, checkpoint_directory)
    end
    if self.epoch_directory then
        seal_epoch_state(self)
    end
end

-- docs:begin collect_mcycle_bundle
function player_meta.__index:collect_mcycle_bundle(epoch_input_offset, input_bundle_offset)
    local pair <close> = self:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local machine = pair.machine
    local builder = self:new_null_computation_hash_builder()
    -- Deliver the input and stay at its boundary. The machine advances to the bundle and pads it
    -- with its fixed-point state hash when the input stops early.
    begin_input(builder, pair, epoch_input_offset, self:read_input(epoch_input_offset))
    local hashes = machine:collect_mcycle_bundle(
        input_bundle_offset,
        self.geometry.log2_mcycles_per_period,
        LOG2_BUNDLE_MCYCLE_COUNT
    )
    local forest = hash_tree.frontier_forest(LOG2_BUNDLE_MCYCLE_COUNT, "keccak256")
    hash_tree.frontier_forest_append(forest, hashes, 1, #hashes + 1)
    return forest
end
-- docs:end collect_mcycle_bundle

-- docs:begin build_uarch_claim
function player_meta.__index:build_uarch_claim(epoch_input_offset, input_period_offset)
    local pair <close> = self:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local machine = pair.machine
    local builder = self:new_uarch_cycle_computation_hash_builder(
        combine_epoch_period_offset(self.geometry.periods_per_input, epoch_input_offset, input_period_offset)
    )
    builder:begin_epoch(machine)
    self:run_to_input_mcycle_offset(
        builder,
        pair,
        epoch_input_offset,
        self:read_input(epoch_input_offset),
        (input_period_offset + 1) * self.geometry.mcycles_per_period
    )
    return builder:end_epoch()
end
-- docs:end build_uarch_claim

-- docs:begin collect_uarch_cycle_bundle
function player_meta.__index:collect_uarch_cycle_bundle(epoch_input_offset, input_period_offset, period_mcycle_offset)
    local pair <close> = self:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local machine = pair.machine
    local tail = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
    local revert_uarch_tail = tail.hashes
    local builder = self:new_null_computation_hash_builder()
    local input_data = self:read_input(epoch_input_offset)
    local input_mcycle_offset =
        combine_input_mcycle_offset(self.geometry.mcycles_per_period, input_period_offset, period_mcycle_offset)
    if input_mcycle_offset == 0 then
        begin_input(builder, pair, epoch_input_offset, input_data)
    else
        self:run_to_input_mcycle_offset(builder, pair, epoch_input_offset, input_data, input_mcycle_offset)
    end
    -- Replay may already have rolled back a rejected input. Its restored boundary
    -- supplies the same uarch history as the tail captured before delivery. The mcycle's
    -- uarch hashes are collected one per uarch cycle until the halt, then pushed as the builder
    -- pushes every mcycle.
    local collected =
        machine:collect_uarch_cycle_root_hashes(usaturating_add(machine:read_reg("mcycle"), 1), 0, revert_uarch_tail)
    local offsets = collected.mcycle_hash_offsets
    local forest = hash_tree.frontier_forest(LOG2_BUNDLE_UARCH_CYCLE_COUNT, "keccak256")
    uarch_computation_hash_push_mcycle({ bundle_height = 0 }, forest, collected.hashes, offsets[1], offsets[2])
    return forest
end
-- docs:end collect_uarch_cycle_bundle

-- Without an epoch directory, inputs stay in the caller's files and outputs in memory. With one,
-- both are in the epoch directory. read_input returns nil past the applied inputs.
function player_meta.__index:read_input(epoch_input_offset)
    if epoch_input_offset >= self.input_count then
        return nil
    end
    if self.epoch_directory then
        return fs.read_file(get_input_path(self.epoch_directory, epoch_input_offset))
    end
    return self.inputs[epoch_input_offset + 1]
end

function player_meta.__index:read_output(epoch_output_offset)
    if self.epoch_directory then
        return fs.read_file(get_output_path(self.epoch_directory, epoch_output_offset))
    end
    return self.outputs[epoch_output_offset + 1]
end

-- The keccak of each output of the epoch, in order.
function player_meta.__index:read_output_hashes()
    if not self.epoch_directory then
        return map(self.outputs, keccak)
    end
    local log = fs.read_file(get_outputs_log_path(self.epoch_directory))
    assert(#log == self.output_count * cartesi.HASH_SIZE, "outputs.log does not match the output count")
    local hashes = {}
    for epoch_output_offset = 0, self.output_count - 1 do
        local first = epoch_output_offset * cartesi.HASH_SIZE + 1
        hashes[epoch_output_offset + 1] = log:sub(first, first + cartesi.HASH_SIZE - 1)
    end
    return hashes
end

-- Clients may request any accepted output from the sealed epoch by its global index, independently of
-- the output the demonstration offers to the referee. Missing indices are no offer.
function player_meta.__index:prove_output(output_index)
    assert(math.type(output_index) == "integer", "invalid output index")
    assert(self.mcycle_forest, "epoch is not sealed")
    local epoch_output_offset = output_index - hash_tree.frontier_get_leaf_count(self.previous_outputs_frontier)
    if epoch_output_offset < 0 or epoch_output_offset >= self.output_count then
        return "nothing"
    end
    -- The first request proves every output of the epoch at once.
    if not self.output_proofs then
        self.output_proofs = hash_tree.frontier_next_proofs(self.previous_outputs_frontier, self:read_output_hashes())
    end
    return {
        output_index = output_index,
        output_data = self:read_output(epoch_output_offset),
        output_proof = self.output_proofs[epoch_output_offset + 1],
    }
end

-- A tree asks for bundles by their index under its root. The mcycle claim's root covers the
-- whole epoch, so the collector splits that epoch-wide index into the input holding the bundle
-- and the bundle's offset within that input.
function player_meta.__index:new_mcycle_tree()
    return new_tree(
        self.geometry.mcycle_height,
        LOG2_BUNDLE_MCYCLE_COUNT,
        self.mcycle_forest,
        function(_, epoch_bundle_offset)
            local bundles_per_input = self.geometry.periods_per_input >> LOG2_BUNDLE_MCYCLE_COUNT
            local epoch_input_offset = epoch_bundle_offset // bundles_per_input
            local input_bundle_offset = epoch_bundle_offset % bundles_per_input
            return self:collect_mcycle_bundle(epoch_input_offset, input_bundle_offset)
        end
    )
end
-- The uarch claim's root covers one period and its bundles are mcycles, so the tree's bundle index
-- is the mcycle's offset within that period. The input and period come from the tree's construction. A stored claim
-- supplies its forest, which is otherwise built.
function player_meta.__index:new_uarch_tree(epoch_input_offset, input_period_offset, forest)
    return new_tree(
        self.geometry.uarch_height,
        LOG2_BUNDLE_UARCH_CYCLE_COUNT,
        forest or self:build_uarch_claim(epoch_input_offset, input_period_offset),
        function(_, period_mcycle_offset)
            return self:collect_uarch_cycle_bundle(epoch_input_offset, input_period_offset, period_mcycle_offset)
        end
    )
end

local prt

-- A copy of the outputs frontier the previous epochs left, or an empty one at genesis.
local function new_outputs_frontier(previous_outputs_frontier)
    if not previous_outputs_frontier then
        return hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    end
    assert(
        #previous_outputs_frontier == cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT + 1
            and previous_outputs_frontier.hash_function == cartesi.keccak256,
        "previous_outputs_frontier is not an outputs frontier"
    )
    return hash_tree.frontier_copy(previous_outputs_frontier)
end

-- Loads an outputs frontier stored with hash_tree.frontier_store.
local function load_outputs_frontier(path)
    return hash_tree.frontier_load(path, cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
end

--------------------------------------------------------------------------------
-- Epoch directory
--
-- A player given an epoch directory keeps its epoch run and dispute there, so it can reopen after a
-- crash or an error. state.json records the newest input boundary, then the seal and each uarch
-- claim, and is the only commit point. Everything it reaches is durable before it is written, and
-- reopening removes what it does not reach. The epoch machine changes in place during an input, so
-- reopening restores machine.revert when the epoch machine does not match state.json, which happens
-- until state.json records the input's end.
-- Small player fields are inline in state.json, and large ones are named by the file that holds
-- them. A field is absent when the player does not have it, so an open epoch has an epoch_builder
-- and a sealed epoch has the seal's fields instead. Inputs and outputs live in files of
-- their own, and outputs.log holds the output keccaks. state.json reaches them through its input
-- and output counts.
--------------------------------------------------------------------------------

local EPOCH_SUBDIRECTORIES = { "entries", "forests", "inputs", "outputs" }

-- state.json names the file of each large player field. The boundary files take the input count,
-- so a new boundary never overwrites the files the committed state.json names.
local function get_boundary_files(input_count)
    return {
        epoch_builder = "frontier-" .. input_count .. ".json",
        outputs_frontier = "outputs-frontier-" .. input_count .. ".json",
        machine_cache = "machine-cache-" .. input_count .. ".json",
    }
end

local MCYCLE_FOREST_FILE = "mcycle-forest.json"

local function get_uarch_claim_file(epoch_input_offset, input_period_offset)
    return "uarch-" .. epoch_input_offset .. "-" .. input_period_offset .. ".json"
end

-- The files the layout creates next to state.json, which reopening removes when state.json does not
-- name them.
local EPOCH_FILE_PATTERNS = {
    "^frontier%-%d+%.json$",
    "^outputs%-frontier%-%d+%.json$",
    "^machine%-cache%-%d+%.json$",
    "^mcycle%-forest%.json$",
    "^uarch%-%d+%-%d+%.json$",
}

local function is_epoch_file(name)
    for _, pattern in ipairs(EPOCH_FILE_PATTERNS) do
        if name:match(pattern) then
            return true
        end
    end
    return name:find(".tmp.", 1, true) ~= nil
end

-- state.json keeps the sealed epoch's outputs Merkle root proof inline.
local EPOCH_STATE_SCHEMAS = {
    EpochState = { outputs_merkle_root_proof = "OutputsMerkleRootProof" },
    OutputsMerkleRootProof = {
        iflags_y_data = "Base64",
        iflags_y_proof = "Proof",
        htif_tohost_data = "Base64",
        htif_tohost_proof = "Proof",
        tx_buffer_data = "Base64",
        tx_buffer_proof = "Proof",
    },
}

function get_input_path(directory, epoch_input_offset)
    return directory .. "/inputs/" .. epoch_input_offset .. ".bin"
end

function get_output_path(directory, epoch_output_offset)
    return directory .. "/outputs/" .. epoch_output_offset .. ".bin"
end

function get_outputs_log_path(directory)
    return directory .. "/outputs.log"
end

-- Clones an input into the epoch directory, so replay never depends on the caller's file.
function store_input(self, epoch_input_offset, path)
    local input_path = get_input_path(self.epoch_directory, epoch_input_offset)
    fs.clone_file(path, input_path)
    fs.sync_file(input_path)
    fs.sync_directory(self.epoch_directory .. "/inputs")
end

-- Stores an input's outputs after the first self.output_count - #outputs of the epoch, and writes
-- their keccaks to outputs.log after the committed records.
local function store_outputs(self, outputs)
    local directory = self.epoch_directory
    local first = self.output_count - #outputs
    for i, output_data in ipairs(outputs) do
        write_durable_file(output_data, get_output_path(directory, first + i - 1))
    end
    fs.sync_directory(directory .. "/outputs")
    local log <close> = assert(io.open(get_outputs_log_path(directory), "r+b"))
    assert(log:seek("set", first * cartesi.HASH_SIZE))
    assert(log:write(table.concat(map(outputs, keccak))))
    fs.sync_file(log)
end

-- Commits the player's fields in state.json, which names the files holding the large ones. The
-- caller makes those files durable first. Afterwards, the files the previous state.json named and this one does
-- not are removed, as are the entries the cache evicted. An open epoch has an epoch_builder, and a
-- sealed one the fields the seal adds.
local function store_epoch_state(self, root_hash, files, pad_bundle)
    local directory = self.epoch_directory
    local state = {
        version = 2,
        input_count = self.input_count,
        output_count = self.output_count,
        root_hash = cartesi.tohex(root_hash),
        epoch_stopped = self.epoch_stopped == true,
        initial_outputs_merkle_root = cartesi.tohex(hash_tree.frontier_get_root_hash(self.previous_outputs_frontier)),
        outputs_frontier = files.outputs_frontier,
        machine_cache = files.machine_cache,
    }
    if files.epoch_builder then
        state.epoch_builder = { frontier = files.epoch_builder, pad_bundle = cartesi.tohex(pad_bundle) }
    else
        state.mcycle_forest = files.mcycle_forest
        state.outputs_merkle_root_proof = self.outputs_merkle_root_proof
        state.uarch_claims = map(self.uarch_claims, function(claim)
            return {
                epoch_input_offset = claim.epoch_input_offset,
                input_period_offset = claim.input_period_offset,
                forest = get_uarch_claim_file(claim.epoch_input_offset, claim.input_period_offset),
            }
        end)
    end
    write_durable_file(cartesi.tojson(state, 2, "EpochState", EPOCH_STATE_SCHEMAS) .. "\n", directory .. "/state.json")
    fs.sync_directory(directory)
    self.machine_cache:remove_evicted()
    local named = {}
    for _, name in pairs(files) do
        named[name] = true
    end
    for _, name in pairs(self.state_files or {}) do
        if not named[name] then
            fs.remove_file(directory .. "/" .. name)
        end
    end
    self.state_files = files
end

-- Commits the boundary the epoch pair has reached. The input's snapshot stays until the next input
-- replaces it, so a crash before this commit reverts.
function commit_epoch_state(self, pair, builder, outputs)
    local directory = self.epoch_directory
    local files = get_boundary_files(self.input_count)
    hash_tree.frontier_forest_store(builder.frontier, directory .. "/forests", directory .. "/" .. files.epoch_builder)
    hash_tree.frontier_store(self.outputs_frontier, directory .. "/" .. files.outputs_frontier)
    self.machine_cache:store(directory .. "/" .. files.machine_cache)
    if #outputs > 0 then
        store_outputs(self, outputs)
    end
    store_epoch_state(self, pair.machine:get_root_hash(), files, builder.pad_bundle)
end

-- Commits the seal. The mcycle forest replaces the open epoch's builder.
function seal_epoch_state(self)
    local directory = self.epoch_directory
    hash_tree.frontier_forest_store(self.mcycle_forest, directory .. "/forests", directory .. "/" .. MCYCLE_FOREST_FILE)
    store_epoch_state(self, self.final_state_hash, {
        outputs_frontier = self.state_files.outputs_frontier,
        machine_cache = self.state_files.machine_cache,
        mcycle_forest = MCYCLE_FOREST_FILE,
    })
end

-- Commits a uarch claim the player built. Its bundles, once opened, are stored with its forest.
function store_uarch_claim(self, claim)
    local directory = self.epoch_directory
    local file = get_uarch_claim_file(claim.epoch_input_offset, claim.input_period_offset)
    hash_tree.frontier_forest_store(claim.tree.forest, directory .. "/forests", directory .. "/" .. file)
    store_epoch_state(self, self.final_state_hash, self.state_files)
end

-- Writes the files load_epoch reads next to the final machine stored in a checkpoint directory.
local function store_checkpoint_files(self, directory)
    local outputs_root =
        output_verifier.validate_outputs_merkle_root_response(self.outputs_merkle_root_proof, self.final_state_hash)
    assert(
        outputs_root == hash_tree.frontier_get_root_hash(self.outputs_frontier),
        "checkpoint output history does not match the machine"
    )
    hash_tree.frontier_store(self.outputs_frontier, directory .. "/outputs-frontier.json")
    write_durable_file(cartesi.tojson({
        version = 2,
        initial_state_hash = cartesi.tohex(self.dapp_contract.initial_state_hash),
        final_state_hash = cartesi.tohex(self.final_state_hash),
        outputs_root = cartesi.tohex(outputs_root),
        output_count = hash_tree.frontier_get_leaf_count(self.outputs_frontier),
        input_count = self.input_count,
        log2_mcycles_per_period = self.geometry.log2_mcycles_per_period,
    }, 2) .. "\n", directory .. "/epoch.json")
    fs.sync_directory(directory)
end

-- Stores the next epoch's checkpoint from the final machine. It is written under <directory>.tmp and
-- renamed into place, so the checkpoint directory either holds a complete checkpoint or does not
-- exist. An existing one comes from an earlier attempt at this seal, and a leftover .tmp is replaced.
function store_checkpoint(self, machine, directory)
    if fs.exists(directory) then
        return
    end
    local temporary_directory = directory .. ".tmp"
    if fs.exists(temporary_directory) then
        remove_leftover_stored_machine(temporary_directory)
    end
    assert_rolling_template(machine)
    machine:store(temporary_directory)
    machine:sync_stored(temporary_directory)
    store_checkpoint_files(self, temporary_directory)
    cartesi.machine:rename_stored(temporary_directory, directory)
end

-- Stores the checkpoint epoch 0 starts from: the template machine with an empty output history. Like
-- the seal's checkpoint, it is written under <directory>.tmp and renamed into place, and an existing
-- one is kept.
local function store_template_checkpoint(template_directory, geometry, directory)
    if fs.exists(directory) then
        return
    end
    local temporary_directory = directory .. ".tmp"
    if fs.exists(temporary_directory) then
        remove_leftover_stored_machine(temporary_directory)
    end
    cartesi.machine:clone_stored(template_directory, temporary_directory)
    local outputs_frontier = new_outputs_frontier()
    local outputs_root = hash_tree.frontier_get_root_hash(outputs_frontier)
    local template_hash
    do
        local machine <close> = cartesi.machine(temporary_directory)
        assert_rolling_template(machine)
        assert(
            machine:read_memory(CMIO_TX_BUFFER_ADDRESS, WORD_SIZE) == outputs_root,
            "template machine has an output history"
        )
        template_hash = machine:get_root_hash()
    end
    hash_tree.frontier_store(outputs_frontier, temporary_directory .. "/outputs-frontier.json")
    write_durable_file(cartesi.tojson({
        version = 2,
        initial_state_hash = cartesi.tohex(template_hash),
        final_state_hash = cartesi.tohex(template_hash),
        outputs_root = cartesi.tohex(outputs_root),
        output_count = 0,
        input_count = 0,
        log2_mcycles_per_period = geometry.log2_mcycles_per_period,
    }, 2) .. "\n", temporary_directory .. "/epoch.json")
    fs.sync_directory(temporary_directory)
    cartesi.machine:rename_stored(temporary_directory, directory)
end

-- Removes everything the layout creates from an epoch directory, which clears what an
-- initialization interrupted before its first state.json left. A name the layout does not create
-- is an error, so a wrong directory is never cleared.
local function clear_epoch_directory(directory)
    for _, name in ipairs(fs.list_directory(directory)) do
        local path = directory .. "/" .. name
        if name == "machine" or name == "machine.revert" or name == "pair" or name == "pair.revert" then
            remove_leftover_stored_machine(path)
        elseif name == "entries" then
            for _, entry in ipairs(fs.list_directory(path)) do
                remove_leftover_stored_machine(path .. "/" .. entry)
            end
            fs.remove_directory(path)
        elseif name == "forests" or name == "inputs" or name == "outputs" then
            for _, file in ipairs(fs.list_directory(path)) do
                fs.remove_file(path .. "/" .. file)
            end
            fs.remove_directory(path)
        elseif name == "state.json" or name == "outputs.log" or is_epoch_file(name) then
            fs.remove_file(path)
        else
            error("epoch directory holds a file its layout does not create: " .. name)
        end
    end
end

-- Removes an epoch directory a player no longer needs, such as after its epoch's dispute.
local function remove_epoch_directory(directory)
    clear_epoch_directory(directory)
    fs.remove_directory(directory)
end

-- Creates the layout of an epoch directory without a state.json.
local function create_epoch_directory(directory)
    clear_epoch_directory(directory)
    for _, name in ipairs(EPOCH_SUBDIRECTORIES) do
        fs.create_directory(directory .. "/" .. name)
    end
    write_durable_file("", get_outputs_log_path(directory))
    fs.sync_directory(directory)
end

-- The root hash of a stored machine, or nil when there is none or it cannot be loaded.
local function get_stored_root_hash(directory)
    if not fs.exists(directory) then
        return nil
    end
    local loaded, machine = pcall(cartesi.machine, directory)
    if not loaded then
        return nil
    end
    local stored <close> = machine
    return stored:get_root_hash()
end

-- Brings the epoch machine to the recorded boundary. machine.revert holds it when a crash came
-- during an input, before state.json recorded the input's end. Otherwise the epoch machine was
-- synced at that boundary and is unchanged since.
local function recover_epoch_machine(directory, root_hash)
    local machine_directory = directory .. "/machine"
    local backup_directory = machine_directory .. ".revert"
    if get_stored_root_hash(backup_directory) == root_hash then
        if fs.exists(machine_directory) then
            remove_leftover_stored_machine(machine_directory)
        end
        cartesi.machine:rename_stored(backup_directory, machine_directory)
        return
    end
    assert(get_stored_root_hash(machine_directory) == root_hash, "the epoch machine does not match its state")
    if fs.exists(backup_directory) then
        remove_leftover_stored_machine(backup_directory)
    end
end

-- The files a state.json names, keyed by the field that names them.
local function get_state_files(state)
    return {
        epoch_builder = state.epoch_builder and state.epoch_builder.frontier,
        outputs_frontier = state.outputs_frontier,
        machine_cache = state.machine_cache,
        mcycle_forest = state.mcycle_forest,
    }
end

-- Removes what state.json does not reach: temporary files, the temporary pair and its snapshot,
-- entries the cache does not list, files no field names, and inputs, outputs, and outputs.log
-- records past the counts.
local function remove_epoch_leftovers(directory, state, machine_cache)
    local function remove_files(subdirectory, count)
        for _, name in ipairs(fs.list_directory(subdirectory)) do
            local offset = tonumber(name:match("^(%d+)%.bin$"))
            if name:find(".tmp.", 1, true) or (count and offset and offset >= count) then
                fs.remove_file(subdirectory .. "/" .. name)
            end
        end
    end
    for _, leftover in ipairs({ "pair", "pair.revert" }) do
        if fs.exists(directory .. "/" .. leftover) then
            remove_leftover_stored_machine(directory .. "/" .. leftover)
        end
    end
    local named = {}
    for _, name in pairs(get_state_files(state)) do
        named[name] = true
    end
    for _, claim in ipairs(state.uarch_claims or {}) do
        named[claim.forest] = true
    end
    for _, name in ipairs(fs.list_directory(directory)) do
        if is_epoch_file(name) and not named[name] then
            fs.remove_file(directory .. "/" .. name)
        end
    end
    remove_files(directory .. "/forests")
    remove_files(directory .. "/inputs", state.input_count)
    remove_files(directory .. "/outputs", state.output_count)
    local outputs_log_path = get_outputs_log_path(directory)
    local outputs_log_size = state.output_count * cartesi.HASH_SIZE
    assert(fs.get_file_size(outputs_log_path) >= outputs_log_size, "outputs.log lost committed records")
    fs.truncate_file(outputs_log_path, outputs_log_size)
    fs.sync_file(outputs_log_path)
    local entries = {}
    for _, entry in ipairs(machine_cache.entries) do
        entries[tostring(entry.epoch_input_offset)] = true
    end
    for _, name in ipairs(fs.list_directory(directory .. "/entries")) do
        if not entries[name] then
            remove_leftover_stored_machine(directory .. "/entries/" .. name)
        end
    end
end

-- Reopens an epoch directory at the boundary or seal its state.json records. An open epoch gets
-- its epoch pair and builder back. A sealed epoch gets its mcycle forest and uarch claim forests
-- back, with no epoch pair.
local function reopen_epoch_directory(self)
    local directory = self.epoch_directory
    local state = cartesi.fromjson(fs.read_file(directory .. "/state.json"), "EpochState", EPOCH_STATE_SCHEMAS)
    assert(state.version == 2, "unsupported epoch state version")
    assert(
        cartesi.fromhex(state.initial_outputs_merkle_root)
            == hash_tree.frontier_get_root_hash(self.previous_outputs_frontier),
        "the epoch directory continues a different output history"
    )
    local root_hash = cartesi.fromhex(state.root_hash)
    recover_epoch_machine(directory, root_hash)
    local machine_directory = directory .. "/machine"
    self.machine_cache =
        load_stored_machine_cache(directory, machine_directory, directory .. "/" .. state.machine_cache)
    remove_epoch_leftovers(directory, state, self.machine_cache)
    self.state_files = get_state_files(state)
    self.input_count, self.output_count = state.input_count, state.output_count
    self.epoch_stopped = state.epoch_stopped
    self.outputs_frontier = load_outputs_frontier(directory .. "/" .. state.outputs_frontier)
    assert(
        hash_tree.frontier_get_leaf_count(self.outputs_frontier)
            == hash_tree.frontier_get_leaf_count(self.previous_outputs_frontier) + self.output_count,
        "the outputs frontier does not match the output count"
    )
    local forests_directory = directory .. "/forests"
    if state.epoch_builder then
        self.epoch_pair = new_stored_machine_pair(new_stored_machine(root_hash, machine_directory), machine_directory)
        assert(
            self.epoch_stopped
                or self.epoch_pair.machine:read_memory(CMIO_TX_BUFFER_ADDRESS, WORD_SIZE)
                    == hash_tree.frontier_get_root_hash(self.outputs_frontier),
            "output history does not match the epoch machine"
        )
        local builder = self:new_mcycle_computation_hash_builder()
        builder.frontier =
            hash_tree.frontier_forest_load(forests_directory, directory .. "/" .. state.epoch_builder.frontier)
        builder.pad_bundle = cartesi.fromhex(state.epoch_builder.pad_bundle)
        builder.input_bundle_count = 0
        self.epoch_builder = builder
        return
    end
    self.final_state_hash = root_hash
    self.outputs_merkle_root_proof = state.outputs_merkle_root_proof
    assert(
        output_verifier.validate_outputs_merkle_root_response(self.outputs_merkle_root_proof, root_hash)
            == hash_tree.frontier_get_root_hash(self.outputs_frontier),
        "the outputs Merkle root proof does not match the output history"
    )
    self.mcycle_forest = hash_tree.frontier_forest_load(forests_directory, directory .. "/" .. state.mcycle_forest)
    for _, stored in ipairs(state.uarch_claims) do
        self.uarch_claims[#self.uarch_claims + 1] = {
            epoch_input_offset = stored.epoch_input_offset,
            input_period_offset = stored.input_period_offset,
            forest = hash_tree.frontier_forest_load(forests_directory, directory .. "/" .. stored.forest),
        }
    end
end

-- Registers the trees of a reopened sealed epoch. Trees collect bundles through the player, so they
-- are made once the player has its final table.
local function register_stored_trees(self)
    local mcycle_tree = self:new_mcycle_tree()
    self.trees[mcycle_tree:get_root_hash()] = mcycle_tree
    for _, claim in ipairs(self.uarch_claims) do
        claim.tree = self:new_uarch_tree(claim.epoch_input_offset, claim.input_period_offset, claim.forest)
        claim.forest = nil
        self.trees[claim.tree:get_root_hash()] = claim.tree
    end
end

-- Each player owns its input filenames, cache, and open epoch computation.
-- Default event handlers are shared and treated as read-only.
-- The optional outputs frontier bootstraps output history after a previous epoch.
-- With an existing epoch directory, the player runs on stored machines kept there instead
-- of forked servers.
local function new_player(dapp_contract, label, previous_outputs_frontier, epoch_directory)
    local self <close> = setmetatable({
        event_handler = event_handler,
        label = label or "honest",
        dapp_contract = dapp_contract,
        geometry = dapp_contract.geometry,
        epoch_directory = epoch_directory,
        input_count = 0,
        output_count = 0,
        trees = {},
        uarch_claims = {},
    }, player_meta)
    self.previous_outputs_frontier = new_outputs_frontier(previous_outputs_frontier)
    if epoch_directory and fs.exists(epoch_directory .. "/state.json") then
        reopen_epoch_directory(self)
        local player = self:move()
        if player.mcycle_forest then
            register_stored_trees(player)
        end
        return player
    end
    local initial_state_hash = dapp_contract.initial_state_hash
    local machine
    if epoch_directory then
        create_epoch_directory(epoch_directory)
        local machine_directory = epoch_directory .. "/machine"
        cartesi.machine:clone_stored(
            dapp_contract.machine_directory or cartesi.tohex(initial_state_hash),
            machine_directory
        )
        self.epoch_pair =
            new_stored_machine_pair(new_stored_machine(initial_state_hash, machine_directory), machine_directory)
        machine = self.epoch_pair.machine
        assert_rolling_template(machine)
        self.machine_cache = new_stored_machine_cache(epoch_directory, machine_directory, machine)
    else
        self.epoch_pair = new_machine_pair(prt.new_machine(initial_state_hash, dapp_contract.machine_directory))
        machine = self.epoch_pair.machine
        assert_rolling_template(machine)
        self.machine_cache = prt.new_machine_cache(fork_server(machine))
        self.inputs, self.outputs = {}, {}
    end
    self.epoch_builder = self:new_mcycle_computation_hash_builder()
    self.epoch_builder:begin_epoch(machine)
    assert(
        machine:read_memory(CMIO_TX_BUFFER_ADDRESS, WORD_SIZE)
            == hash_tree.frontier_get_root_hash(self.previous_outputs_frontier),
        "output history does not match initial machine"
    )
    self.outputs_frontier = hash_tree.frontier_copy(self.previous_outputs_frontier)
    if epoch_directory then
        commit_epoch_state(self, self.epoch_pair, self.epoch_builder, {})
    end
    return self:move()
end

-- Restore the public bootstrap inputs, leaving machine ownership to new_player.
local function load_epoch(directory)
    local manifest = cartesi.fromjson(fs.read_file(directory .. "/epoch.json"))
    assert(manifest.version == 2, "unsupported player checkpoint version")
    assert(
        math.type(manifest.output_count) == "integer" and manifest.output_count >= 0,
        "invalid checkpoint output count"
    )
    local frontier = load_outputs_frontier(directory .. "/outputs-frontier.json")
    assert(hash_tree.frontier_get_leaf_count(frontier) == manifest.output_count, "checkpoint output count mismatch")
    assert(
        cartesi.tohex(hash_tree.frontier_get_root_hash(frontier)) == manifest.outputs_root,
        "checkpoint output root mismatch"
    )
    return {
        initial_state_hash = cartesi.fromhex(manifest.final_state_hash),
        machine_directory = directory,
        geometry = new_geometry(manifest.log2_mcycles_per_period),
    },
        frontier,
        manifest
end

prt = {
    load_epoch = load_epoch,
    store_template_checkpoint = store_template_checkpoint,
    remove_epoch_directory = remove_epoch_directory,
    LOG2_BUNDLE_MCYCLE_COUNT = LOG2_BUNDLE_MCYCLE_COUNT,
    LOG2_BUNDLE_UARCH_CYCLE_COUNT = LOG2_BUNDLE_UARCH_CYCLE_COUNT,
    new_player = new_player,
    new_tree = new_tree,
    new_machine = new_machine,
    new_null_computation_hash_builder = new_null_computation_hash_builder,
    new_mcycle_computation_hash_builder = new_mcycle_computation_hash_builder,
    new_uarch_cycle_computation_hash_builder = new_uarch_cycle_computation_hash_builder,
    umin = umin,
    usaturating_add = usaturating_add,
    is_target_mcycle = is_target_mcycle,
    is_yielded_manual = is_yielded_manual,
    is_at_fixed_point = is_at_fixed_point,
    uarch_computation_hash_push_mcycle = uarch_computation_hash_push_mcycle,
    new_machine_cache = new_machine_cache,
    new_machine_pair = new_machine_pair,
    new_match = new_match,
    new_referee = new_referee,
    new_dapp_contract = new_dapp_contract,
    new_geometry = new_geometry,
    split_epoch_period_offset = split_epoch_period_offset,
    combine_epoch_period_offset = combine_epoch_period_offset,
    split_state_transition_offset = split_state_transition_offset,
    combine_input_mcycle_offset = combine_input_mcycle_offset,
    validate_bisection_response = validate_bisection_response,
    advance_bisection = advance_bisection,
    validate_seal_response = validate_seal_response,
}

-- Module loading exposes the shared implementation without starting a CLI role.
if ... == "prt" then
    return prt
end

-- =============================================================================
-- Role dispatch
-- =============================================================================

local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")
local next_argument = 3

-- Takes the next argument. It is required when a message says what is missing.
local function take_argument(message)
    local value = arg[next_argument]
    assert(value or not message, message)
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
    local label = take_argument()
    local epoch_directory = take_argument()
    run_role = function(dapp_contract)
        local player <close> = new_player(dapp_contract, label, nil, epoch_directory)
        prtu.run_client(player, server_address)
    end
    assert(next_argument > #arg, "only the referee takes input files")
else
    error("unknown role: " .. role)
end

local dapp_contract = new_dapp_contract(initial_state_hash, { take_remaining_arguments() })
run_role(dapp_contract)
