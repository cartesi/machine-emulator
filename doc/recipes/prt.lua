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
local get_other_turn_index = prtu.get_other_turn_index
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

-- Protocol coordinates are zero-based. Keep the epoch period separate from the uarch
-- transition offset: their combined counter would exceed a Lua integer's 64 bits.
local function split_epoch_period_index(periods_per_input, epoch_period_index)
    return epoch_period_index // periods_per_input, epoch_period_index % periods_per_input
end

local function combine_epoch_period_index(periods_per_input, input_index, period_index)
    return input_index * periods_per_input + period_index
end

local function split_state_transition_offset(state_transition_offset)
    return state_transition_offset >> cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE,
        state_transition_offset & cartesi.UARCH_CYCLE_MAX
end

local function combine_input_mcycle_offset(mcycles_per_period, period_index, mcycle_offset)
    return period_index * mcycles_per_period + mcycle_offset
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
    match.turn_index = get_other_turn_index(match.turn_index)
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
local function validate_claim_response(submitted_claim, height)
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
-- from the agreed state hash. Returns the state hash the logs reach; invalid logs raise an
-- error, which the request dispatcher rejects through its protected validator callback.
-- docs:begin validate_state_transition_response
local function validate_state_transition_response(
    dapp_contract,
    current_state_hash,
    epoch_period_index,
    state_transition_offset,
    logs
)
    local periods_per_input = dapp_contract.geometry.periods_per_input
    local input_index, period_index = split_epoch_period_index(periods_per_input, epoch_period_index)
    local _, uarch_cycle = split_state_transition_offset(state_transition_offset)
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
-- docs:end validate_state_transition_response

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
-- open the on-turn node. At leaf zero the agreed state is the tournament's initial state;
-- otherwise the on-turn claim must prove the preceding state against its computation hash.
-- docs:begin validate_seal_response
local function validate_seal_response(tournament, match, response)
    assert(match.height == 1)
    assert(keccak(response.turn_left_node, response.turn_right_node) == match.turn_parent_node)
    local descend_left = response.turn_left_node ~= match.other_left_node
    local leaf_index = match.position + (descend_left and 0 or 1)
    local agreed_state_hash
    if leaf_index ~= 0 then
        local proof = response.agreed_state_hash_proof
        assert(proof.target_address == leaf_index - 1)
        assert(proof.log2_target_size == 0)
        assert(proof.log2_root_size == tournament.height)
        assert(#proof.sibling_hashes == tournament.height)
        assert(proof.root_hash == match.claims[match.turn_index].computation_hash)
        assert(descend_left or proof.target_hash == response.turn_left_node)
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
    assert(keccak(children.computation_hash_left, children.computation_hash_right) == computation_hash)
end

-- Requests the waiting claim's response at the timeout block.
local function emit_schedule_match_timeout_win(tournament, match, deadline)
    local other_turn_index = get_other_turn_index(match.turn_index)
    local other_claim = match.claims[other_turn_index]
    return server:request_first_valid(
        subscription_hash(tournament.id, other_claim),
        EVENTS.schedule_match_timeout_win,
        { deadline, other_claim.computation_hash },
        function(response)
            assert(server:get_time() >= deadline and server:get_time() < deadline + 1)
            validate_timeout_win_response(response, other_claim.computation_hash)
            story.report_timeout_win(match)
            return other_turn_index
        end,
        deadline
    )
end

local function emit_schedule_match_elimination(match, deadline)
    return server:request_first_valid(EVERYONE, EVENTS.schedule_match_elimination, { deadline }, function()
        assert(server:get_time() >= deadline)
        story.report_match_eliminated(match)
        return 0
    end, deadline)
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
        function()
            assert(server:get_time() >= deadline)
            return true
        end,
        deadline
    )
    local proof <close> = server:request_first_valid(
        subscriptions,
        EVENTS.prove_state_transition,
        { tournament.input_index, tournament.period_index, state_transition_offset },
        function(response)
            assert(server:get_time() < deadline)
            return validate_state_transition_response(
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
    local input_index, period_index = split_epoch_period_index(geometry.periods_per_input, epoch_period_index)
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
            local claim = validate_claim_response(response, geometry.uarch_height)
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
            function()
                assert(server:get_time() >= winner_expires_at)
                return true
            end, winner_expires_at
        )
        local propagation <close> = server:request_first_valid(
            subscription_hash(mcycle_tournament.id, mcycle_claim),
            EVENTS.propagate_uarch_result, { mcycle_claim.computation_hash },
            function(response)
                assert(server:get_time() < winner_expires_at)
                assert(keccak(response.computation_hash_left, response.computation_hash_right)
                    == mcycle_claim.computation_hash)
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
    local turn_claim = match.claims[match.turn_index]
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
    local close_block = server:request_block() + 1
    local collection <close> = server:request_all(
        dapp_contract.initial_state_hash,
        EVENTS.commit_mcycle_claim,
        {},
        function(response)
            return validate_claim_response(response, geometry.mcycle_height)
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
local function validate_outputs_merkle_root_response(result, final_state_hash)
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

local function validate_output_response(output, outputs_merkle_root)
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
            return validate_outputs_merkle_root_response(response, winner.final_state_hash)
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
                    return validate_output_response(response, outputs_merkle_root) and response
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
-- subtree root per 2^bundle_height leaves, stored at its logical height, and queries
-- below a bundle are answered by opening it.
------------------------------------------------------------

local LOG2_BUNDLE_MCYCLE_COUNT = 4
local LOG2_BUNDLE_UARCH_CYCLE_COUNT = 16
local LOG2_HASHES_PER_COLLECTION = 8
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

-- Limits each collection call to the mcycle span of 2^LOG2_HASHES_PER_COLLECTION bundle roots,
-- bounding temporary hash storage. Caps the span at MCYCLE_MAX to avoid shift overflow.
local function mcycle_hashes_collection_chunk_size(log2_period, log2_bundle_mcycle_count)
    local log2_collection_chunk_size = log2_period + log2_bundle_mcycle_count + LOG2_HASHES_PER_COLLECTION
    if log2_collection_chunk_size >= 64 then
        return cartesi.MCYCLE_MAX
    end
    return 1 << log2_collection_chunk_size
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
    self.cache.owners[machine] = nil
    self.machine, self.backup = nil, nil
end
machine_owner_meta.__close = machine_owner_meta.__index.close

-- Transfer ownership out of a <close> local without closing the machine on return.
function machine_owner_meta.__index:move()
    assert(self.machine, "machine owner is closed")
    local owner = setmetatable({ cache = self.cache, machine = self.machine, backup = self.backup }, machine_owner_meta)
    self.cache.owners[self.machine] = owner
    self.machine, self.backup = nil, nil
    return owner
end

local function new_machine_owner(cache, machine)
    local owner = setmetatable({ cache = cache, machine = machine }, machine_owner_meta)
    cache.owners[machine] = owner
    return machine, owner
end

function machine_cache_meta.__index:close()
    self.closed = true
    for _, owner in pairs(self.owners) do
        owner:close()
    end
    self.checkpoints = {}
end
machine_cache_meta.__close = machine_cache_meta.__index.close

function machine_cache_meta.__index:snapshot(machine)
    local owner = assert(self.owners[machine], "machine is not owned by this cache")
    assert(not owner.backup, "machine already has a snapshot")
    owner.backup = fork_server(machine)
end

function machine_cache_meta.__index:commit(machine)
    local owner = assert(self.owners[machine], "machine is not owned by this cache")
    local backup <close> = owner.backup -- luacheck: ignore 211
    owner.backup = nil
end

function machine_cache_meta.__index:revert(machine)
    local owner = assert(self.owners[machine], "machine is not owned by this cache")
    local backup <close> = assert(owner.backup, "no snapshot to revert to")
    owner.backup = nil
    machine:shutdown_server()
    machine:swap(backup)
end

-- Spreads a bounded number of checkpoints across the epoch to shorten replay when collecting bundles.
-- As the epoch advances, doubles the input gap and replaces closely spaced checkpoints with later
-- ones, preserving the initial machine so every input boundary remains reachable.
-- Only the forward claim build offers checkpoints, so the list remains ordered.
-- Callers offer manual yields. Only an accepted yield is the next input's virgin boundary;
-- rejection rolls back to the input's own boundary and offers no new checkpoint.
function machine_cache_meta.__index:consider(input_index, machine)
    assert(not self.closed, "machine cache is closed")
    if self.frozen then
        return
    end
    if not is_rx_accepted(receive_cmio_request(machine)) then
        return
    end
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

-- Keep the completed epoch's checkpoints available for replay without accepting new offers.
function machine_cache_meta.__index:freeze()
    assert(not self.closed, "machine cache is closed")
    self.frozen = true
end

-- Selection is private: callers always receive the requested virgin boundary, not merely the
-- closest retained one. The owner closes the clone if replay fails before it can be returned.
function machine_cache_meta.__index:clone_at_input_boundary(input_index, run_to_input_boundary)
    assert(not self.closed, "machine cache is closed")
    local closest = self.checkpoints[1]
    for i = 2, #self.checkpoints do
        if self.checkpoints[i].input_index > input_index then
            break
        end
        closest = self.checkpoints[i]
    end
    local machine, owner <close> = new_machine_owner(self, fork_server(closest.machine))
    run_to_input_boundary(machine, closest.input_index, input_index)
    return machine, owner:move()
end

local function new_machine_cache(initial_machine, capacity, initial_input_gap)
    capacity = capacity or DEFAULT_MACHINE_CACHE_CAPACITY
    assert(capacity > 0, "machine cache capacity must include its initial checkpoint")
    local input_gap = initial_input_gap or DEFAULT_MACHINE_CACHE_INPUT_GAP
    local cache = setmetatable({
        capacity = capacity,
        checkpoints = {},
        owners = {},
        input_gap = input_gap,
        replace_cursor = 2,
    }, machine_cache_meta)
    local machine, owner = new_machine_owner(cache, initial_machine)
    cache.checkpoints[1] = { input_index = 0, machine = machine, owner = owner }
    return cache
end

-- Advances through a builder's run(mcycle_end) method until a fixed point or the target mcycle,
-- returning the break reason. A null builder delegates plain replay to its machine.
-- Mcycle bundle collection supplies a table with only run and uses no yield callback.
-- Automatic yields are read through the builder and passed to the optional callback; without one,
-- they are ignored. A terminal manual yield remains unread for the caller to handle.
local function run_to_stop(builder, mcycle_end, on_yield_automatic)
    while true do
        local break_reason = builder:run(mcycle_end)
        if is_at_fixed_point(break_reason) or is_target_mcycle(break_reason) then
            return break_reason
        elseif is_yielded_automatic(break_reason) then
            if on_yield_automatic then
                local yield_reason, data = receive_cmio_request(builder)
                on_yield_automatic(yield_reason, data)
            end
        end
        -- Other reasons (soft yields or console breaks) just keep going.
    end
end

-- Retain only accepted outputs and check their cumulative root. Pending outputs from other
-- outcomes are discarded when the input driver returns.
local function flush_pending_outputs(pending, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
    if not outputs or not is_rx_accepted(yield_reason) then
        return
    end
    for _, output in ipairs(pending) do
        outputs[#outputs + 1] = output
        hash_tree.frontier_push_back(outputs_frontier, keccak(output))
    end
    assert(hash_tree.frontier_get_root_hash(outputs_frontier) == outputs_merkle_root, "outputs Merkle root mismatch")
end

-- Delivers a posted input, recording the root a rejection reverts to. The machine and
-- logged transition both leave inapplicable deliveries unchanged.
local function load_cmio_input(builder, data, revert_root_hash)
    if data ~= nil then
        builder:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
    end
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

-- Builders override execution and forward other machine methods, caching them on first use.
local computation_hash_meta = {
    __index = function(self, name)
        return util.forward_method(self, self.machine, name)
    end,
}

-- Plain replay has the same input lifecycle as a sampled run.
local function noop() end
local function make_null_computation_hash_builder(machine)
    return setmetatable({
        machine = machine,
        begin_epoch = noop,
        begin_input = noop,
        end_input = noop,
        end_epoch = noop,
    }, computation_hash_meta)
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
    builder.bundle_count = builder.bundle_count + count
    builder.input_bundle_count = builder.input_bundle_count + count
    if at_fixed_point then
        local pad_count = builder.max_bundles_per_input - builder.input_bundle_count
        hash_tree.frontier_forest_pad_back(builder.frontier, builder.pad_bundle, pad_count, builder.bundle_height)
        builder.bundle_count = builder.bundle_count + pad_count
        builder.input_bundle_count = builder.max_bundles_per_input
    end
end

local function mcycle_computation_hash_begin_epoch(builder)
    builder.frontier = hash_tree.frontier_forest(builder.height, "keccak256")
    builder.bundle_count = 0
    builder.input_bundle_count = 0
    local collected = builder.machine:collect_mcycle_root_hashes(
        builder.machine:read_reg("mcycle"),
        builder.log2_period,
        0,
        builder.bundle_height
    )
    assert(is_at_fixed_point(collected.break_reason), "mcycle computation hash started outside a fixed point")
    builder.pad_bundle = collected.hashes[#collected.hashes]
end

local function mcycle_computation_hash_begin_input(builder, input_index)
    builder.input_index = input_index
    assert(
        (builder.bundle_count << builder.bundle_height) == input_index * builder.periods_per_input,
        "mcycle computation hash input is out of order"
    )
    builder.input_bundle_count = 0
    builder.mcycle_phase = 0
    builder.partial_bundle = nil
end

local function mcycle_computation_hash_run(builder, mcycle_end)
    local collected = { mcycle_phase = builder.mcycle_phase, partial_bundle = builder.partial_bundle }
    repeat
        local collection_end =
            usaturating_add(builder.machine:read_reg("mcycle"), builder.collection_chunk_size, mcycle_end)
        collected = builder.machine:collect_mcycle_root_hashes(
            collection_end,
            builder.log2_period,
            collected.mcycle_phase,
            builder.bundle_height,
            collected.partial_bundle
        )
        mcycle_computation_hash_push_collected(builder, collected)
        if is_yielded_manual(collected.break_reason) then
            builder.machine_cache:consider(builder.input_index + 1, builder.machine)
        end
    until not is_target_mcycle(collected.break_reason) or builder.machine:read_reg("mcycle") == mcycle_end
    builder.mcycle_phase, builder.partial_bundle = collected.mcycle_phase, collected.partial_bundle
    return collected.break_reason
end

local function mcycle_computation_hash_end_input(builder)
    assert(builder.input_bundle_count == builder.max_bundles_per_input, "mcycle computation hash input is incomplete")
    builder.input_bundle_count = 0
end

local function mcycle_computation_hash_end_epoch(builder)
    assert(builder.input_bundle_count == 0, "mcycle computation hash input was not closed")
    builder.machine_cache:freeze()
    if builder.bundle_count == builder.max_bundle_count then
        return builder.frontier
    end
    hash_tree.frontier_forest_pad_back(
        builder.frontier,
        builder.pad_bundle,
        builder.max_bundle_count - builder.bundle_count,
        builder.bundle_height
    )
    builder.bundle_count = builder.max_bundle_count
    return builder.frontier
end

-- The caller supplies a working clone at input zero. Collect the full epoch as roots
-- of bundles of 2^LOG2_BUNDLE_MCYCLE_COUNT period samples, offering accepted boundaries
-- to the machine cache. Counts measure bundles at bundle_height.
local function make_mcycle_computation_hash_builder(log2_mcycles_per_period, machine_cache, machine)
    local log2_periods_per_input = cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_mcycles_per_period
    local height = cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH + log2_periods_per_input
    return setmetatable({
        periods_per_input = 1 << log2_periods_per_input,
        machine_cache = machine_cache,
        machine = machine,
        max_bundle_count = 1 << (height - LOG2_BUNDLE_MCYCLE_COUNT),
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
    }, computation_hash_meta)
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

-- Reconstruct the bundle at a zero-based index within one mcycle. The half-open range
-- [mcycle_hashes_begin, mcycle_hashes_end) contains its execution hashes, halted hash, and reset hash.
local function make_uarch_bundle(bundle_index, hashes, mcycle_hashes_begin, mcycle_hashes_end)
    local forest = hash_tree.frontier_forest(LOG2_BUNDLE_UARCH_CYCLE_COUNT, "keccak256")
    local halt_hash, reset_hash = hashes[mcycle_hashes_end - 2], hashes[mcycle_hashes_end - 1]
    local uarch_cycles_per_mcycle = 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local bundle_start = mcycle_hashes_begin + (bundle_index << LOG2_BUNDLE_UARCH_CYCLE_COUNT)
    local bundle_leaf_count = 1 << LOG2_BUNDLE_UARCH_CYCLE_COUNT
    local reset_padding_count = bundle_start + bundle_leaf_count == mcycle_hashes_begin + uarch_cycles_per_mcycle and 1
        or 0

    -- Copy the transient prefix, including the first halted hash when it falls in this bundle.
    local transient_count_wanted = bundle_leaf_count - reset_padding_count
    local transient_count_available = math.max(0, mcycle_hashes_end - 1 - bundle_start)
    local transient_count = math.min(transient_count_wanted, transient_count_available)
    if transient_count > 0 then
        hash_tree.frontier_forest_append(forest, hashes, bundle_start, bundle_start + transient_count)
    end

    -- Add only the additional copies needed to fill the bundle before reset.
    local halt_padding_count = bundle_leaf_count - transient_count - reset_padding_count
    if halt_padding_count > 0 then
        hash_tree.frontier_forest_pad_back(forest, halt_hash, halt_padding_count)
    end
    if reset_padding_count > 0 then
        hash_tree.frontier_forest_push_back(forest, reset_hash)
    end
    return forest
end

-- Append execution bundles, halt repetitions, and the reset-ending bundle for one mcycle.
local function uarch_computation_hash_push_mcycle(builder, frontier, hashes, mcycle_hashes_begin, mcycle_hashes_end)
    local halt_hash, reset_hash = hashes[mcycle_hashes_end - 2], hashes[mcycle_hashes_end - 1]
    local height = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - builder.bundle_height
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
    local log2_cycles = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local log2_bundles_per_mcycle = log2_cycles - builder.bundle_height
    local remaining = (builder.max_bundle_count - builder.bundle_count) >> log2_bundles_per_mcycle
    local count = available
    local at_fixed_point = is_at_fixed_point(collected.break_reason)
    if at_fixed_point then
        count = count - 1
    end
    assert(count <= remaining, "uarch collection exceeds the claim's mcycle capacity")
    for i = 1, count do
        uarch_computation_hash_push_mcycle(builder, builder.frontier, collected.hashes, offsets[i], offsets[i + 1])
    end
    builder.bundle_count = builder.bundle_count + (count << log2_bundles_per_mcycle)
    if not at_fixed_point then
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
    hash_tree.frontier_forest_pad_back(builder.frontier, pad_frontier, remaining - count)
    builder.bundle_count = builder.max_bundle_count
end

local function uarch_computation_hash_begin_input(builder, input_index, input_mcycle_boundary)
    builder.input_index = input_index
    builder.input_mcycle_boundary = input_mcycle_boundary
    local collected = builder.machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
    builder.revert_uarch_tail = collected.hashes
    builder.target_start = usaturating_add(
        builder.input_mcycle_boundary,
        combine_input_mcycle_offset(builder.mcycles_per_period, builder.period_index, 0)
    )
    builder.target_end = usaturating_add(
        builder.target_start,
        builder.mcycles_per_period,
        usaturating_add(builder.input_mcycle_boundary, MAX_MCYCLES_PER_ADVANCE_STATE)
    )
end

-- Keep plain replay here so it shares input preparation and rejection handling with collection.
local function uarch_computation_hash_run(builder, mcycle_end)
    local machine = builder.machine
    mcycle_end = umin(mcycle_end, builder.target_end)
    if math.ult(machine:read_reg("mcycle"), builder.target_start) then
        local reason = machine:run(umin(mcycle_end, builder.target_start))
        if not is_target_mcycle(reason) or math.ult(mcycle_end, builder.target_start) then
            return reason
        end
    end
    local reason
    repeat
        local collection_end = usaturating_add(machine:read_reg("mcycle"), builder.collection_chunk_size, mcycle_end)
        local collected =
            machine:collect_uarch_cycle_root_hashes(collection_end, builder.bundle_height, builder.revert_uarch_tail)
        builder:push_collected(collected)
        reason = collected.break_reason
    until not is_target_mcycle(reason) or machine:read_reg("mcycle") == mcycle_end
    return reason
end

local function uarch_computation_hash_end_input(builder)
    if builder.bundle_count < builder.max_bundle_count then
        -- A yield before the selected leaves is now a fixed point. On rejection,
        -- collection uses the pre-delivery tail to reproduce the reverted state.
        builder.target_start = builder.machine:read_reg("mcycle")
        builder.target_end = cartesi.MCYCLE_MAX
        builder:run(cartesi.MCYCLE_MAX)
    end
    assert(builder.bundle_count == builder.max_bundle_count, "uarch computation hash is incomplete")
end

local function uarch_computation_hash_begin_epoch(builder)
    builder.frontier = hash_tree.frontier_forest(builder.height, "keccak256")
    builder.bundle_count = 0
end

-- Receive a working machine at the selected input's virgin boundary. Before delivery,
-- begin_input saves its uarch tail for rejection; run replays to the selected period and
-- collects roots of bundles of 2^LOG2_BUNDLE_UARCH_CYCLE_COUNT transitions.
-- A fixed point before the selected period supplies its history without reaching the target.
local function make_uarch_cycle_computation_hash_builder(log2_mcycles_per_period, machine, epoch_period_index)
    local periods_per_input = 1 << (cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE - log2_mcycles_per_period)
    local _, period_index = split_epoch_period_index(periods_per_input, epoch_period_index)
    local height = log2_mcycles_per_period + cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    return setmetatable({
        mcycles_per_period = 1 << log2_mcycles_per_period,
        machine = machine,
        height = height,
        period_index = period_index,
        max_bundle_count = 1 << (height - LOG2_BUNDLE_UARCH_CYCLE_COUNT),
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
    }, computation_hash_meta)
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

function handlers.schedule_match_timeout_win(player, deadline, computation_hash)
    return prtu.schedule_response(player, deadline, function()
        local tree = assert(player.trees[computation_hash], "event concerns a claim this player does not hold")
        local left, right = tree:get_children(0, tree.height)
        return { computation_hash_left = left, computation_hash_right = right }
    end)
end

function handlers.schedule_match_elimination(player, deadline)
    return prtu.schedule_response(player, deadline, function()
        write_stderr("%s: returning eliminate_match\n", player.label)
        return {}
    end)
end

-- A claim: the computation hash's two children and the standard proof of its final state,
-- the last leaf. Producing the proof explicitly opens the last stored bundle.
local function make_claim(tree)
    local final_leaf_index = (1 << tree.height) - 1
    if tree.bundle_height > 0 then
        tree:open_bundle(final_leaf_index >> tree.bundle_height)
    end
    local computation_hash_left, computation_hash_right = tree:get_children(0, tree.height)
    return {
        computation_hash_left = computation_hash_left,
        computation_hash_right = computation_hash_right,
        final_state_hash_proof = tree:prove(final_leaf_index),
    }
end

-- The player's opening mcycle claim. The player announces its root, so a transcript can be
-- read against the players, without the referee ever narrating who holds what.
function handlers.commit_mcycle_claim(player)
    write_stderr("%s: building mcycle claim\n", player.label)
    local tree = player:make_mcycle_tree()
    player.trees[tree:get_root()] = tree
    local claim = make_claim(tree)
    write_stderr(
        "%s: posted claim %s with final state %s\n",
        player.label,
        format_short_hash(tree:get_root()),
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
    local tree = assert(player.trees[computation_hash], "event concerns a claim this player does not hold")
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
-- immediately before them, except at leaf zero where the referee already knows that state.
-- At the first leaf of a bundle, the proof explicitly opens the preceding bundle too.
function handlers.seal_divergence(player, computation_hash, position, other_left_node)
    local tree = assert(player.trees[computation_hash], "event concerns a claim this player does not hold")
    local turn_left_node, turn_right_node = tree:get_children(position, 1)
    local response = { turn_left_node = turn_left_node, turn_right_node = turn_right_node }
    local descend_left = turn_left_node ~= other_left_node
    local leaf_index = position + (descend_left and 0 or 1)
    if leaf_index ~= 0 then
        local agreed_leaf_index = leaf_index - 1
        if tree.bundle_height > 0 then
            tree:open_bundle(agreed_leaf_index >> tree.bundle_height)
        end
        response.agreed_state_hash_proof = tree:prove(agreed_leaf_index)
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
-- The parent match is suspended until the uarch tournament ends. The input index
-- and the period index are 0-based, as the referee counts them. A holder whose uarch claim
-- ends in neither contested value cannot defend its parent claim, and dies on the
-- contradiction.
function handlers.commit_uarch_claim(player, input_index, period_index, next_state_hashes)
    write_stderr("%s: building uarch claim for input %d, period %d\n", player.label, input_index, period_index)
    local tree = player:make_uarch_tree(input_index, period_index)
    player.trees[tree:get_root()] = tree
    local claim = make_claim(tree)
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
    options.make_mcycle_computation_hash_builder = options.make_mcycle_computation_hash_builder
        or make_mcycle_computation_hash_builder
    options.make_uarch_cycle_computation_hash_builder = options.make_uarch_cycle_computation_hash_builder
        or make_uarch_cycle_computation_hash_builder
    options.make_null_computation_hash_builder = options.make_null_computation_hash_builder
        or make_null_computation_hash_builder
    local player = { label = options.label or "honest", trees = {} }
    for name, handler in pairs(handlers) do
        player[name] = handler
    end

    -- Run one input from its virgin boundary, or to a target inside it. Both use the same
    -- delivery and rollback rules. Only accepted inputs publish their outputs.
    -- Input delivery has the same no-op semantics during forward execution and disputes.
    local function run_advance_state_input(
        builder,
        input_index,
        input_mcycle_offset_end,
        revert_root_hash,
        outputs,
        outputs_frontier
    )
        local machine = builder.machine
        local pending = {}
        local function on_yield_automatic(yield_reason, output)
            if outputs and is_tx_output(yield_reason) then
                pending[#pending + 1] = output
            end
        end
        local mcycle_boundary = builder:read_reg("mcycle")
        local mcycle_end = usaturating_add(mcycle_boundary, input_mcycle_offset_end)
        builder:begin_input(input_index, mcycle_boundary)
        machine_cache:snapshot(machine)
        load_cmio_input(builder, inputs[input_index + 1], revert_root_hash)
        local break_reason = run_to_stop(builder, mcycle_end, on_yield_automatic)
        local yield_reason, outputs_merkle_root
        if is_yielded_manual(break_reason) then
            yield_reason, outputs_merkle_root = receive_cmio_request(builder)
        end
        if is_rx_rejected(yield_reason) then
            builder:end_input()
            machine_cache:revert(machine)
            assert(builder:get_root_hash() == revert_root_hash, "rollback did not restore the input boundary")
        elseif is_at_fixed_point(break_reason) then
            builder:end_input()
            flush_pending_outputs(pending, outputs, outputs_frontier, yield_reason, outputs_merkle_root)
            -- Acceptance and sticky stops retain the running machine. A run that stops at its
            -- target keeps its snapshot, so the input can still be rolled back.
            machine_cache:commit(machine)
        end
        return break_reason, yield_reason, mcycle_boundary
    end

    -- Runs the explicit input range [input_index_begin, input_index_end), limited to posted inputs.
    -- A sticky fixed point ends the range early, since every later input idles.
    -- An optional outputs vector collects accepted outputs, checked against the cumulative frontier.
    local function run_advance_state_epoch(builder, input_index_begin, input_index_end, outputs)
        input_index_end = math.min(input_index_end, #inputs)
        local outputs_frontier = outputs and hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
        -- Keep the expected boundary across rejections. Only acceptance establishes a new one.
        local revert_root_hash = builder:get_root_hash()
        builder:begin_epoch()
        for input_index = input_index_begin, input_index_end - 1 do
            local break_reason, yield_reason = run_advance_state_input(
                builder,
                input_index,
                MAX_MCYCLES_PER_ADVANCE_STATE,
                revert_root_hash,
                outputs,
                outputs_frontier
            )
            if is_rx_accepted(yield_reason) then
                revert_root_hash = builder:get_root_hash()
            elseif not is_rx_rejected(yield_reason) then
                assert(is_at_fixed_point(break_reason), "input stopped outside a fixed point")
                break
            end
        end
        return builder:end_epoch()
    end

    local function run_to_input_boundary(machine, input_index_begin, input_index_end)
        local builder = options.make_null_computation_hash_builder(machine)
        return run_advance_state_epoch(builder, input_index_begin, input_index_end)
    end

    -- docs:begin build_mcycle_claim
    local function build_mcycle_claim()
        local machine, _ <close> = machine_cache:clone_at_input_boundary(0, run_to_input_boundary)
        assert(
            machine:read_reg("iflags_Y") ~= 0
                and machine:read_reg("htif_tohost_dev") == cartesi.HTIF_DEV_YIELD
                and machine:read_reg("htif_tohost_cmd") == cartesi.HTIF_YIELD_CMD_MANUAL
                and machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED,
            "initial machine is not waiting on an rx-accepted manual yield"
        )
        local builder =
            options.make_mcycle_computation_hash_builder(geometry.log2_mcycles_per_period, machine_cache, machine)
        return run_advance_state_epoch(builder, 0, #inputs)
    end
    -- docs:end build_mcycle_claim

    -- docs:begin collect_mcycle_bundle
    function player.collect_mcycle_bundle(_, bundle_index)
        local first_leaf = bundle_index << LOG2_BUNDLE_MCYCLE_COUNT
        local input_index, period_index = split_epoch_period_index(geometry.periods_per_input, first_leaf)
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, run_to_input_boundary)
        local revert_root_hash = machine:get_root_hash()
        local builder = options.make_null_computation_hash_builder(machine)
        local _, _, mcycle_boundary =
            run_advance_state_input(builder, input_index, period_index * geometry.mcycles_per_period, revert_root_hash)
        local max_leaf_count = 1 << LOG2_BUNDLE_MCYCLE_COUNT
        local hashes, mcycle_phase = {}, 0
        local break_reason = run_to_stop({
            run = function(_, mcycle_end)
                local collected =
                    machine:collect_mcycle_root_hashes(mcycle_end, geometry.log2_mcycles_per_period, mcycle_phase, 0)
                mcycle_phase = collected.mcycle_phase
                table.move(collected.hashes, 1, #collected.hashes, #hashes + 1, hashes)
                return collected.break_reason
            end,
        }, usaturating_add(mcycle_boundary, (period_index + max_leaf_count) * geometry.mcycles_per_period))
        local count = #hashes
        local at_fixed_point = is_at_fixed_point(break_reason)
        if at_fixed_point then
            -- Padding supplies this state's first required occurrence too.
            count = count - 1
        end
        assert(count <= max_leaf_count, "mcycle collection exceeds the bundle's leaf capacity")
        local forest = hash_tree.frontier_forest(LOG2_BUNDLE_MCYCLE_COUNT, "keccak256")
        hash_tree.frontier_forest_append(forest, hashes, 1, count + 1)
        if at_fixed_point then
            hash_tree.frontier_forest_pad_back(forest, hashes[#hashes], max_leaf_count - count)
        end
        return forest
    end
    -- docs:end collect_mcycle_bundle

    -- docs:begin build_uarch_claim
    local function build_uarch_claim(input_index, period_index)
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, run_to_input_boundary)
        local revert_root_hash = machine:get_root_hash()
        local builder = options.make_uarch_cycle_computation_hash_builder(
            geometry.log2_mcycles_per_period,
            machine,
            combine_epoch_period_index(geometry.periods_per_input, input_index, period_index)
        )
        builder:begin_epoch()
        run_advance_state_input(
            builder,
            input_index,
            (period_index + 1) * geometry.mcycles_per_period,
            revert_root_hash
        )
        return builder:end_epoch()
    end
    -- docs:end build_uarch_claim

    -- docs:begin collect_uarch_cycle_bundle
    function player.collect_uarch_cycle_bundle(_, input_index, period_index, bundle_index)
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, run_to_input_boundary)
        local revert_root_hash = machine:get_root_hash()
        local tail = machine:collect_uarch_cycle_root_hashes(cartesi.MCYCLE_MAX, 0)
        local revert_uarch_tail = tail.hashes
        local bundles_per_mcycle = 1
            << (cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - LOG2_BUNDLE_UARCH_CYCLE_COUNT)
        local mcycle_offset = bundle_index // bundles_per_mcycle
        local builder = options.make_null_computation_hash_builder(machine)
        run_advance_state_input(
            builder,
            input_index,
            combine_input_mcycle_offset(geometry.mcycles_per_period, period_index, mcycle_offset),
            revert_root_hash
        )
        -- Replay may already have rolled back a rejected input. Its restored boundary
        -- supplies the same uarch history as the tail captured before delivery.
        local collected = machine:collect_uarch_cycle_root_hashes(
            usaturating_add(machine:read_reg("mcycle"), 1),
            0,
            revert_uarch_tail
        )
        local offsets = collected.mcycle_hash_offsets
        return make_uarch_bundle(bundle_index % bundles_per_mcycle, collected.hashes, offsets[1], offsets[2])
    end
    -- docs:end collect_uarch_cycle_bundle

    -- The disputed transition's access logs, produced by positioning a fresh fork at the
    -- transition and logging it, whatever claim is under dispute. The transition out of an
    -- input boundary includes the input, when the epoch has one, before the first uarch step.
    -- The transition closing an instruction executes one more step, by then a fixed point, and
    -- the reset. Every other transition is an ordinary uarch step.
    -- docs:begin prove_state_transition
    function player.prove_state_transition(_, input_index, period_index, state_transition_offset)
        local mcycle_offset, uarch_cycle = split_state_transition_offset(state_transition_offset)
        local machine, _ <close> = machine_cache:clone_at_input_boundary(input_index, run_to_input_boundary)
        local revert_root_hash = machine:get_root_hash()
        local data = inputs[input_index + 1]
        if state_transition_offset == 0 and period_index == 0 and data then
            -- Logging never fails. A machine that is not waiting for the input logs the no-op delivery.
            local send_cmio_log =
                machine:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, revert_root_hash)
            return { send_cmio_log = send_cmio_log, step_log = machine:log_step_uarch() }
        end
        local builder = options.make_null_computation_hash_builder(machine)
        run_advance_state_input(
            builder,
            input_index,
            combine_input_mcycle_offset(geometry.mcycles_per_period, period_index, mcycle_offset),
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
        local machine, _ <close> = machine_cache:clone_at_input_boundary(0, run_to_input_boundary)
        local outputs = {}
        local builder = options.make_null_computation_hash_builder(machine)
        run_advance_state_epoch(builder, 0, #inputs, outputs)
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
        local genesis_frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
        local leaves = {}
        for i, output in ipairs(outputs) do
            leaves[i] = keccak(output)
        end
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
                return player:collect_mcycle_bundle(bundle_index)
            end
        )
    end
    function player.make_uarch_tree(_, input_index, period_index)
        return new_tree(
            geometry.uarch_height,
            LOG2_BUNDLE_UARCH_CYCLE_COUNT,
            build_uarch_claim(input_index, period_index),
            function(_, bundle_index)
                return player:collect_uarch_cycle_bundle(input_index, period_index, bundle_index)
            end
        )
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
        make_null_computation_hash_builder = make_null_computation_hash_builder,
        make_mcycle_computation_hash_builder = make_mcycle_computation_hash_builder,
        make_uarch_cycle_computation_hash_builder = make_uarch_cycle_computation_hash_builder,
        umin = umin,
        usaturating_add = usaturating_add,
        is_target_mcycle = is_target_mcycle,
        is_yielded_manual = is_yielded_manual,
        is_at_fixed_point = is_at_fixed_point,
        uarch_computation_hash_push_mcycle = uarch_computation_hash_push_mcycle,
        new_machine_cache = new_machine_cache,
        player_handlers = handlers,
        new_match = new_match,
        new_referee = new_referee,
        new_geometry = new_geometry,
        split_epoch_period_index = split_epoch_period_index,
        combine_epoch_period_index = combine_epoch_period_index,
        split_state_transition_offset = split_state_transition_offset,
        combine_input_mcycle_offset = combine_input_mcycle_offset,
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
