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
-- Roles, selected by the first argument. Every game role takes the referee address and log2 of
-- the mcycle period, and every machine-holding role takes the epoch's input files. The referee
-- is never told how many players to expect: it gathers claims until a seal connection closes the
-- join phase. The referee sorts the claims it gathers, so the bracket and the whole narration are
-- a pure function of the claim set, not of the order in which players connect.
--   prt.lua referee  <address> <log2-period> <input> [<input> ...]
--   prt.lua honest   <address> <log2-period> <input> [<input> ...]
--   prt.lua quitter  <address> <log2-period>
--   prt.lua forger   <address> <log2-period> <index> <forged-input> <input> [<input> ...]
--   prt.lua tamperer <address> <log2-period> <input-index> <entry-offset> <input> [<input> ...]
--   prt.lua fabulist <address> <log2-period> <input-index> <leaf-offset> <input> [<input> ...]
--   prt.lua seal     <address>
--
-- The seal role is the sealer: it stays connected and seals every tournament the referee
-- opens. The recipe starts it once every player is in, so the mcycle tournament seals on the
-- players that connected, and every nested tournament seals as soon as it opens.
--
-- The referee lives here. The players, their machines, claim builds, and dishonest strategies
-- live in prt-player.lua, and the claim trees, the match walk, and the referee server in
-- prtu.lua.

local cartesi = require("cartesi")
local socket = require("socket")
local hash_tree = require("cartesi.hash-tree")
local prtu = require("prtu")
local prt_story = require("prt-story")

local keccak = cartesi.keccak256
local hex = prtu.hex
local new_match, valid_move, advance_match = prtu.new_match, prtu.valid_move, prtu.advance_match

-- The seal role carries no dispute: it is the sealer, which closes the submissions of every
-- tournament the referee opens, the mcycle one once the last player has connected, and every
-- nested one as it opens. It needs none of the game geometry.
if arg[1] == "seal" then
    return prtu.serve(prtu.new_sealer(), assert(arg[2], "missing referee address"))
end

local LOG2_MCYCLES_PER_PERIOD = assert(tonumber(arg[3]), "missing log2 of the mcycle period")
local prt_player = require("prt-player")
prt_player.configure(LOG2_MCYCLES_PER_PERIOD)
local MCYCLE_HEIGHT, UARCH_HEIGHT = prt_player.MCYCLE_HEIGHT, prt_player.UARCH_HEIGHT
local PERIODS_PER_INPUT = prt_player.PERIODS_PER_INPUT
local UARCH_CYCLES_PER_MCYCLE = prt_player.UARCH_CYCLES_PER_MCYCLE
local story = prt_story.new(UARCH_CYCLES_PER_MCYCLE)

local function stderrf(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

-- Reads an input, an ABI-encoded EvmAdvance blob, from a file. The referee and the players
-- all read the same bytes the blockchain posted.
local function read_input(filename)
    local file <close> = assert(io.open(filename, "rb"))
    return file:read("a")
end

-- Reads the epoch's inputs from the files on the command line, starting at `first`.
local function read_inputs(first)
    local inputs = {}
    for index = first, #arg do
        inputs[index - first + 1] = read_input(arg[index])
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
local server, dispatcher

-- Whether a standard hash-tree proof places a leaf at the expected logical index and geometry
-- under the expected claim root.
local function valid_claim_proof(proof, index, height, root)
    if type(proof) ~= "table" or type(proof.sibling_hashes) ~= "table" then
        return false
    end
    return proof.target_address == index
        and proof.log2_target_size == 0
        and proof.log2_root_size == height
        and #proof.sibling_hashes == height
        and proof.root_hash == root
        and pcall(hash_tree.verify_slice, proof)
end

-- Validates a join witness: its two children establish the root, and its standard proof places
-- the final state at the tree's last leaf. Returns the claim.
local function validate_join(witness, height)
    local root = keccak(witness.left, witness.right)
    assert(valid_claim_proof(witness.proof, (1 << height) - 1, height, root), "invalid final-state proof")
    return { root = root, left = witness.left, right = witness.right, final_state = witness.proof.target_hash }
end

-- Turns the submissions to a tournament into its distinct claims, sorted by root hash. Each
-- valid submission is kept only if `accept` allows it (a uarch tournament accepts only the two
-- contested finals) and merged with the identical claim any other player submitted, and its
-- sender is recorded as a holder, so that claim's matches ask it. The sort makes the bracket a
-- pure function of the claim set, not of the order players connected.
-- docs:begin distinct_claims
local function distinct_claims(submissions, height, accept)
    local claims, by_root = {}, {}
    for _, submission in ipairs(submissions) do
        local ok, claim = pcall(validate_join, submission.value, height)
        if ok and (not accept or accept(claim)) then
            local root_hex = hex(claim.root)
            if not by_root[root_hex] then
                by_root[root_hex] = claim
                claims[#claims + 1] = claim
            end
            server:add_holder(root_hex, submission.connection)
        elseif not ok then
            stderrf("a submission failed validation: %s\n", tostring(claim))
        end
    end
    table.sort(claims, function(a, b)
        return hex(a.root) < hex(b.root)
    end)
    return claims
end
-- docs:end distinct_claims

-- Verifies the disputed transition's logs on their own, the way the Dave contracts verify
-- them on the blockchain, without ever instantiating a machine. The transition index picks the
-- form, as in CartesiStateTransition.sol: the transition out of an input boundary includes
-- the input the dapp contract holds (never one a player supplies), the transition closing an
-- instruction verifies a step and then the reset, and every other is an ordinary step. Each
-- verification returns the state hash its log provably advances to, and the chain starts
-- from the agreed state hash. Returns the hash the logs reach, or raises on a bad log.
-- docs:begin verify_transition
local function verify_transition(dapp_contract, disputed_period, transition_index, agree_hash, logs)
    local machine = cartesi.machine
    local uarch_cycle = transition_index & (UARCH_CYCLES_PER_MCYCLE - 1)
    local hash = agree_hash
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
-- proof against either one binds them both. The standard proof verifies against the claim root.
local function wait_for_agreed_hash(m, tournament, leaf_index)
    if leaf_index == 0 then
        return tournament.initial_hash
    end
    for _, claim in ipairs({ m.one, m.two }) do
        local conns = server:subscribers({ hex(claim.root) })
        local move = server:accept_first(conns, "Proof", function(v)
            return valid_claim_proof(v, leaf_index - 1, tournament.height, claim.root) and v
        end, 'return player:prove("%s", %d)', hex(claim.root), leaf_index - 1)
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
local function settle_uarch_match(tournament, m, transition_index, agree_hash, d1, d2)
    local disputed_period = tournament.disputed_period
    story.transition_opened(tournament, m, transition_index)
    local conns = server:subscribers({ hex(m.one.root), hex(m.two.root) })
    local hash = server:accept_first(
        conns,
        "Logs",
        function(v)
            return verify_transition(tournament.dapp_contract, disputed_period, transition_index, agree_hash, v)
        end,
        "return player:transition_logs(%d, %d, %d)",
        disputed_period.input_index,
        disputed_period.period_index,
        transition_index
    )
    local winner = hash == d1 and m.one or hash == d2 and m.two or nil
    story.transition_settled(m, hash, winner, d1, d2)
    return winner
end
-- docs:end settle_uarch_match

-- Forward declaration: settling an mcycle match spawns a uarch tournament, which runs
-- matches, which settle against the machine.
local run_tournament

-- Opens the uarch tournament of an mcycle match over the period its claims part ways on, to
-- the holders of the two claims, and returns it with the claims it seals with: the valid
-- submissions whose final state is one of the two contested values, the same restriction
-- validContestedFinalState imposes on chain.
-- docs:begin open_uarch_tournament
local function open_uarch_tournament(parent, m, disputed_period, agree_hash, d1, d2)
    local submissions = server:open_tournament(
        m.tag,
        server:subscribers({ hex(m.one.root), hex(m.two.root) }),
        "Join",
        'return player:commit_uarch_claim(%d, %d, "%s", "%s")',
        disputed_period.input_index,
        disputed_period.period_index,
        hex(d1),
        hex(d2)
    )
    local claims = distinct_claims(submissions, UARCH_HEIGHT, function(claim)
        return claim.final_state == d1 or claim.final_state == d2
    end)
    story.claims_joined(m.tag, claims)
    return {
        level = "uarch",
        tag = m.tag,
        height = UARCH_HEIGHT,
        initial_hash = agree_hash,
        dapp_contract = parent.dapp_contract,
        disputed_period = disputed_period,
        settle = settle_uarch_match,
        claims = claims,
    }
end
-- docs:end open_uarch_tournament

-- Settles an mcycle match once the walk isolates the divergent leaf: the two claims part
-- ways over what the state hash was after one period of one input. A uarch tournament opens
-- over that period, its holders submit uarch claims, and the uarch winner's final state names
-- the mcycle claim that survives.
-- docs:begin settle_mcycle_match
local function settle_mcycle_match(tournament, m, epoch_period_index, agree_hash, d1, d2)
    local disputed_period = {
        input_index = epoch_period_index // PERIODS_PER_INPUT,
        period_index = epoch_period_index % PERIODS_PER_INPUT,
    }
    story.uarch_tournament_opened(m, disputed_period, agree_hash)
    local uarch_tournament = open_uarch_tournament(tournament, m, disputed_period, agree_hash, d1, d2)
    local uarch_winner = run_tournament(uarch_tournament)
    local survivor = uarch_winner and (uarch_winner.final_state == d1 and m.one or m.two)
    story.uarch_tournament_settled(m, uarch_winner, survivor)
    return survivor
end
-- docs:end settle_mcycle_match

-- Settles the dispute a match walk isolated: recovers the agreed state before the divergent
-- leaf, when the walk did not expose it, and hands the dispute to the tournament's settle.
-- docs:begin settle_dispute
local function settle_dispute(tournament, m, dispute)
    local agree_hash = dispute.agreed or wait_for_agreed_hash(m, tournament, dispute.leaf_index)
    story.dispute_isolated(m, dispute, agree_hash)
    if not agree_hash then
        return nil
    end
    return tournament.settle(tournament, m, dispute.leaf_index, agree_hash, dispute.d1, dispute.d2)
end
-- docs:end settle_dispute

-- Runs one match to its end and returns the winning claim, or nil when both die. Each round
-- asks the holders of the on-turn claim to open its node, and the walk advances on the first
-- move that validates. A claim nobody opens loses by default.
-- docs:begin run_match
local function run_match(tournament, m)
    while true do
        local conns = server:subscribers({ hex(m.turn.root) })
        local move = server:accept_first(conns, "Advance", function(v)
            return valid_move(m, v) and v
        end, 'return player:advance("%s", %d, %d, "%s")', hex(m.turn.root), m.height, m.index, hex(m.left_node))
        if not move then
            story.default_win(m)
            return m.other
        end
        local dispute = advance_match(m, move)
        if dispute then
            return settle_dispute(tournament, m, dispute)
        end
        story.match_advanced(m)
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
        dispatcher:spawn(function()
            results[slot] = task()
            pending = pending - 1
            dispatcher:schedule(main, "task_done")
        end)
    end
    while pending > 0 do
        dispatcher:wake_when_scheduled()
    end
    return results
end

-- Names a new match of a tournament: the tournament's name followed by the match's number in
-- it. The mcycle tournament's matches are match_1, match_2, and so on, narrated as 1, 2, and so
-- on, and the matches of the uarch tournament match_1 opens are match_1_1, match_1_2, and so
-- on, narrated as 1.1, 1.2, and so on. A match's name is fixed by its place in the bracket, so
-- it is the same on every run.
local function name_match(tournament)
    tournament.match_count = (tournament.match_count or 0) + 1
    local tag =
        string.format("%s_%d", tournament.level == "uarch" and tournament.tag or "match", tournament.match_count)
    return tag, (tag:sub(#"match_" + 1):gsub("_", "."))
end

-- Pairs the surviving claims two by two into the matches of a round, in bracket order.
local function pair_claims(tournament, claims, round)
    local matches = {}
    for i = 1, #claims - 1, 2 do
        local m = new_match(claims[i], claims[i + 1], tournament.height)
        m.tag, m.id = name_match(tournament)
        story.match_opened(tournament, round, m)
        matches[#matches + 1] = m
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
    local tasks = {}
    for slot, m in ipairs(matches) do
        tasks[slot] = function()
            return run_match(tournament, m)
        end
    end
    local results, winners = run_all(tasks), {}
    story.round_settled(tournament, claims, round, matches, results)
    for slot = 1, #matches do
        local winner = results[slot]
        if winner then
            winners[#winners + 1] = winner
        end
    end
    if #claims % 2 == 1 then
        winners[#winners + 1] = claims[#claims]
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

-- Opens the mcycle tournament to every player that connects until the sealer seals it, and
-- returns it with the distinct claims it seals with, sorted so the bracket is a pure function
-- of the claim set. The referee never needs to know the player count: the tournament closes
-- once it is sealed and every player it asked has submitted or closed.
-- docs:begin open_mcycle_tournament
local function open_mcycle_tournament(referee, dapp_contract)
    local submissions = server:open_tournament("tournament", nil, "Join", "return player:join()")
    local claims = distinct_claims(submissions, MCYCLE_HEIGHT)
    story.claims_joined("claims", claims)
    return {
        level = "mcycle",
        tag = "tournament",
        height = MCYCLE_HEIGHT,
        initial_hash = referee.initial_hash,
        dapp_contract = dapp_contract,
        settle = settle_mcycle_match,
        claims = claims,
    }
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
    story.tournament_winner(winner)
    local conns = server:subscribers({ hex(winner.root) })
    local result = server:accept_first(conns, "EpochResult", function(v)
        return verify_result(v, winner.final_state) and v
    end, "return player:prove_result()")
    assert(result, "no result proved against the winning final state")
    story.result_posted(result)
    server:collect(nil, nil, "return player:finish()")
end
-- docs:end wait_for_result

-- Seen from the referee, the whole game is short. It opens the mcycle tournament, reduces the
-- claims it seals with to the one that survives every match, and settles the epoch on its
-- result. The mcycle tournament packs what the reduction needs: the agreed initial state hash,
-- the dapp contract whose inputs verification trusts, and the way its matches settle.
-- Everything hard, the accept loop, the wire, the coroutine scheduling, runs underneath, in
-- the referee server this is handed to.
-- docs:begin run_referee
local function run_referee(referee, dapp_contract)
    local winner = run_tournament(open_mcycle_tournament(referee, dapp_contract))
    assert(winner, "the tournament ended with no winner")
    wait_for_result(winner)
end
-- docs:end run_referee

-- Models application deployment, returning the contract context the referee works against. The
-- epoch's inputs are all posted to the blockchain, so the contract holds its own copy of
-- every one, the copy that verification trusts over anything a player commits.
local function deploy(inputs)
    return { inputs = inputs }
end

-- The referee, standing in for the Dave contracts. It holds only what the blockchain would: the
-- agreed initial state hash (the template's own root hash, what a freshly deployed application
-- looks like on chain), the deployed dapp contract, and, during a match, one node hash per side
-- of the walk. Its server hides the accept loop, the wire, and the coroutine scheduling; run()
-- drives run_referee inside it, against the dapp contract it is handed.
local function new_referee(server_address)
    local host, port = server_address:match("^(.-):(%d+)$")
    local listener = assert(socket.bind(host, tonumber(port)))
    dispatcher = prtu.new_dispatcher()
    server = prtu.new_server(dispatcher, listener)
    server:accept()
    return {
        initial_hash = cartesi.machine(prt_player.TEMPLATE):get_root_hash(),
        run = function(self, dapp_contract)
            server:run(function()
                run_referee(self, dapp_contract)
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
    local dapp_contract = deploy(read_inputs(4))
    local referee = new_referee(server_address)
    referee:run(dapp_contract)
elseif role == "honest" then
    prtu.serve(prt_player.new_player("honest", read_inputs(4)), server_address)
elseif role == "quitter" then
    local player = prt_player.new_player("quitter", {})
    prt_player.make_quitter(player)
    prtu.serve(player, server_address)
elseif role == "forger" then
    local index = assert(tonumber(arg[4]), "missing forged input index")
    local forged = read_input(assert(arg[5], "missing forged input file"))
    local player = prt_player.new_player("forger", read_inputs(6))
    prt_player.make_forger(player, index, forged)
    prtu.serve(player, server_address)
elseif role == "tamperer" then
    local input_index = assert(tonumber(arg[4]), "missing tampered input index")
    local entry_offset = assert(tonumber(arg[5]), "missing tamper entry offset")
    local player = prt_player.new_player("tamperer", read_inputs(6))
    prt_player.make_tamperer(player, input_index, entry_offset)
    prtu.serve(player, server_address)
elseif role == "fabulist" then
    local input_index = assert(tonumber(arg[4]), "missing lied-about input index")
    local leaf_offset = assert(tonumber(arg[5]), "missing lied-about leaf offset")
    local player = prt_player.new_player("fabulist", read_inputs(6))
    prt_player.make_fabulist(player, input_index, leaf_offset)
    prtu.serve(player, server_address)
else
    error("unknown role: " .. role)
end
