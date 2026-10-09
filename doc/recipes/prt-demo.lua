-- Stream both calculator epochs through Dave, preserving normal empty epoch zero.
local evmu = require("cartesi.evmu")
local cartesi = require("cartesi")
local util = require("cartesi.util")
local json = require("dkjson")
local cast = require("prt-cast")
local eth = require("prt-ethereum")
local prt = require("prt")
local dishonest = require("prt-dishonest")
local epoch = require("prt-epoch")
local hash_tree = require("cartesi.hash-tree")
local initial_hash = assert(arg[1], "missing template hash")
assert(#assert(eth.raw(initial_hash)) == 32, "invalid template hash")
local mode = arg[2] or "story"
local chain = cast.new("http://127.0.0.1:8545")
local zero_address = "0x" .. string.rep("00", 20)
local prt_out = "/opt/dave/prt/contracts/out"
local rollups_out = "/opt/dave/cartesi-rollups/contracts/out"
local artifacts = {}
local function artifact(name, directory)
    local result = eth.artifact(directory or prt_out, name)
    artifacts[name] = result
    return result
end

local function signer(index)
    local key = "wallets/player-" .. index
    local address = cast.run({ "cast", "wallet", "address", "--keystore", key, "--password-file", "wallets/password" })
        :gsub("%s+$", "")
        :lower()
    return { address = address, keystore = key, password_file = "wallets/password" }
end
local deployer = signer(0)
local function deploy(name, directory, types, args)
    local compiled = artifact(name, directory)
    local code = compiled.bytecode.object
    assert(code:match("^0x%x+$"), "unlinked creation code for " .. name)
    if types then
        code = code .. eth.hex(evmu.encode_abi(types, args)):sub(3)
    end
    io.stderr:write("Deploying ", name, "\n")
    local receipt, failure = chain:send(deployer, nil, code)
    assert(receipt, failure and json.encode(failure))
    return assert(receipt.contractAddress):lower(), receipt
end
local implementation = deploy("Tournament")
local stf = deploy("CartesiStateTransition")
local encoded_hash = assert(chain:call(stf, evmu.encode_calldata_hex("UARCH_PRISTINE_STATE_HASH()", {})))
assert(encoded_hash == eth.hex(cartesi.UARCH_PRISTINE_STATE_HASH), "emulator and Solidity pristine uarch hashes differ")
local provider = deploy("CanonicalTournamentParametersProvider", nil, "(uint64,uint64,uint64)", { 1000, 10000, 2 })
local factory =
    deploy("MultiLevelTournamentFactory", nil, "(address,address,address)", { implementation, provider, stf })
local input_box = deploy("InputBox", rollups_out)
local application_factory = deploy("ApplicationFactory", rollups_out, "(address)", { zero_address })
artifact("DaveConsensus", rollups_out)
local dave_factory =
    deploy("DaveAppFactory", rollups_out, "(address,address,address)", { input_box, application_factory, factory })
local abi = eth.abi({
    artifacts.Tournament,
    artifacts.MultiLevelTournamentFactory,
    artifacts.InputBox,
    artifacts.DaveConsensus,
    artifacts.DaveAppFactory,
})
local receipt, failure = chain:send(
    deployer,
    dave_factory,
    abi:calldata("newDaveApp", {
        initial_hash,
        10,
        deployer.address,
        {},
        { deployer.address, 0, 0, 0, zero_address },
        eth.zero,
    })
)
assert(receipt, failure and json.encode(failure))
local app, consensus
for _, log in ipairs(receipt.logs) do
    local event = abi:event(log)
    if event and event.name == "DaveAppCreated" then
        app, consensus = event.appContract, event.daveConsensus
    end
end
assert(app and consensus, "application deployment event missing")
local staging_period = eth.small(
    evmu.decode_abi(
        "(uint256)",
        assert(eth.raw(assert(chain:call(consensus, abi:calldata("getClaimStagingPeriod", {})))))
    )[1]
)
util.write_file(
    json.encode({
        factory = factory,
        input_box = input_box,
        app = app,
        consensus = consensus,
        initial_hash = initial_hash,
        uarch_pristine_hash = encoded_hash,
    }, { indent = true }),
    "deployment.json"
)

local sessions = {}
local function close_players()
    for _, session in ipairs(sessions) do
        for _, actor in ipairs(session.actors) do
            getmetatable(actor.player).__close(actor.player)
        end
    end
end
local _ <close> = setmetatable({}, { __close = close_players })
local function open_epoch(number, previous)
    local dapp, last_proof, manifest
    if previous then
        assert(number == previous.epoch + 1, "epochs are not consecutive")
        dapp, last_proof, manifest = prt.load_epoch(previous.directory .. "/checkpoint")
    else
        dapp = { initial_state_hash = assert(eth.raw(initial_hash)), geometry = prt.new_geometry(10) }
    end
    local actors = {}
    local directory = "epoch-" .. number
    local function add(label, player, checkpoint_directory)
        actors[#actors + 1] = {
            label = label,
            player = player,
            signer = signer(#actors + 1),
            claims = {},
            directory = directory,
            checkpoint_directory = checkpoint_directory,
        }
        return actors[#actors]
    end
    if number > 0 and mode ~= "smoke" then
        add("quitter", dishonest.new_quitter(dapp, "quitter", last_proof))
        add("tamperer", dishonest.new_tamperer(dapp, 0, 100, "tamperer", last_proof))
        add("fabulist", dishonest.new_fabulist(dapp, 2, 2000, "fabulist", last_proof))
        add("fixed_fabulist", dishonest.new_fabulist(dapp, 2, 60000, "fixed_fabulist", last_proof))
        add("forger", dishonest.new_forger(dapp, 2, "forged-input-2.bin", "forger", last_proof))
    end
    local honest = prt.new_player(dapp, "honest", last_proof)
    local honest_actor = add("honest", honest, directory .. "/checkpoint")
    if number > 0 and mode ~= "smoke" then
        add("quitter_1", dishonest.new_quitter(dapp, "quitter 1", last_proof))
        add("quitter_2", dishonest.new_quitter(dapp, "quitter 2", last_proof))
    end
    local session = epoch.new({
        chain = chain,
        abi = abi,
        app = app,
        input_box = input_box,
        consensus = consensus,
        factory = factory,
        epoch = number,
        input_begin = previous and previous.input_begin + #previous.input_paths or 0,
        initial_hash = eth.hex(dapp.initial_state_hash),
        previous_outputs_root = manifest and manifest.outputs_root or eth.zero,
        actors = actors,
        cleaner = { label = "keeper", signer = deployer },
        directory = directory,
        claim_staging_period = staging_period,
    })
    session.honest_actor = honest_actor
    sessions[#sessions + 1] = session
    return session
end

local function claim_label(session, address, commitment)
    if commitment == eth.zero then
        return "none"
    end
    for _, actor in ipairs(session.actors) do
        if actor.claims[address] and actor.claims[address].root == commitment then
            return actor.label
        end
    end
    return commitment:sub(1, 14)
end
local function narrate(session, snapshot)
    local reasons = { "by a verified state transition", "by timeout", "by the child tournament result" }
    local lines =
        { "Epoch " .. session.epoch .. (session.epoch == 0 and " (empty bootstrap)" or " (calculator)") .. "\n" }
    for _, input in ipairs(session.inputs) do
        lines[#lines + 1] = "Block "
            .. input.block
            .. ": input "
            .. input.index
            .. " processed while the epoch was open.\n"
    end
    lines[#lines + 1] = "Block "
        .. eth.small(session.seal.log.blockNumber)
        .. ": epoch sealed; player checkpoint saved.\n"
    for _, event in ipairs(snapshot.events) do
        local prefix = "Block " .. eth.small(event.log.blockNumber) .. ": "
        if event.name == "CommitmentJoined" then
            lines[#lines + 1] = prefix
                .. claim_label(session, event.address, event.commitment)
                .. " joins "
                .. event.address
                .. ".\n"
        elseif event.name == "MatchCreated" then
            lines[#lines + 1] = prefix
                .. claim_label(session, event.address, event.one)
                .. " meets "
                .. claim_label(session, event.address, event.two)
                .. ".\n"
        elseif event.name == "NewInnerTournament" then
            local input, period = eth.coordinates(event.descriptor.baseCycle)
            lines[#lines + 1] = prefix
                .. "A uarch tournament opens over local input "
                .. input
                .. ", period "
                .. period
                .. ".\n"
        elseif event.name == "LeafMatchSealed" then
            lines[#lines + 1] = prefix
                .. "The leaf match isolates transition "
                .. tostring(event.divergencePosition)
                .. ".\n"
        elseif event.name == "MatchDeleted" then
            local winner = eth.small(event.winnerCommitment)
            local label = winner == 0 and "both claims eliminated"
                or (claim_label(session, event.address, winner == 1 and event.one or event.two) .. " wins")
            lines[#lines + 1] = prefix .. label .. " " .. assert(reasons[eth.small(event.reason) + 1]) .. ".\n"
        elseif event.name == "EpochStaged" and eth.small(event.epochNumber) == session.epoch then
            lines[#lines + 1] = prefix .. "The consensus stages the proven epoch result.\n"
        elseif event.name == "BondRecovered" then
            lines[#lines + 1] = prefix
                .. claim_label(session, event.address, event.commitment)
                .. " recovers its winning bond.\n"
        end
    end
    if snapshot.settled then
        lines[#lines + 1] = "Block "
            .. eth.small(snapshot.settled.log.blockNumber)
            .. ": result accepted; epoch "
            .. (session.epoch + 1)
            .. " sealed.\n"
    end
    util.write_file(table.concat(lines), session.directory .. "/story.txt")
    util.write_file(json.encode(snapshot.logs, { indent = true }), session.directory .. "/chain-logs.json")
end

local function play(session, accumulating)
    local coordinator = assert(session.dispute)
    if session.epoch > 0 then
        require("prt-proof-test")(
            chain,
            stf,
            consensus,
            session.honest_actor.player,
            session.input_paths,
            session.directory
        )
    end
    for tick = 1, 10000 do
        local snapshot, progressed, next_block = coordinator:tick()
        narrate(session, snapshot)
        if accumulating then
            accumulating:poll()
        end
        if not progressed then
            local standing = snapshot.contexts[coordinator.root].standing
            if snapshot.settled and snapshot.recovered[coordinator.root] then
                assert(
                    standing and standing.dangling == session.honest_actor.claims[coordinator.root].root,
                    "winning commitment differs from the honest claim"
                )
                local _, _, manifest = prt.load_epoch(session.directory .. "/checkpoint")
                assert(
                    snapshot.settled.initialMachineStateHash == manifest.final_state_hash,
                    "settled machine differs from checkpoint"
                )
                assert(
                    snapshot.settled.outputsMerkleRoot == manifest.outputs_root,
                    "settled outputs differ from checkpoint"
                )
                io.stderr:write(
                    "Epoch ",
                    session.epoch,
                    ": accepted and bonds recovered after ",
                    tick,
                    " observations.\n"
                )
                return
            end
            assert(not coordinator.terminal, coordinator.terminal)
            assert(next_block and next_block > snapshot.head + 1, "bridge idle without a future action")
            assert(chain:rpc("anvil_mine", { string.format("0x%x", next_block - snapshot.head - 1) }))
        end
    end
    error("epoch exceeded the observation limit")
end

local function post_inputs(session, expressions)
    for _, expression in ipairs(expressions) do
        local submitted, err =
            chain:send(deployer, input_box, abi:calldata("addInput", { app, eth.hex(expression .. "\n") }))
        assert(submitted, err and json.encode(err))
        local count = #session.input_paths
        session:poll()
        assert(not session.dispute and #session.input_paths == count + 1, "input was not processed before sealing")
    end
end

local bootstrap = open_epoch(0)
assert(bootstrap:poll(), "missing bootstrap seal")
local first = open_epoch(1, bootstrap)
post_inputs(first, { "6*2^1024 + 3*2^512", "invalid input", "2^2048" })
play(bootstrap, first)
assert(first.dispute, "epoch one was not sealed")
local second = open_epoch(2, first)
post_inputs(second, { "(2^256 - 1) * (2^256 - 1)", "scale=80; sqrt(2)", "scale=100; 355/113" })
play(first, second)
assert(second.dispute, "epoch two was not sealed")
play(second)

-- Loading the final checkpoint in a fresh player also covers a subsequent epoch
-- with no new outputs: its inherited last-output proof must survive sealing.
local dapp, proof, manifest = prt.load_epoch(second.directory .. "/checkpoint")
assert(manifest.output_count == 5 and proof.target_address == 4, "calculator output history did not continue")
local resumed <close> = prt.new_player(dapp, "checkpoint validation", proof)
resumed.event_handler.epoch_sealed(resumed, 0, "continuation-checkpoint")
local _, retained, continued = prt.load_epoch("continuation-checkpoint")
assert(continued.final_state_hash == manifest.final_state_hash and retained.root_hash == proof.root_hash)
local stories = { "Two calculator epochs on Anvil, using the normal empty epoch zero.\n\n" }
for _, session in ipairs(sessions) do
    stories[#stories + 1] = util.read_file(session.directory .. "/story.txt") .. "\n"
    for _, response in ipairs(session.honest_actor.player.output_proofs) do
        hash_tree.verify_slice(response)
    end
end
util.write_file(table.concat(stories), "story.txt")
print(table.concat(stories))
print("Both calculator epochs accepted; checkpoints preserve outputs 0 through 4.")
