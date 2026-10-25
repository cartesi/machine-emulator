-- Exercise the bridge encoder against the deployed state transition. The native verifier is the
-- independent result oracle. The state transition authenticates delivered inputs through the
-- consensus, which knows only the inputs of sealed epochs, so the test first settles empty epoch 0
-- with one unopposed honest player and seals epoch 1 over the calculator inputs.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local eth = require("prt-ethereum")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local json = require("dkjson")
local cast = require("prt-cast")
local prt = require("prt")
local prt_deploy = require("prt-deploy")

local function check(chain, transition, provider, player, paths, directory)
    local vectors = {
        { "input delivery", 0, 0, 0 },
        { "ordinary step", 0, 0, 1 },
        { "instruction reset", 0, 0, (1 << 20) - 1 },
        { "late period reset", 2, 2000, (1 << 30) - 1 },
        { "absent input", #paths, 0, 0 },
    }
    local results = {}
    for _, vector in ipairs(vectors) do
        local name, input, period, offset = table.unpack(vector)
        local cycle = (evmu.bint(input) << 68) + (evmu.bint(period) << 30) + offset
        local response = player.event_handler.prove_state_transition(player, input, period, offset)
        local first = (response.send_cmio_log or response.step_log).accesses[1]
        local before = eth.hex(hash_tree.roll_hash_up_tree({
            log2_root_size = 64,
            log2_target_size = math.max(first.log2_size, cartesi.HASH_TREE_LOG2_WORD_SIZE),
            target_address = first.address,
            sibling_hashes = first.sibling_hashes,
        }, first.read_hash))
        local input_data = paths[input + 1] and fs.read_file(paths[input + 1])
        local expected = eth.verify_transition(response, cycle, input_data, before)
        local proof = eth.transition_proof(response, cycle, input_data)
        local function call(candidate)
            return chain:call(
                transition,
                evmu.encode_calldata_hex(
                    "transitionState(bytes32,uint256,bytes,address)",
                    { before, cycle, candidate, provider }
                )
            )
        end
        local obtained, failure = call(proof)
        assert(obtained == expected, name .. ": Solidity differs from native: " .. json.encode(failure))
        -- Exact consumption and authentication must reject both length changes
        -- and corruption, including for otherwise valid no-op transitions.
        local raw = assert(eth.raw(proof))
        for _, malformed in ipairs({
            proof .. "00",
            proof:sub(1, -3),
            eth.hex(raw:sub(1, -2) .. string.char(raw:byte(-1) ~ 1)),
        }) do
            local value, err = call(malformed)
            assert(not value and err and err.code == 3, name .. ": malformed proof accepted")
        end
        results[#results + 1] = {
            name = name,
            cycle = tostring(cycle),
            before = before,
            after = obtained,
            proof_bytes = #raw,
            malformed_rejected = 3,
        }
    end
    local file <close> = assert(io.open((directory or ".") .. "/proof-vectors.json", "w"))
    assert(file:write(json.encode(results, { indent = true })))
    io.stderr:write("Native and Solidity verifiers agree on ", #results, " proof classes and malformed vectors.\n")
end

local initial_hash = assert(arg[1], "missing template hash")
local chain = cast.new(os.getenv("PRT_RPC_URL") or "http://127.0.0.1:8545")
local deployment = prt_deploy.deploy(chain, initial_hash)
local abi, geometry, consensus = deployment.abi, deployment.geometry, deployment.consensus
local claimant = prt_deploy.signer(1)

local function mine_to(number)
    local tip = chain:head()
    if number > tip then
        assert(chain:rpc("anvil_mine", { string.format("0x%x", number - tip) }))
    end
end

-- The decoded events of this name that an address emitted.
local function get_events(address, name)
    local events = {}
    for _, log in ipairs(chain:logs(address, (chain:head()))) do
        local event = abi:event(log)
        if event and event.name == name then
            events[#events + 1] = event
        end
    end
    return events
end

local function send(signer, to, name, args, value)
    local receipt, failure = chain:send(signer, to, abi:calldata(name, args), value)
    assert(receipt, failure and json.encode(failure))
    return receipt
end

-- Epoch 0 is empty, so its honest player seals at once, and its claim joins the root unopposed.
local sealed = get_events(consensus, "EpochSealed")
assert(#sealed == 1 and eth.small(sealed[1].epochNumber) == 0, "epoch 0 was not sealed at deployment")
local creation
for _, event in ipairs(get_events(deployment.factory, "TournamentCreated")) do
    if event.tournament == sealed[1].tournament then
        creation = event
    end
end
assert(creation, "root tournament creation missing")
local bootstrap <close> =
    prt.new_player({ initial_state_hash = assert(eth.raw(initial_hash)), geometry = geometry }, "bootstrap")
bootstrap.event_handler.epoch_sealed(bootstrap, 0, "checkpoint-1")
local claim = eth.claim(bootstrap.event_handler.commit_mcycle_claim(bootstrap), geometry.mcycle_height)
send(claimant, creation.tournament, "joinTournament", {
    claim.final_state,
    claim.proof,
    claim.children[1],
    claim.children[2],
}, tostring(creation.bondValue))
for _, expression in ipairs({ "6*2^1024 + 3*2^512", "invalid input", "2^2048" }) do
    send(deployment.deployer, deployment.input_box, "addInput", { deployment.app, eth.hex(expression .. "\n") })
end
-- The lone claim wins once the root's joining window closes. Accepting it seals epoch 1.
mine_to(eth.small(creation.descriptor.startInstant) + eth.small(creation.descriptor.allowance))
local outputs_proof = bootstrap.event_handler.prove_outputs_merkle_root(bootstrap)
send(claimant, consensus, "stageTournamentResult", {
    sealed[1].epochNumber,
    eth.validity_proof(outputs_proof, claim.final_state),
})
mine_to(chain:head() + deployment.staging_period)
send(claimant, consensus, "acceptStagedTournamentResult", { sealed[1].epochNumber })
sealed = get_events(consensus, "EpochSealed")
assert(
    #sealed == 2 and eth.small(sealed[2].inputIndexLowerBound) == 0 and eth.small(sealed[2].inputIndexUpperBound) == 3,
    "epoch 1 was not sealed over the three inputs"
)

-- Epoch 1's player starts from the bootstrap's checkpoint and processes the inputs the chain holds.
local dapp, outputs_frontier = prt.load_epoch("checkpoint-1")
local player <close> = prt.new_player(dapp, "honest", outputs_frontier)
local paths = {}
for _, event in ipairs(get_events(deployment.input_box, "InputAdded")) do
    if event.appContract == deployment.app then
        local index = eth.small(event.index)
        paths[index + 1] = "input-" .. index .. ".bin"
        fs.write_file(assert(eth.raw(event.input)), paths[index + 1])
        player.event_handler.input_added(player, index, paths[index + 1])
    end
end
player.event_handler.epoch_sealed(player, #paths, "checkpoint-2")
check(chain, deployment.stf, consensus, player, paths, ".")

-- Loading a checkpoint in a fresh player also covers a following epoch with no new outputs: its
-- inherited outputs frontier must survive sealing.
local next_dapp, next_outputs_frontier, manifest = prt.load_epoch("checkpoint-2")
assert(manifest.output_count > 0, "the calculator inputs produced no outputs")
local continued <close> = prt.new_player(next_dapp, "continuation", next_outputs_frontier)
continued.event_handler.epoch_sealed(continued, 0, "continuation-checkpoint")
local _, _, continuation = prt.load_epoch("continuation-checkpoint")
assert(
    continuation.final_state_hash == manifest.final_state_hash and continuation.outputs_root == manifest.outputs_root,
    "an epoch without outputs changed the checkpoint"
)
print("PRT proof tests passed.")
