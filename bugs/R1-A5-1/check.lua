-- R1-A5-1 check (run by test.sh from a temporary directory holding wallets/, with PRT_RPC_URL pointing at a
-- private anvil and PRT_DAVE_DIR at the RELEASED Dave build).
--
-- Deploys the pinned Dave v3.0.0-alpha.7 contracts (with the cartesi-rollups-contracts 3.0.0-alpha.10
-- Application, guardian = deployer, as doc/recipes/prt-deploy.lua does) for a bare-metal rolling template whose
-- application emits one voucher per advance-state input. Settles empty epoch 0, seals epoch 1 over one input,
-- lets the honest player's claim win epoch 1's root tournament unopposed and stages the result with a valid
-- machine validity proof. From that point (snapshot) it runs two branches:
--   control: the staging period elapses, acceptStagedTournamentResult succeeds, the voucher's valid output
--            proof validates and executeOutput succeeds;
--   foreclosed: same, except the guardian calls Application.foreclose() right after staging.
-- A5 requires, in the foreclosed branch too: "the referee accepts every output that the settled state commits
-- to, whenever its valid proof is presented. No party can make it stop accepting them."
-- Exit 1 if the foreclosed branch refuses the settled state's output, 0 if it accepts it, 2 on setup errors
-- (including a control branch that does not accept the output).
local harness = require("harness")
harness.main(function()
    local cartesi = require("cartesi")
    local evmu = require("cartesi.evmu")
    local json = require("dkjson")
    local eth = require("prt-ethereum")
    local fs = require("cartesi.filesystem")
    local rpc_client = require("prt-rpc")
    local signing = require("prt-signer")
    local prt = require("prt")
    local prt_deploy = require("prt-deploy")

    local guest = assert(arg[1], "missing guest.bin path")
    local rpc = assert(os.getenv("PRT_RPC_URL"), "PRT_RPC_URL not set")

    -- Template: the guest at its first manual yield, accepted, with the empty outputs root (a valid template).
    local template_dir = "template"
    do
        local m <close> = cartesi.machine({ ram = { length = 64 << 20, backing_store = { data_filename = guest } } })
        if m:run(math.maxinteger) ~= cartesi.BREAK_REASON_YIELDED_MANUALLY then
            harness.setup_error("guest did not yield manually")
        end
        if (m:read_reg("htif_tohost") >> 32) & 0xffff ~= cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
            harness.setup_error("guest did not accept")
        end
        m:store(template_dir)
    end
    local template_hash
    do
        local m <close> = cartesi.new()
        m:load(template_dir, { clear_hash_tree = true })
        template_hash = m:get_root_hash()
    end
    print("template hash " .. cartesi.tohex(template_hash))

    local chain = rpc_client.new(rpc)
    local deployment = prt_deploy.deploy(chain, cartesi.tohex(template_hash))
    local geometry, consensus, app = deployment.geometry, deployment.consensus, deployment.app
    local rollups_out = prt_deploy.dave_directory .. "/cartesi-rollups/contracts/out"
    local prt_out = prt_deploy.dave_directory .. "/prt/contracts/out"
    local abi = eth.abi({
        eth.artifact(prt_out, "Tournament"),
        eth.artifact(prt_out, "MultiLevelTournamentFactory"),
        eth.artifact(rollups_out, "InputBox"),
        eth.artifact(rollups_out, "DaveConsensus"),
        eth.artifact(rollups_out, "DaveAppFactory"),
        (eth.artifact(rollups_out, "Application")),
    })
    local guardian = deployment.deployer
    local claimant = prt_deploy.signer(1)
    local executor = prt_deploy.signer(2)

    local guardian_on_chain = evmu.decode_abi("(address)",
        assert(eth.raw(assert(chain:call(app, abi:calldata("getGuardian", {}))))))[1]
    print("application " .. app .. ", consensus " .. consensus .. ", guardian " .. tostring(guardian_on_chain))
    if tostring(guardian_on_chain):lower() ~= guardian.address:lower() then
        harness.setup_error("guardian is not the deployer")
    end

    local function mine_to(number)
        local tip = chain:head()
        if number > tip then
            assert(chain:rpc("anvil_mine", { string.format("0x%x", number - tip) }))
        end
    end
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
    local function must_send(signer, to, name, args, value)
        local receipt, failure = signing.send(chain, signer, to, abi:calldata(name, args), value)
        if not receipt then
            harness.setup_error(name .. " failed: " .. json.encode(failure))
        end
        return receipt
    end
    local known_errors = {
        ["0x01f89e1a"] = "ApplicationForeclosed(address)",
        ["0x44a192ff"] = "InvalidOutputsMerkleRoot(bytes32)",
        ["0x3f68df47"] = "Foreclosed()",
    }
    local function describe(failure)
        local data = type(failure) == "table" and type(failure.data) == "string" and failure.data or ""
        local name = known_errors[data:sub(1, 10)]
        return (name and (name .. " ") or "") .. json.encode(failure)
    end
    local function try_send(signer, to, name, args)
        local receipt, failure = signing.send(chain, signer, to, abi:calldata(name, args))
        return receipt ~= nil, failure
    end
    local function try_call(to, name, args)
        local value, failure = chain:call(to, abi:calldata(name, args))
        return value ~= nil, failure
    end
    local function tournament_of(sealed_event)
        for _, event in ipairs(get_events(deployment.factory, "TournamentCreated")) do
            if event.tournament == sealed_event.tournament then
                return event
            end
        end
        harness.setup_error("tournament creation event missing")
    end
    local function win_unopposed(creation, claim)
        must_send(claimant, creation.tournament, "joinTournament", {
            claim.final_state,
            claim.proof,
            claim.children[1],
            claim.children[2],
        }, tostring(creation.bondValue))
        mine_to(eth.small(creation.descriptor.startInstant) + eth.small(creation.descriptor.allowance))
    end

    -- Epoch 0: empty, settled by the bootstrap player's claim (as doc/recipes/prt-proof-test.lua does).
    for _, directory in ipairs({ "epoch-0", "epoch-1" }) do
        fs.create_directory(directory)
    end
    local sealed = get_events(consensus, "EpochSealed")
    if not (#sealed == 1 and eth.small(sealed[1].epochNumber) == 0) then
        harness.setup_error("epoch 0 not sealed at deployment")
    end
    do
        local bootstrap <close> = prt.new_stored_player(
            { initial_state_hash = template_hash, geometry = geometry, machine_directory = template_dir },
            "bootstrap", nil, "epoch-0", "checkpoint-1")
        bootstrap.event_handler.epoch_sealed(bootstrap, 0)
        local claim = eth.claim(bootstrap.event_handler.commit_mcycle_claim(bootstrap), geometry.mcycle_height)
        must_send(deployment.deployer, deployment.input_box, "addInput", { app, eth.hex("hello") })
        win_unopposed(tournament_of(sealed[1]), claim)
        local outputs_proof = bootstrap.event_handler.prove_outputs_merkle_root(bootstrap)
        must_send(claimant, consensus, "stageTournamentResult",
            { sealed[1].epochNumber, eth.validity_proof(outputs_proof, claim.final_state) })
        mine_to(chain:head() + deployment.staging_period)
        must_send(claimant, consensus, "acceptStagedTournamentResult", { sealed[1].epochNumber })
    end
    sealed = get_events(consensus, "EpochSealed")
    if not (#sealed == 2 and eth.small(sealed[2].inputIndexUpperBound) == 1) then
        harness.setup_error("epoch 1 was not sealed over the one input")
    end
    print("epoch 0 settled; epoch 1 sealed over input 0")

    -- Epoch 1: the honest player processes input 0 (one voucher), its claim wins, the result is staged.
    local dapp, outputs_frontier = prt.load_epoch_checkpoint("checkpoint-1")
    local player <close> = prt.new_stored_player(dapp, "honest", outputs_frontier, "epoch-1")
    for _, event in ipairs(get_events(deployment.input_box, "InputAdded")) do
        if event.appContract == app then
            local index = eth.small(event.index)
            local path = "input-" .. index .. ".bin"
            fs.write_file(assert(eth.raw(event.input)), path)
            player.event_handler.input_added(player, index, path)
        end
    end
    player.event_handler.epoch_sealed(player, 1)
    local claim = eth.claim(player.event_handler.commit_mcycle_claim(player), geometry.mcycle_height)
    win_unopposed(tournament_of(sealed[2]), claim)
    local outputs_proof = player.event_handler.prove_outputs_merkle_root(player)
    local epoch1 = sealed[2].epochNumber
    must_send(claimant, consensus, "stageTournamentResult",
        { epoch1, eth.validity_proof(outputs_proof, claim.final_state) })
    local staged_root = eth.hex(outputs_proof.tx_buffer_data)
    print("epoch 1 tournament won by the honest claim, final state " .. claim.final_state ..
        ", staged outputs root " .. staged_root)

    local output = player.event_handler.prove_output(player)
    if output == "nothing" or type(output) ~= "table" then
        harness.setup_error("the player has no output to prove")
    end
    if eth.hex(output.output_proof.root_hash) ~= staged_root then
        harness.setup_error("output proof root differs from the staged outputs root")
    end
    local output_data = eth.hex(output.output_data)
    local output_proof = { output.output_index, eth.siblings(output.output_proof) }
    print(string.format("voucher at index %d: %s", output.output_index, output_data))

    local function settle_and_use(label)
        mine_to(chain:head() + deployment.staging_period)
        local accepted, accept_failure = try_send(claimant, consensus, "acceptStagedTournamentResult", { epoch1 })
        local validated, validate_failure = try_call(app, "validateOutput", { output_data, output_proof })
        local executed, execute_failure = try_send(executor, app, "executeOutput", { output_data, output_proof })
        print(string.format("%s: acceptStagedTournamentResult %s%s", label, accepted and "ok" or "REVERTED ",
            accepted and "" or describe(accept_failure)))
        print(string.format("%s: validateOutput(voucher) %s%s", label, validated and "ok" or "REVERTED ",
            validated and "" or describe(validate_failure)))
        print(string.format("%s: executeOutput(voucher) %s%s", label, executed and "ok" or "REVERTED ",
            executed and "" or describe(execute_failure)))
        return accepted and validated and executed
    end

    local snapshot = assert(chain:rpc("evm_snapshot", {}))

    -- Control: without foreclosure the settled state's voucher is accepted and executed.
    if not settle_and_use("control (no foreclosure)") then
        harness.setup_error("control branch does not accept the voucher of the settled state")
    end
    if not chain:rpc("evm_revert", { snapshot }) then
        harness.setup_error("evm_revert failed")
    end

    -- Foreclosed: the guardian forecloses the application after the tournament settled and the result was
    -- staged, before acceptance.
    must_send(guardian, app, "foreclose", {})
    local foreclosed = evmu.decode_abi("(bool)", assert(eth.raw(assert(chain:call(app, abi:calldata("isForeclosed", {}))))))[1]
    print("guardian called foreclose(); isForeclosed = " .. tostring(foreclosed))
    local ok = settle_and_use("foreclosed")

    return harness.expect(ok,
        "A5: 'the referee accepts every output that the settled state commits to, whenever its valid proof is " ..
        "presented. No party can make it stop accepting them.' After the guardian's foreclose(), the winner of " ..
        "epoch 1's tournament can no longer be accepted and its voucher's valid proof is refused " ..
        "(reading assumed: the guardian is a 'party' under A5)")
end)
