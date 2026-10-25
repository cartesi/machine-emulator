-- Deploys Dave's contracts and a Dave application for a template on the local chain, from the
-- deployer account. The demo and the proof test share it.
local evmu = require("cartesi.evmu")
local cartesi = require("cartesi")
local json = require("dkjson")
local cast = require("prt-cast")
local eth = require("prt-ethereum")
local bridge = require("prt-bridge")
local M = {}

local zero_address = "0x" .. string.rep("00", 20)
-- Dave's compiled contracts, as the PRT image installs them or as copied from it.
M.dave_directory = os.getenv("PRT_DAVE_DIR") or "/opt/dave"
local prt_out = M.dave_directory .. "/prt/contracts/out"
local rollups_out = M.dave_directory .. "/cartesi-rollups/contracts/out"

-- The account of the local wallet with this index. Index 0 is the deployer.
function M.signer(index)
    local key = "wallets/player-" .. index
    local address = cast.run({ "cast", "wallet", "address", "--keystore", key, "--password-file", "wallets/password" })
        :gsub("%s+$", "")
        :lower()
    return { address = address, keystore = key, password_file = "wallets/password" }
end

function M.deploy(chain, initial_hash)
    local deployer = M.signer(0)
    local artifacts = {}
    local function artifact(name, directory)
        local result = eth.artifact(directory or prt_out, name)
        artifacts[name] = result
        return result
    end
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
    assert(
        encoded_hash == eth.hex(cartesi.UARCH_PRISTINE_STATE_HASH),
        "emulator and Solidity pristine uarch hashes differ"
    )
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
    -- The players' geometry is the tournament factory's.
    local geometry = bridge.read_geometry(chain, abi, factory)
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
    return {
        deployer = deployer,
        abi = abi,
        geometry = geometry,
        stf = stf,
        factory = factory,
        input_box = input_box,
        app = app,
        consensus = consensus,
        staging_period = staging_period,
        uarch_pristine_hash = encoded_hash,
    }
end

return M
