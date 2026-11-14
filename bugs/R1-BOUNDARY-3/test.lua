-- R1-BOUNDARY-3: crisium's seal lookup (get_seal over seal_history) fetches, keeps and decodes every
-- consensus log since the deployment block, so restarting and opening each new epoch cost O(past epochs).
--
-- Runs the real doc/recipes/crisium.lua (with the real prt-log-history.lua and prt-ethereum.lua ABI decoding
-- of the pinned Dave artifacts) against an in-process mock chain. Only the transport (prt-rpc), the
-- checkpoint loader and player (prt), the epoch listener (prt-epoch), the bridge's geometry reader and the
-- websocket module are stubbed; none of them takes part in get_seal.
--
-- For E past epochs, the consensus holds EpochSealed(k) for k = 0..E-1 and EpochStaged(k) for k = 0..E-2. The
-- player restarts from checkpoint epoch-E (the honest player keeps only the newest checkpoints), which needs
-- the seal of epoch E-1 (phase "restart"); then epoch E is sealed and checkpoint epoch-(E+1) appears, and the
-- player opens epoch E+1 (phase "new epoch"). In each phase the test counts the consensus logs that
-- eth_getLogs hands to the player and the logs the player decodes. R12 requires both to be independent of E.
--
-- Usage: bugs/run.sh R1-BOUNDARY-3 [E_small E_large]   (default 2 200)
-- CRISIUM_LUA=<file> runs another copy of crisium.lua (to check a candidate fix).
local harness = require("harness")

harness.main(function()
    local repo = assert(os.getenv("REPO"), "REPO not set (run through bugs/run.sh)")
    local recipes = os.getenv("RECIPES_DIR") or (repo .. "/doc/recipes")
    local dave = os.getenv("HARNESS_WORK") .. "/dave/patched"
    local fs = require("cartesi.filesystem")
    if not fs.exists(dave .. "/cartesi-rollups/contracts/out/DaveConsensus.sol/DaveConsensus.json") then
        harness.setup_error("Dave build missing: " .. dave .. " (bugs/harness/chain/build-dave.sh patched)")
    end
    local cartesi = require("cartesi")
    local evmu = require("cartesi.evmu")
    local eth = require("prt-ethereum")

    local e_small = math.tointeger(tonumber(arg[1] or "2"))
    local e_large = math.tointeger(tonumber(arg[2] or "200"))
    assert(e_small and e_large and e_small >= 1 and e_large > e_small, "bad arguments")

    local APP = "0x" .. string.rep("a1", 20)
    local CONSENSUS = "0x" .. string.rep("c0", 20)
    local INPUT_BOX = "0x" .. string.rep("1b", 20)
    local FACTORY = "0x" .. string.rep("fa", 20)
    local STF = "0x" .. string.rep("57", 20)
    local DEPLOYMENT_BLOCK = 100

    local function word(n)
        return string.format("%064x", n)
    end
    local function address_word(a)
        return string.rep("0", 24) .. a:sub(3)
    end
    local function block_hash(n)
        return "0x" .. string.rep("b", 32) .. string.format("%032x", n)
    end
    local function topic_of(signature)
        return eth.hex(cartesi.keccak256(signature))
    end
    local SEALED = topic_of("EpochSealed(uint256,uint256,uint256,bytes32,bytes32,address)")
    local STAGED = topic_of("EpochStaged(uint256,bytes32,bytes32)")

    local function selector(signature)
        return evmu.encode_calldata_hex(signature, {}):sub(1, 10):lower()
    end
    local call_results = {
        [selector("getOutputsMerkleRootValidator()")] = "0x" .. address_word(CONSENSUS),
        [selector("getInputBox()")] = "0x" .. address_word(INPUT_BOX),
        [selector("getApplicationContract()")] = "0x" .. address_word(APP),
        [selector("getTournamentFactory()")] = "0x" .. address_word(FACTORY),
        [selector("getDeploymentBlockNumber()")] = "0x" .. word(DEPLOYMENT_BLOCK),
        [selector("getClaimStagingPeriod()")] = "0x" .. word(10),
        [selector("stateTransition()")] = "0x" .. address_word(STF),
        [selector("UARCH_PRISTINE_STATE_HASH()")] = eth.hex(cartesi.UARCH_PRISTINE_STATE_HASH),
        [selector("getTemplateHash()")] = "0x" .. word(0),
    }

    -- One run of crisium.lua over a consensus with `past` sealed epochs; returns the counters of both phases.
    local function run(past)
        local tmp = assert(io.popen("mktemp -d"):read("l"))
        local checkpoints, state = tmp .. "/checkpoints", tmp .. "/state"
        fs.create_directory(checkpoints)
        fs.create_directory(checkpoints .. "/epoch-" .. past)

        local chain_logs, tip = {}, DEPLOYMENT_BLOCK
        local function add_log(topic0, number, data)
            tip = tip + 1
            chain_logs[#chain_logs + 1] = {
                address = CONSENSUS,
                blockNumber = string.format("0x%x", tip),
                blockHash = block_hash(tip),
                logIndex = "0x0",
                transactionIndex = "0x0",
                removed = false,
                topics = { topic0, "0x" .. word(number) },
                data = data,
            }
            tip = tip + 4
        end
        local function seal(k)
            -- inputIndexLowerBound, inputIndexUpperBound, initialMachineStateHash, outputsMerkleRoot, tournament
            add_log(SEALED, k, "0x" .. word(k) .. word(k + 1) .. word(0) .. word(0) .. address_word(FACTORY))
        end
        local function stage(k)
            add_log(STAGED, k, "0x" .. word(0) .. word(0))
        end
        for k = 0, past - 1 do
            if k > 0 then
                stage(k - 1)
            end
            seal(k)
        end

        local counters = { fetched = 0, decoded = 0, requests = 0 }
        local phases = {}
        local STOP = {}

        local chain = {}
        function chain:head()
            return tip, block_hash(tip), tip, block_hash(tip)
        end
        function chain:is_canonical(number, hash)
            return number <= tip and hash == block_hash(number)
        end
        function chain:call(to, data)
            return assert(call_results[data:sub(1, 10):lower()], "unexpected eth_call to " .. to .. ": " .. data)
        end
        function chain:logs(address, last_block, first_block, topics)
            counters.requests = counters.requests + 1
            local result = {}
            for _, log in ipairs(chain_logs) do
                local n = tonumber(log.blockNumber)
                local match = log.address == address and n >= (first_block or 0) and n <= last_block
                if match and topics then
                    for i, t in ipairs(topics) do
                        if t ~= nil and t ~= log.topics[i] then
                            match = false
                        end
                    end
                end
                if match then
                    result[#result + 1] = log
                end
            end
            counters.fetched = counters.fetched + #result
            return result
        end

        local function snapshot(name)
            phases[name] = { fetched = counters.fetched, decoded = counters.decoded, requests = counters.requests }
            counters.fetched, counters.decoded, counters.requests = 0, 0, 0
        end

        local player = {
            event_handler = {
                idle = function()
                    return false
                end,
            },
            check_backlog = function() end,
        }
        setmetatable(player, { __close = function() end })
        local stubs = {
            ["prt-rpc"] = {
                new = function()
                    return chain
                end,
                policy = function(v)
                    return v
                end,
            },
            ["prt"] = {
                load_epoch_checkpoint = function()
                    return { initial_state_hash = string.rep("\0", 32) }, {}, { outputs_root = eth.zero }
                end,
                new_stored_player = function()
                    return player
                end,
                remove_epoch_files = function() end,
            },
            ["prt-dishonest"] = {},
            ["prt-bridge"] = {
                read_geometry = function()
                    return {}
                end,
            },
            ["prt-websocket"] = {},
            ["prt-epoch"] = {
                new = function(args)
                    if args.epoch == past then
                        -- restart done: the player found the seal of epoch past-1
                        snapshot("restart")
                        -- epoch `past` is sealed and its player stored the next checkpoint
                        stage(past - 1)
                        seal(past)
                        tip = tip + 3
                        fs.create_directory(checkpoints .. "/epoch-" .. (past + 1))
                        return {
                            epoch = args.epoch,
                            inputs = {},
                            player = args.player,
                            poll = function() end,
                        }
                    end
                    assert(args.epoch == past + 1, "unexpected epoch opened: " .. tostring(args.epoch))
                    snapshot("new epoch")
                    error(STOP, 0)
                end,
            },
        }
        local saved = {}
        for name, stub in pairs(stubs) do
            saved[name] = package.loaded[name]
            package.loaded[name] = stub
        end
        -- count the logs crisium decodes (abi:event), keeping the real decoder
        local real_abi = eth.abi
        eth.abi = function(...)
            local abi = real_abi(...)
            local decode = abi.event
            abi.event = function(self, log)
                counters.decoded = counters.decoded + 1
                return decode(self, log)
            end
            return abi
        end

        local chunk = assert(loadfile(os.getenv("CRISIUM_LUA") or (recipes .. "/crisium.lua")))
        local saved_arg = arg
        arg = {
            "--rpc=http://mock.invalid:1/",
            "--application=" .. APP,
            "--state=" .. state,
            "--checkpoints=" .. checkpoints,
            "--dave=" .. dave,
            "--poll-interval=0",
        }
        local ok, err = pcall(chunk)
        arg = saved_arg
        eth.abi = real_abi
        for name in pairs(stubs) do
            package.loaded[name] = saved[name]
        end
        os.execute("rm -rf '" .. tmp .. "'")
        if ok or err ~= STOP then
            error("crisium did not reach the second epoch: " .. tostring(err), 0)
        end
        assert(phases.restart and phases["new epoch"], "phases not recorded")
        return phases, #chain_logs
    end

    local small, small_logs = run(e_small)
    local large, large_logs = run(e_large)
    local function show(past, total, p)
        print(
            string.format(
                "past epochs %4d (consensus logs %4d): restart fetched %4d decoded %4d (%d requests) | "
                    .. "new epoch fetched %4d decoded %4d (%d requests)",
                past,
                total,
                p.restart.fetched,
                p.restart.decoded,
                p.restart.requests,
                p["new epoch"].fetched,
                p["new epoch"].decoded,
                p["new epoch"].requests
            )
        )
    end
    show(e_small, small_logs, small)
    show(e_large, large_logs, large)

    -- R12: the player's observation work (logs fetched and kept, logs decoded) on a restart and when it opens
    -- a new epoch must not grow with the number of past epochs. A small constant slack allows a fix that,
    -- say, reads a few logs around the previous seal.
    local SLACK = 4
    local failures = {}
    local function check(phase, metric)
        local a, b = small[phase][metric], large[phase][metric]
        if b > a + SLACK then
            failures[#failures + 1] = string.format(
                "%s: logs %s grow from %d (%d past epochs) to %d (%d past epochs)",
                phase,
                metric,
                a,
                e_small,
                b,
                e_large
            )
        end
    end
    check("restart", "fetched")
    check("restart", "decoded")
    check("new epoch", "decoded")
    check("new epoch", "fetched")
    for _, f in ipairs(failures) do
        print("VIOLATION " .. f)
    end
    return harness.expect(
        #failures == 0,
        "R12: crisium's seal lookup must not grow with the number of past epochs "
            .. "(restart and per-epoch observation cost)"
    )
end)
