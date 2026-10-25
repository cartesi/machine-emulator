-- Stream both calculator epochs through Dave, preserving normal empty epoch zero.
local fs = require("cartesi.filesystem")
local json = require("dkjson")
local cast = require("prt-cast")
local eth = require("prt-ethereum")
local socket = require("socket")
local prt = require("prt")
local bridge = require("prt-bridge")
local initial_hash = assert(arg[1], "missing template hash")
assert(#assert(eth.raw(initial_hash)) == 32, "invalid template hash")
local mode = arg[2] or "story"
local rpc_url = os.getenv("PRT_RPC_URL") or "http://127.0.0.1:8545"
local chain = cast.new(rpc_url)
-- Mining is the orchestrator's own request and may take as long as the node needs.
local miner = cast.new(rpc_url, false)
local input_policy = cast.policy(os.getenv("PRT_INPUT_CONFIRMATIONS") or "8")
local dispute_policy = cast.policy(os.getenv("PRT_DISPUTE_CONFIRMATIONS") or "4")
local test_reorg = os.getenv("PRT_TEST_REORG") == "yes"
local test_restart = os.getenv("PRT_TEST_RESTART") == "yes"

local prt_deploy = require("prt-deploy")
local deployment = prt_deploy.deploy(chain, initial_hash)
local signer = prt_deploy.signer
local deployer, abi, geometry = deployment.deployer, deployment.abi, deployment.geometry
local factory, input_box = deployment.factory, deployment.input_box
local app, consensus, staging_period = deployment.app, deployment.consensus, deployment.staging_period
-- Each player signs with the same account in every epoch, so its journal follows one account.
local SIGNER_INDICES = {
    quitter = 1,
    tamperer = 2,
    fabulist = 3,
    fixed_fabulist = 4,
    forger = 5,
    honest = 6,
    quitter_1 = 7,
    quitter_2 = 8,
}
-- The account of every player, and the player each account belongs to.
local signers, labels = {}, {}
for label, index in pairs(SIGNER_INDICES) do
    signers[label] = signer(index)
    labels[signers[label].address] = label
end
fs.write_file(
    json.encode({
        factory = factory,
        input_box = input_box,
        app = app,
        consensus = consensus,
        initial_hash = initial_hash,
        uarch_pristine_hash = deployment.uarch_pristine_hash,
        input_policy = input_policy,
        dispute_policy = dispute_policy,
    }, { indent = true }),
    "deployment.json"
)
-- checkpoints/epoch-N/ holds the machine every player starts epoch N from. Epoch 0 starts from the
-- template, and the honest player stores each next one at its seal.
local function get_checkpoint_directory(number)
    return "checkpoints/epoch-" .. number
end
fs.create_directory("checkpoints")
prt.store_template_checkpoint(initial_hash, geometry, get_checkpoint_directory(0))

-- Every player runs as its own process, with its kind and the first epoch it plays. The scripted
-- adversaries play the calculator epochs and leave the cleanup transactions to the honest player.
local players = { { label = "honest", kind = "honest", first_epoch = 0 } }
if mode ~= "smoke" then
    for _, player in ipairs({
        { label = "quitter", kind = "quitter" },
        { label = "tamperer", kind = "tamperer:0:100" },
        { label = "fabulist", kind = "fabulist:2:2000" },
        { label = "fixed_fabulist", kind = "fabulist:2:60000" },
        { label = "forger", kind = "forger:2:forged-input-2.bin" },
        { label = "quitter_1", kind = "quitter" },
        { label = "quitter_2", kind = "quitter" },
    }) do
        player.first_epoch, player.cleanup = 1, "no"
        players[#players + 1] = player
    end
end

-- Each player keeps its state in players/<label>/ and runs under a supervisor that relaunches it
-- when it exits. Stopping the supervisors stops the players.
local recipes_directory = assert(os.getenv("RECIPES_DIR"), "missing RECIPES_DIR")
local supervisors = {}
local function stop_players()
    for _, pid in ipairs(supervisors) do
        pcall(cast.run, { "kill", pid })
    end
end
local _ <close> = setmetatable({}, { __close = stop_players })
local function read_pid(player)
    local path = "players/" .. player.label .. "/pid"
    return fs.exists(path) and fs.read_file(path):gsub("%s+$", "") or nil
end
-- Statuses are progress reports, not run artifacts, so they live in the container's own
-- filesystem, where replacing one by a rename is atomic for its readers.
local status_directory = fs.temp_pathname()
fs.create_directory(status_directory)
local function get_status_path(player)
    return status_directory .. "/" .. player.label .. ".json"
end
fs.create_directory("players")
for _, player in ipairs(players) do
    local directory = "players/" .. player.label
    local account = assert(signers[player.label], "player has no account")
    fs.create_directory(directory)
    local arguments = {
        "--rpc=" .. rpc_url,
        "--application=" .. app,
        "--keystore=" .. account.keystore,
        "--password-file=" .. account.password_file,
        "--state=" .. directory,
        "--checkpoints=checkpoints",
        "--dave=" .. prt_deploy.dave_directory,
        "--kind=" .. player.kind,
        "--label=" .. player.label,
        "--first-epoch=" .. player.first_epoch,
        "--cleanup=" .. (player.cleanup or "yes"),
        "--input-policy=" .. tostring(input_policy),
        "--dispute-policy=" .. tostring(dispute_policy),
        "--status-file=" .. get_status_path(player),
        "--ws=" .. rpc_url:gsub("^http", "ws"),
        "--bump-blocks=" .. (os.getenv("PRT_FEE_BUMP_BLOCKS") or "3"),
        "--bump-percent=" .. (os.getenv("PRT_FEE_BUMP_PERCENT") or "15"),
        "--max-fee=" .. (os.getenv("PRT_MAX_FEE_PER_GAS") or "100000000000"),
        "--max-priority-fee=" .. (os.getenv("PRT_MAX_PRIORITY_FEE_PER_GAS") or "10000000000"),
    }
    local supervisor = cast.run({
        "sh",
        "-c",
        '"$@" > "$0" 2>&1 < /dev/null & echo $!',
        directory .. "/log.txt",
        "bash",
        recipes_directory .. "/prt-supervise.sh",
        directory .. "/pid",
        "lua5.4",
        recipes_directory .. "/prt-player.lua",
        table.unpack(arguments),
    })
    supervisors[#supervisors + 1] = supervisor:gsub("%s+$", "")
end

local function read_status(player)
    local path = get_status_path(player)
    if not fs.exists(path) then
        return nil
    end
    local status, _, err = json.decode(fs.read_file(path))
    return assert(status, err)
end

-- Waits until every player has passed over the current tip without publishing. It returns their
-- statuses and the earliest block any of them needs. It reads only the statuses until they agree
-- on a tip, then asks the node whether that tip is still current. A player is relaunched only if
-- it exits, which fails the run.
local pids, killed = {}, {}
local function await_players()
    while true do
        local tip_hash
        local statuses, next_block = {}, nil
        for _, player in ipairs(players) do
            local pid = read_pid(player)
            -- A player killed on purpose counts as absent until its supervisor relaunches it.
            if pid == killed[player.label] then
                pid = nil
            end
            pids[player.label] = pids[player.label] or pid
            assert(
                not pid or pid == pids[player.label],
                player.label .. " exited; see players/" .. player.label .. "/log.txt"
            )
            local status = pid and read_status(player)
            tip_hash = tip_hash or (status and status.tip_hash)
            if not status or status.tip_hash ~= tip_hash or status.published or status.retry then
                statuses = nil
                break
            end
            assert(not status.terminal, player.label .. ": " .. tostring(status.terminal))
            statuses[player.label] = status
            if status.next_block then
                next_block = math.min(next_block or status.next_block, status.next_block)
            end
        end
        if statuses and select(2, chain:head()) == tip_hash then
            return statuses, next_block
        end
        socket.sleep(0.02)
    end
end

-- With PRT_TEST_RESTART=yes, the honest player is killed once at each restart point, as a crash would
-- end it. Its last status is removed, so the orchestrator waits for its relaunched process to pass.
local restarts = {}
local function restart_honest(point)
    if not test_restart or restarts[point] then
        return
    end
    local honest = players[1]
    local pid = assert(read_pid(honest), "the honest player has no process")
    cast.run({ "kill", "-9", pid })
    killed[honest.label], pids[honest.label], restarts[point] = pid, nil, true
    if fs.exists(get_status_path(honest)) then
        fs.remove_file(get_status_path(honest))
    end
    io.stderr:write("Killed the honest player ", point, ".\n")
    return true
end

-- How far the players of an epoch are: the fewest of its inputs any of them received, and whether
-- every one of them has seen its seal.
local function get_progress(statuses, number)
    local inputs, sealed = math.huge, true
    for _, player in ipairs(players) do
        if player.first_epoch <= number then
            local progress = statuses[player.label].epochs[tostring(number)]
            inputs = math.min(inputs, progress and progress.inputs or 0)
            sealed = sealed and progress ~= nil and progress.sealed
        end
    end
    return inputs, sealed
end

-- With PRT_PROFILE=yes, every player times its RPC calls by method, log decoding, each player
-- handler, and its listener polls and bridge ticks, and reports the totals in its status. As each
-- epoch is accepted, the demo prints the time spent since the previous report, summed over the
-- honest player and over the others.
local profiling, reported = os.getenv("PRT_PROFILE") == "yes", {}
local function report_profile(epoch_number, statuses)
    if not profiling then
        return
    end
    local totals, names = {}, {}
    for _, player in ipairs(players) do
        for name, entry in pairs(statuses[player.label].profile or {}) do
            local key = name .. (player.label == "honest" and " honest" or " others")
            local total = totals[key] or { seconds = 0, calls = 0 }
            total.seconds, total.calls = total.seconds + entry.seconds, total.calls + entry.calls
            totals[key] = total
        end
    end
    for name, total in pairs(totals) do
        local previous = reported[name] or { seconds = 0, calls = 0 }
        names[#names + 1] = { name, total.seconds - previous.seconds, total.calls - previous.calls }
    end
    table.sort(names, function(a, b)
        return a[2] > b[2]
    end)
    for _, entry in ipairs(names) do
        io.stderr:write(string.format("Epoch %d profile: %-40s %9.2f s %8d calls\n", epoch_number, table.unpack(entry)))
    end
    reported = totals
end

-- The orchestrator keeps one session per epoch: the inputs it posted, the consensus's seal, and
-- the story it narrates. Everything else it knows comes from the chain, the checkpoints, and the
-- players' statuses.
local sessions = {}
local function new_session(number)
    local session = { epoch = number, inputs = {}, story = "" }
    sessions[#sessions + 1] = session
    return session
end

-- The consensus's seal of an epoch.
local function get_seal(number)
    for _, log in ipairs(chain:logs(consensus, (chain:head()))) do
        local event = abi:event(log)
        if event and event.name == "EpochSealed" and eth.small(event.epochNumber) == number then
            return event
        end
    end
end

-- Whether every player's account has nothing pending.
local function accounts_idle()
    for _, account in pairs(signers) do
        local pending = assert(chain:rpc("eth_getTransactionCount", { account.address, "pending" }))
        if pending ~= assert(chain:rpc("eth_getTransactionCount", { account.address, "latest" })) then
            return false
        end
    end
    return true
end

local function narrate(session, snapshot)
    local reasons = { "by a verified state transition", "by timeout", "by the child tournament result" }
    -- A commitment belongs to the player whose account joined it.
    local owners = {}
    for _, event in ipairs(snapshot.events) do
        if event.name == "CommitmentJoined" then
            owners[event.address .. ":" .. event.commitment] = labels[event.submitter] or event.submitter
        end
    end
    local function claim_label(address, commitment)
        if commitment == eth.zero then
            return "none"
        end
        return owners[address .. ":" .. commitment] or commitment:sub(1, 14)
    end
    local lines =
        { "Epoch " .. session.epoch .. (session.epoch == 0 and " (empty bootstrap)" or " (calculator)") .. "\n" }
    for _, input in ipairs(session.inputs) do
        lines[#lines + 1] = "Block " .. input.block .. ": input " .. input.index .. " added.\n"
    end
    lines[#lines + 1] = "Block " .. eth.small(session.seal.log.blockNumber) .. ": epoch sealed.\n"
    -- A win that re-pairs its survivor logs the new match before deleting the old one.
    -- Narrate matches created by a transaction after its other events.
    local created, created_tx = {}, nil
    local function flush_created()
        table.move(created, 1, #created, #lines + 1, lines)
        created = {}
    end
    for _, event in ipairs(snapshot.events) do
        if event.log.transactionHash ~= created_tx then
            flush_created()
            created_tx = event.log.transactionHash
        end
        local prefix = "Block " .. eth.small(event.log.blockNumber) .. ": "
        if event.name == "CommitmentJoined" then
            lines[#lines + 1] = prefix
                .. claim_label(event.address, event.commitment)
                .. " joins "
                .. event.address
                .. ".\n"
        elseif event.name == "MatchCreated" then
            created[#created + 1] = prefix
                .. claim_label(event.address, event.one)
                .. " meets "
                .. claim_label(event.address, event.two)
                .. ".\n"
        elseif event.name == "NewInnerTournament" then
            local input, period = eth.coordinates(event.descriptor.baseCycle, geometry)
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
            local label
            if winner == 0 then
                label = claim_label(event.address, event.one)
                    .. " and "
                    .. claim_label(event.address, event.two)
                    .. " are eliminated"
            else
                label = claim_label(event.address, winner == 1 and event.one or event.two) .. " wins"
            end
            lines[#lines + 1] = prefix .. label .. " " .. assert(reasons[eth.small(event.reason) + 1]) .. ".\n"
        elseif event.name == "EpochStaged" and eth.small(event.epochNumber) == session.epoch then
            lines[#lines + 1] = prefix .. "The consensus stages the proven epoch result.\n"
        elseif event.name == "BondRecovered" then
            lines[#lines + 1] = prefix
                .. claim_label(event.address, event.commitment)
                .. " recovers its winning bond.\n"
        end
    end
    flush_created()
    if snapshot.settled then
        lines[#lines + 1] = "Block "
            .. eth.small(snapshot.settled.log.blockNumber)
            .. ": result accepted; epoch "
            .. (session.epoch + 1)
            .. " sealed.\n"
    end
    session.story = table.concat(lines)
end

local function mine_to(number)
    local tip = chain:head()
    if number > tip then
        local start = socket.gettime()
        local ok, result, failure = pcall(miner.rpc, miner, "anvil_mine", { string.format("0x%x", number - tip) })
        assert(
            ok and result,
            string.format(
                "mining %d blocks after block %d failed after %.1f s, at %s: %s",
                number - tip,
                tip,
                socket.gettime() - start,
                os.date("!%H:%M:%S"),
                tostring(ok and failure and json.encode(failure) or result)
            )
        )
    end
end

-- Only the disposable-chain harness advances time to satisfy confirmations. It mines straight to
-- the block where an event in a given block has the input policy's depth, and one block at a time
-- under a policy the node decides, such as finalized.
local function get_confirmed_block(block)
    local next_block = chain:head() + 1
    if math.type(input_policy) == "integer" then
        return math.max(block + input_policy, next_block)
    end
    return next_block
end

local function await_inputs(session, count)
    for _ = 1, 1000 do
        local inputs, sealed = get_progress(await_players(), session.epoch)
        assert(not sealed, "input was not processed before sealing")
        if inputs == count then
            if session.epoch == 1 then
                restart_honest("after an input")
            end
            return
        end
        mine_to(get_confirmed_block(session.inputs[count].block))
    end
    error("input observation policy did not advance")
end

local function await_seal(session)
    for _ = 1, 1000 do
        if select(2, get_progress(await_players(), session.epoch)) then
            session.seal = assert(get_seal(session.epoch), "players saw a seal the consensus did not emit")
            if session.epoch == 1 then
                restart_honest("after the seal")
            end
            return
        end
        local seal = get_seal(session.epoch)
        mine_to(seal and get_confirmed_block(eth.small(seal.log.blockNumber)) or chain:head() + 1)
    end
    error("epoch seal observation policy did not advance")
end

-- The orchestrator's own view of a sealed epoch's dispute, at an observation policy.
local function new_observer(seal, observation_policy)
    return bridge.new_observer({
        chain = chain,
        abi = abi,
        root = seal.tournament,
        factory = factory,
        consensus = consensus,
        epoch = seal.epochNumber,
        initial_hash = seal.initialMachineStateHash,
        claim_staging_period = staging_period,
        observation_policy = observation_policy,
        seal_block = eth.small(seal.log.blockNumber),
        seal_hash = seal.log.blockHash,
    })
end

-- The block of the event that triggers the test reorg, if the view holds it.
local function get_trigger_block(view)
    for _, event in ipairs(view.events) do
        if event.name == "NewInnerTournament" or (mode == "smoke" and event.name == "CommitmentJoined") then
            return eth.small(event.log.blockNumber)
        end
    end
end

local function play(session)
    local seal = session.seal
    local root = seal.tournament
    local observer = new_observer(seal, dispute_policy)
    -- With PRT_TEST_REORG=yes, epoch 1's dispute is reorganized once its players have observed the
    -- trigger event. The chain reverts to its snapshot from before the trigger's block, which is
    -- deeper than the players' dispute confirmations and shallower than finality. The players act on
    -- each new block, so the snapshot is taken before the orchestrator mines.
    local reorg = test_reorg and session.epoch == 1 and { snapshots = {}, tip_observer = new_observer(seal, 0) }
    local reorganized = false
    for observation = 1, 10000 do
        local statuses, next_block = await_players()
        local snapshot = observer:observe()
        if snapshot and snapshot.ready then
            narrate(session, snapshot)
        end
        local progressed = false
        -- Epoch 1's dispute restarts the honest player during a bisection, after it joins a uarch
        -- tournament, and once the root has a winner whose result is not staged yet.
        if session.epoch == 1 and snapshot and snapshot.ready then
            for _, event in ipairs(snapshot.events) do
                if event.name == "MatchAdvanced" and event.address == root then
                    progressed = restart_honest("during a bisection") or progressed
                elseif
                    event.name == "CommitmentJoined"
                    and event.address ~= root
                    and labels[event.submitter] == "honest"
                then
                    progressed = restart_honest("after a uarch claim") or progressed
                end
            end
            local context = snapshot.contexts[root]
            local standing = context and context.standing
            if
                standing
                and eth.small(standing.matchCount) == 0
                and standing.dangling ~= eth.zero
                and not snapshot.staged
            then
                progressed = restart_honest("before staging") or progressed
            end
        end
        if reorg and not reorg.trigger_block then
            local tip_view = reorg.tip_observer:observe()
            reorg.trigger_block = tip_view and get_trigger_block(tip_view)
        end
        if reorg and reorg.trigger_block and snapshot and get_trigger_block(snapshot) then
            local old_tip, old_hash = chain:head()
            local target
            for _, saved in ipairs(reorg.snapshots) do
                if saved.block < reorg.trigger_block then
                    target = saved
                end
            end
            local finalized = assert(chain:rpc("eth_getBlockByNumber", { "finalized", false }))
            assert(target and target.block > eth.small(finalized.number), "the test reorg would cross finality")
            assert(chain:rpc("evm_revert", { target.id }))
            mine_to(chain:head() + 1)
            fs.write_file(
                json.encode({
                    old_tip = old_tip,
                    old_hash = old_hash,
                    replacement_tip = chain:head(),
                    observation_block = snapshot.head,
                    depth = old_tip - target.block,
                }, { indent = true }),
                "reorg.json"
            )
            io.stderr:write("Epoch 1: replaced the observed dispute branch ", old_tip - target.block, " blocks deep.\n")
            reorg, reorganized = nil, true
            progressed = true
        end
        if not progressed then
            local context = snapshot and snapshot.contexts[root]
            local standing = context and context.standing
            if snapshot and snapshot.settled and snapshot.recovered[root] and accounts_idle() then
                assert(not test_reorg or session.epoch ~= 1 or reorganized, "dispute reorg was not exercised")
                for _, point in ipairs({
                    "after an input",
                    "after the seal",
                    "during a bisection",
                    "after a uarch claim",
                    "before staging",
                }) do
                    assert(not test_restart or session.epoch ~= 1 or restarts[point], "never restarted " .. point)
                end
                local joined = standing and context.joined[standing.dangling]
                assert(
                    joined and labels[joined.submitter] == "honest",
                    "winning commitment differs from the honest claim"
                )
                local _, _, manifest = prt.load_epoch(get_checkpoint_directory(session.epoch + 1))
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
                    observation,
                    " observations.\n"
                )
                report_profile(session.epoch, statuses)
                return
            end
            if reorg then
                local block = chain:head()
                reorg.snapshots[#reorg.snapshots + 1] = { id = assert(chain:rpc("evm_snapshot", {})), block = block }
            end
            -- A mined trigger is followed block by block until the players observe it.
            if reorg and reorg.trigger_block then
                mine_to(chain:head() + 1)
            else
                mine_to(math.max(next_block or 0, chain:head() + 1))
            end
        end
    end
    error("epoch exceeded the observation limit")
end

local function post_inputs(session, expressions)
    for _, expression in ipairs(expressions) do
        local receipt, err =
            chain:send(deployer, input_box, abi:calldata("addInput", { app, eth.hex(expression .. "\n") }))
        assert(receipt, err and json.encode(err))
        for _, log in ipairs(receipt.logs) do
            local event = abi:event(log)
            if event and event.name == "InputAdded" then
                session.inputs[#session.inputs + 1] =
                    { index = eth.small(event.index), block = eth.small(log.blockNumber) }
            end
        end
        await_inputs(session, #session.inputs)
    end
end

local bootstrap = new_session(0)
await_seal(bootstrap)
local first = new_session(1)
post_inputs(first, { "6*2^1024 + 3*2^512", "invalid input", "2^2048" })
play(bootstrap)
await_seal(first)
local second = new_session(2)
post_inputs(second, { "(2^256 - 1) * (2^256 - 1)", "scale=80; sqrt(2)", "scale=100; 355/113" })
play(first)
await_seal(second)
play(second)

local _, _, manifest = prt.load_epoch(get_checkpoint_directory(second.epoch + 1))
assert(manifest.output_count == 5, "calculator output history did not continue")
local stories = { "Two calculator epochs on Anvil, using the normal empty epoch zero.\n\n" }
for _, session in ipairs(sessions) do
    stories[#stories + 1] = session.story .. "\n"
end
fs.write_file(table.concat(stories), "story.txt")
print(table.concat(stories))
print("Both calculator epochs accepted; checkpoints preserve outputs 0 through 4.")
