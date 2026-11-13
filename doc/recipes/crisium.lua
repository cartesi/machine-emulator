-- A PRT player as its own process. From its application's address it discovers the consensus,
-- the input box, the tournament factory and its geometry. It then follows every epoch from the
-- first one it plays, which is --first-epoch or the oldest checkpoint present, whichever comes
-- later. Each epoch starts from checkpoints/epoch-N/, whose machine the epoch's seal must match. A
-- listener delivers the epoch's inputs and seal, and the dispute bridge answers the epoch's
-- tournament. Its state lives in the state directory: the transaction journal and, for the honest
-- player, one epoch directory per epoch. The honest player keeps the files of the newest
-- --keep-epochs finished epochs (1 by default) and removes the checkpoint and epoch directory of
-- older ones.
--
-- crisium runs as a sentinel by default, or as a validator with --mode=validator. A sentinel signs
-- nothing and needs no keystore. It computes the honest claims and reports, as anomalies, what a
-- validator should have done and has not: deadline_near and missed_deadline for an action whose window
-- closes within --warning-blocks=N blocks (10 by default) or has closed, and stalled_action for an
-- action without a window that has been due for that many blocks. A validator plays the dispute.
--
-- Usage: lua5.4 crisium.lua --rpc=URL --application=ADDRESS --state=DIRECTORY --checkpoints=DIRECTORY
--     --dave=DIRECTORY [OPTION...]
-- A validator also takes --mode=validator --keystore=FILE --password-file=FILE --kind=KIND.
--
-- KIND is honest, or one of the scripted adversaries quitter, tamperer:INPUT:BUNDLE,
-- fabulist:INPUT:LEAF, and forger:INPUT:FILE. A sentinel computes honest claims and takes no KIND.
-- The options are --label=NAME, --first-epoch=N,
-- --keep-epochs=N, --cleanup=no, --input-policy=POLICY, --dispute-policy=POLICY,
-- --status-file=FILE, --ws=URL (the node's WebSocket endpoint, which pushes new block headers),
-- --poll-interval=SECONDS, the fee limits --bump-blocks=N, --bump-percent=N, --max-fee=WEI, and
-- --max-priority-fee=WEI, and --anomaly-handler=MODULE. After every pass the player writes its status to
-- the status file, for a harness that mines the chain. MODULE is a Lua module, found through LUA_PATH,
-- that returns a function the player calls with each anomaly's kind and message. It must return quickly,
-- since it runs inside a pass. Without it, the player prints each anomaly to stderr.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")
local fs = require("cartesi.filesystem")
local json = require("dkjson")
local socket = require("socket")
local rpc_client = require("prt-rpc")
local eth = require("prt-ethereum")
local prt = require("prt")
local dishonest = require("prt-dishonest")
local epoch = require("prt-epoch")
local log_history = require("prt-log-history")
local bridge = require("prt-bridge")
local websocket = require("prt-websocket")

local options = {}
for _, argument in ipairs(arg) do
    local name, value = argument:match("^%-%-([%w-]+)=(.*)$")
    assert(name, "invalid argument: " .. argument)
    options[name:gsub("-", "_")] = value
end
local mode = options.mode or "sentinel"
assert(mode == "sentinel" or mode == "validator", "invalid mode: " .. mode)
local validator = mode == "validator"
local required = { "rpc", "application", "state", "checkpoints", "dave" }
if validator then
    table.move({ "keystore", "password_file", "kind" }, 1, 3, #required + 1, required)
else
    assert(options.kind == nil or options.kind == "honest", "a sentinel computes only honest claims")
    options.kind = "honest"
end
for _, name in ipairs(required) do
    assert(options[name], "missing --" .. name:gsub("_", "-"))
end
-- Only a validator signs, so only it loads the signer
local signing = validator and require("prt-signer")
local label = options.label or (validator and options.kind:match("^[%w_]+") or "sentinel")
local warning_blocks = math.tointeger(tonumber(options.warning_blocks or "10"))
assert(warning_blocks and warning_blocks >= 0, "invalid number of warning blocks")
local anomaly_handler = options.anomaly_handler and require(options.anomaly_handler)
assert(
    anomaly_handler == nil or type(anomaly_handler) == "function",
    "the anomaly handler module must return a function"
)
local keep_epochs = math.tointeger(tonumber(options.keep_epochs or "1"))
assert(keep_epochs and keep_epochs >= 0, "invalid number of kept epochs")
local input_policy = rpc_client.policy(options.input_policy or "finalized")
local dispute_policy = rpc_client.policy(options.dispute_policy or 4)

-- With PRT_PROFILE=yes, the player times its RPC calls by method, log decoding, each player
-- handler, and its listener polls and bridge ticks. Its status carries the totals.
local profile = os.getenv("PRT_PROFILE") == "yes" and {} or nil
local gettime = socket.gettime
local function measure(name, f, ...)
    if not profile then
        return f(...)
    end
    local start = gettime()
    local results = table.pack(f(...))
    local entry = profile[name] or { seconds = 0, calls = 0 }
    entry.seconds, entry.calls = entry.seconds + gettime() - start, entry.calls + 1
    profile[name] = entry
    return table.unpack(results, 1, results.n)
end

local chain = rpc_client.new(options.rpc)
if validator then
    signing.install(chain)
end
local function artifact(directory, name)
    return (eth.artifact(options.dave .. "/" .. directory .. "/contracts/out", name))
end
local abi = eth.abi({
    artifact("cartesi-rollups", "Application"),
    artifact("cartesi-rollups", "DaveConsensus"),
    artifact("cartesi-rollups", "InputBox"),
    artifact("prt", "Tournament"),
    artifact("prt", "MultiLevelTournamentFactory"),
})
if profile then
    local rpc, decode = chain.rpc, abi.event
    function chain.rpc(self, method, params)
        return measure("rpc " .. method, rpc, self, method, params)
    end
    function abi.event(self, log)
        return measure("decode", decode, self, log)
    end
end
local function call(address, name, types)
    return evmu.decode_abi(types, assert(eth.raw(assert(chain:call(address, abi:calldata(name, {}))))))[1]
end

-- Everything else comes from the application.
local app = options.application:lower()
local consensus = call(app, "getOutputsMerkleRootValidator", "(address)"):lower()
local input_box = call(consensus, "getInputBox", "(address)"):lower()
assert(call(consensus, "getApplicationContract", "(address)"):lower() == app, "consensus serves another application")
local factory = call(consensus, "getTournamentFactory", "(address)"):lower()
local first_block = eth.small(call(consensus, "getDeploymentBlockNumber", "(uint256)"))
local staging_period = eth.small(call(consensus, "getClaimStagingPeriod", "(uint256)"))
local state_transition = call(factory, "stateTransition", "(address)"):lower()
assert(
    chain:call(state_transition, evmu.encode_calldata_hex("UARCH_PRISTINE_STATE_HASH()", {}))
        == eth.hex(cartesi.UARCH_PRISTINE_STATE_HASH),
    "emulator and Solidity pristine uarch hashes differ"
)
local template_hash = assert(chain:call(app, abi:calldata("getTemplateHash", {}))):lower()
local geometry = bridge.read_geometry(chain, abi, factory)

local signer = validator
    and {
        address = signing.address(options.keystore, options.password_file),
        keystore = options.keystore,
        password_file = options.password_file,
    }
if not fs.exists(options.state) then
    fs.create_directory(options.state)
end

-- The honest player completes the epoch removals a crash interrupted. No player starts before the
-- oldest checkpoint.
local oldest_checkpoint
if fs.exists(options.checkpoints) then
    for _, name in ipairs(fs.list_directory(options.checkpoints)) do
        local removed = math.tointeger(tonumber(name:match("^epoch%-(%d+)%.removed$")))
        local number = math.tointeger(tonumber(name:match("^epoch%-(%d+)$")))
        if removed and options.kind == "honest" then
            local suffix = "/epoch-" .. removed
            prt.remove_epoch_files(options.checkpoints .. suffix, options.state .. suffix)
        elseif number and (not oldest_checkpoint or number < oldest_checkpoint) then
            oldest_checkpoint = number
        end
    end
end
local first_epoch = math.tointeger(tonumber(options.first_epoch or "0"))
assert(first_epoch and first_epoch >= 0, "invalid first epoch")
first_epoch = math.max(first_epoch, oldest_checkpoint or 0)
local transactions = validator
    and require("prt-transactions").new({
        chain = chain,
        path = options.state .. "/journal.json",
        bump_blocks = assert(math.tointeger(tonumber(options.bump_blocks or "3")), "invalid fee bump interval"),
        bump_percent = assert(math.tointeger(tonumber(options.bump_percent or "15")), "invalid fee bump percent"),
        max_fee = options.max_fee,
        max_priority_fee = options.max_priority_fee,
    })

-- The honest player stores each epoch in its own epoch directory and reopens it after a relaunch.
-- Its epoch seal stores the next epoch's checkpoint. The scripted adversaries keep their epochs in
-- memory and compute them again.
local function new_player(dapp, outputs_frontier, epoch_directory, checkpoint_directory)
    local kind, first, second = options.kind:match("^([%w_]+):?([^:]*):?(.*)$")
    local player
    if kind == "honest" then
        if not fs.exists(epoch_directory) then
            fs.create_directory(epoch_directory)
        end
        player = prt.new_stored_player(dapp, label, outputs_frontier, epoch_directory, checkpoint_directory)
    elseif kind == "quitter" then
        player = dishonest.new_quitter(dapp, label, outputs_frontier)
    elseif kind == "tamperer" then
        player = dishonest.new_tamperer(dapp, tonumber(first), tonumber(second), label, outputs_frontier)
    elseif kind == "fabulist" then
        player = dishonest.new_fabulist(dapp, tonumber(first), tonumber(second), label, outputs_frontier)
    elseif kind == "forger" then
        player = dishonest.new_forger(dapp, tonumber(first), second, label, outputs_frontier)
    else
        error("unknown player kind: " .. options.kind)
    end
    player.anomaly_handler = anomaly_handler
    if profile then
        local handlers = player.event_handler
        player.event_handler = setmetatable({}, {
            __index = function(_, name)
                local handler = handlers[name]
                return handler
                    and function(...)
                        return measure("player " .. name, handler, ...)
                    end
            end,
        })
    end
    return player
end

-- The consensus's seals come from a history, which pages its requests and fetches only the blocks
-- it has not seen.
local seal_history = log_history.new(chain)

-- The consensus's seal of an epoch, or nil while it is open.
local function get_seal(number)
    seal_history:observe(chain:head())
    for _, log in ipairs(seal_history:get_logs(consensus, first_block)) do
        local event = abi:event(log)
        if event and event.name == "EpochSealed" and eth.small(event.epochNumber) == number then
            return event
        end
    end
end

-- One listener per epoch, opened once its checkpoint exists and the previous epoch is sealed.
local listeners, next_epoch = {}, first_epoch
local function open_epochs()
    while true do
        local checkpoint_directory = options.checkpoints .. "/epoch-" .. next_epoch
        if not fs.exists(checkpoint_directory) then
            return
        end
        local previous_seal = next_epoch > 0 and get_seal(next_epoch - 1)
        if next_epoch > 0 and not previous_seal then
            return
        end
        local dapp, outputs_frontier, manifest = prt.load_epoch_checkpoint(checkpoint_directory)
        if next_epoch == 0 then
            assert(manifest.final_state_hash:lower() == template_hash, "epoch 0's checkpoint is not the template")
        end
        listeners[#listeners + 1] = epoch.new({
            chain = chain,
            transactions = transactions,
            abi = abi,
            app = app,
            input_box = input_box,
            consensus = consensus,
            factory = factory,
            epoch = next_epoch,
            input_begin = previous_seal and eth.small(previous_seal.inputIndexUpperBound) or 0,
            initial_hash = eth.hex(dapp.initial_state_hash),
            previous_outputs_root = previous_seal and manifest.outputs_root or eth.zero,
            geometry = geometry,
            player = new_player(
                dapp,
                outputs_frontier,
                options.state .. "/epoch-" .. next_epoch,
                options.checkpoints .. "/epoch-" .. (next_epoch + 1)
            ),
            signer = signer,
            sentinel = not validator,
            warning_blocks = warning_blocks,
            label = label,
            cleanup = options.cleanup ~= "no",
            claim_staging_period = staging_period,
            input_policy = input_policy,
            dispute_policy = dispute_policy,
            first_block = first_block,
            -- An input logged in the previous seal's block can still belong to this epoch
            first_input_block = previous_seal and eth.small(previous_seal.log.blockNumber) or first_block,
        })
        next_epoch = next_epoch + 1
    end
end

-- The honest player keeps the files of the newest keep_epochs finished epochs and removes those of
-- older ones, oldest first, from the oldest checkpoint even when the first epoch it plays is later. It
-- stops at an epoch still observed, which finishes later.
local oldest_stored, newest_finished = oldest_checkpoint or first_epoch, -1
local function remove_finished_epochs(epoch_number)
    newest_finished = math.max(newest_finished, epoch_number)
    while oldest_stored <= newest_finished - keep_epochs do
        for _, listener in ipairs(listeners) do
            if listener.epoch == oldest_stored then
                return
            end
        end
        local suffix = "/epoch-" .. oldest_stored
        prt.remove_epoch_files(options.checkpoints .. suffix, options.state .. suffix)
        io.stderr:write("Epoch ", oldest_stored, ": files removed.\n")
        oldest_stored = oldest_stored + 1
    end
end

-- One pass over every epoch: each listener polls and, once its epoch is sealed, its dispute bridge
-- ticks. The status reports whether the pass published, the next block it needs, how many of each
-- epoch's inputs it has received, whether each epoch is sealed, and why it stopped, if it did.
local function pass()
    open_epochs()
    local status = { epochs = {}, published = false }
    local disputes = {}
    for _, listener in ipairs(listeners) do
        local dispute = measure("poll", listener.poll, listener)
        status.epochs[tostring(listener.epoch)] = { inputs = #listener.inputs, sealed = dispute ~= nil }
        disputes[#disputes + 1] = dispute
    end
    -- Only the newest sealed epoch has deadlines (older ones keep at most bond recoveries), so its bridge
    -- ticks first and takes the signer's next nonce before them.
    for i = #disputes, 1, -1 do
        local dispute = disputes[i]
        local step = dispute.sentinel and dispute.watch or dispute.tick
        local snapshot, published, next_block = measure("tick", step, dispute)
        -- A rejected observation leaves the bridge to try again at the same tip.
        status.retry = status.retry or snapshot == nil
        status.published = status.published or published
        if next_block then
            status.next_block = math.min(status.next_block or next_block, next_block)
        end
        status.terminal = status.terminal or dispute.terminal
    end
    -- A finished epoch has nothing left to do, so its listener, bridge and player are dropped
    for i = #listeners, 1, -1 do
        local dispute = listeners[i].dispute
        if dispute and dispute.finished then
            local finished = table.remove(listeners, i)
            io.stderr:write("Epoch ", finished.epoch, ": finished, no longer observed.\n")
            do
                local _ <close> = finished.player
            end
            if options.kind == "honest" then
                remove_finished_epochs(finished.epoch)
            end
        end
    end
    return status
end

-- One step of work without a deadline for every player, sealed epochs first, and whether any has more.
local function idle()
    local more = false
    for i = #listeners, 1, -1 do
        local player = listeners[i].player
        more = player.event_handler.idle(player) or more
    end
    return more
end

-- The status replaces the previous one whole, so a reader never sees a partial status.
local function store_status(status)
    if options.status_file then
        local temporary = options.status_file .. ".tmp"
        fs.write_file(json.encode(status), temporary)
        assert(os.rename(temporary, options.status_file))
    end
end

-- A player passes again whenever the tip changes, and right away after a pass that published or
-- must retry. Otherwise it does idle work, one step at a time, checking the tip between steps. With
-- nothing to do, with --ws it waits for the node to push the next header, and reads the tip itself at
-- least once per poll interval in case a header was missed. Otherwise it polls at that interval.
local poll_interval = assert(tonumber(options.poll_interval or "1"), "invalid poll interval")
local heads = options.ws and websocket.new_head_subscription(options.ws)
local last_hash, again = nil, true
while true do
    local tip, tip_hash = chain:head()
    if again or tip_hash ~= last_hash then
        -- A new block follows the idle time of the previous one
        if last_hash and tip_hash ~= last_hash then
            for _, listener in ipairs(listeners) do
                listener.player:check_backlog()
            end
        end
        local status = pass()
        status.tip, status.tip_hash, status.profile = tip, tip_hash, profile
        store_status(status)
        assert(not status.terminal, status.terminal)
        last_hash, again = tip_hash, status.published or status.retry
    elseif not idle() then
        if heads then
            heads:wait(poll_interval)
        else
            socket.sleep(poll_interval)
        end
    end
end
