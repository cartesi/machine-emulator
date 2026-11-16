-- The stored player, which the bridge runs. It extends the player in prt.lua with an epoch directory,
-- where it keeps its epoch run and dispute on stored machines, so it can reopen after a crash or an
-- error. It also stores the checkpoint each epoch starts from.

local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
local CMIO_TX_BUFFER_ADDRESS = cartesi.AR_CMIO_TX_BUFFER_START
local DEFAULT_MACHINE_CACHE_INPUT_GAP = prt.DEFAULT_MACHINE_CACHE_INPUT_GAP

local is_yielded_manual = prt.is_yielded_manual
local shallow_move = prt.shallow_move
local machine_pair_meta = prt.machine_pair_meta
local machine_cache_meta = prt.machine_cache_meta
local find_nearest_entry = prt.find_nearest_entry
local get_mcycle_sample_hash = prt.get_mcycle_sample_hash
local new_mcycle_pad_bundle = prt.new_mcycle_pad_bundle
local new_geometry = prt.new_geometry
local new_outputs_frontier = prt.new_outputs_frontier
local player_meta = prt.player_meta
local event_handler = prt.event_handler
local new_empty_player = prt.new_empty_player
local open_epoch = prt.open_epoch

-- Transform values while preserving their keys.
local function map(values, transform)
    local result = {}
    for key, value in pairs(values) do
        result[key] = transform(value)
    end
    return result
end

-- The stored player, which the bridge runs, keeps more input boundaries, so reaching a disputed input
-- replays only a few inputs.
local STORED_MACHINE_CACHE_CAPACITY = 32

-- Check readiness at the current cycle, so halt takes precedence over manual yield as in the CLI.
-- Inspect the yield header without reading an output payload, and require pristine uarch state.
local function assert_rolling_template(machine)
    assert(
        is_yielded_manual(machine:run(machine:read_reg("mcycle")))
            and machine:read_reg("htif_tohost_dev") == cartesi.HTIF_DEV_YIELD
            and machine:read_reg("htif_tohost_cmd") == cartesi.HTIF_YIELD_CMD_MANUAL
            and machine:read_reg("htif_tohost_reason") == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED,
        "initial machine is not waiting on an rx-accepted manual yield"
    )
    assert(
        machine:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)
            == cartesi.UARCH_PRISTINE_STATE_HASH,
        "initial machine uarch state is not pristine"
    )
end

-- Loads a stored machine into this process, sharing every change with its directory, and checks its
-- state hash. Its locks go with the process, so a player that crashes leaves no machine holding them.
-- The runtime configuration is optional.
local function new_stored_machine(state_hash, directory, runtime)
    local machine <close> = cartesi.new()
    machine:load(directory, runtime, cartesi.SHARING_ALL)
    assert(machine:get_root_hash() == state_hash, "stored machine hash mismatch")
    return machine:move()
end

-- Owns a stored machine that clone_stored just created and removes it if closed before move().
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
-- Returns the clone's directory.
local function clone_loaded_directory(machine, directory, clone_directory)
    machine:destroy()
    machine:clone_stored(directory, clone_directory)
    local clone <close> = new_temporary_stored_machine(clone_directory)
    machine:sync_stored(clone_directory)
    machine:load(directory, nil, cartesi.SHARING_ALL)
    return clone:move()
end

-- Removes a stored machine that a crash or an earlier pair may have left, possibly incomplete, if there is one.
local function remove_leftover_stored_machine(directory)
    if fs.exists(directory) then
        cartesi.machine:remove_stored(directory, cartesi.REMOVE_FORCED)
    end
end

-- A stored pair runs its machine on the backing stores of its directory and keeps a synced copy of the
-- last committed state in a backup. Callers commit only after recording the boundary.
-- Closing only releases the machine, so an error leaves the disk as a crash would.
local stored_machine_pair_meta = { __index = setmetatable({}, { __index = machine_pair_meta.__index }) }
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
    assert(not self.snapshot_taken, "machine already has a snapshot")
    self.snapshot_taken = true
end

-- The machine is destroyed for the sync and the clone, and loaded again after.
function stored_machine_pair_methods:commit()
    local machine = self.machine
    machine:destroy()
    machine:sync_stored(self.directory)
    local backup_directory = self.directory .. ".revert"
    if fs.exists(backup_directory) then
        machine:remove_stored(backup_directory)
    end
    machine:clone_stored(self.directory, backup_directory)
    machine:sync_stored(backup_directory)
    machine:load(self.directory, nil, cartesi.SHARING_ALL)
    self.snapshot_taken = false
end

-- The backup stays until the next commit.
function stored_machine_pair_methods:revert()
    assert(self.snapshot_taken, "no snapshot to revert to")
    local machine = self.machine
    machine:destroy()
    machine:remove_stored(self.directory)
    machine:clone_stored(self.directory .. ".revert", self.directory)
    machine:load(self.directory, nil, cartesi.SHARING_ALL)
    self.snapshot_taken = false
    assert(machine:get_root_hash() == self.revert_root_hash, "rollback did not restore the input boundary")
end

-- The first commit creates the backup.
local function new_stored_machine_pair(machine, directory)
    local pair <close> = setmetatable({ machine = machine, directory = directory }, stored_machine_pair_meta)
    pair.revert_root_hash = machine:get_root_hash()
    pair:commit()
    return pair:move()
end

-- A stored cache keeps its entries as stored machines under entries/ in the epoch directory, and
-- its one temporary pair runs on a clone in pair/. Evicted entries stay on disk until remove_evicted,
-- once the player's state no longer lists them.
local stored_machine_cache_meta = { __index = setmetatable({}, { __index = machine_cache_meta.__index }) }
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
        remove_leftover_stored_machine(leftover)
    end
    cartesi.machine:clone_stored(entry.directory, directory)
    local clone <close> = new_temporary_stored_machine(directory)
    local machine = new_stored_machine(entry.root_hash, directory)
    return new_stored_machine_pair(machine, clone:move())
end

-- The epoch machine is loaded from machine_directory. Entry zero is cloned from it.
local function new_stored_machine_cache(epoch_directory, machine_directory, machine)
    local cache <close> = setmetatable({
        capacity = STORED_MACHINE_CACHE_CAPACITY,
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
    fs.write_durable_file(cartesi.tojson({
        capacity = self.capacity,
        input_gap = self.input_gap,
        replace_cursor = self.replace_cursor,
        last_epoch_input_offset = self.last_epoch_input_offset,
        entries = entries,
    }, 2) .. "\n", path)
    fs.sync_directory(fs.get_parent_directory(path))
end

-- A stored player only records its inputs and runs them in idle time, so an open epoch never delays a
-- response in a sealed epoch's dispute.
local stored_event_handler = setmetatable({
    input_added = function(self, epoch_input_offset, path)
        self:add_pending_input(epoch_input_offset, path)
    end,
}, { __index = event_handler })

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
-- and a sealed epoch has the seal's fields instead. Inputs live in files of their own, which
-- state.json reaches through its input count.
-- The forests directory contains one tree directory per claim: mcycle/ for the epoch builder
-- and sealed mcycle forest, and uarch-<input>-<period>/ for each uarch claim.
--------------------------------------------------------------------------------

local EPOCH_SUBDIRECTORIES = { "entries", "forests", "inputs" }

-- state.json names the file of each large player field. The boundary files take the input count,
-- so a new boundary never overwrites the files the committed state.json names.
local function get_boundary_files(input_count)
    return {
        epoch_builder = "frontier-" .. input_count .. ".json",
        outputs_frontier = "outputs-frontier-" .. input_count .. ".json",
        machine_cache = "machine-cache-" .. input_count .. ".json",
    }
end

-- The file of the epoch's last output takes the output count instead. A boundary without new outputs
-- names the file the committed state.json names, so the file is not written again.
local function get_last_output_file(output_count)
    return "last-output-" .. output_count .. ".json"
end

local MCYCLE_FOREST_FILE = "mcycle-forest.json"

local function get_uarch_claim_name(epoch_input_offset, input_period_offset)
    return "uarch-" .. epoch_input_offset .. "-" .. input_period_offset
end

-- Each claim forest owns its tree directory. The builder and sealed mcycle forest are the same forest.
local function store_forest(forest, directory, name, frontier_file)
    local forests_directory = directory .. "/forests"
    local forest_directory = forests_directory .. "/" .. name
    if not fs.exists(forest_directory) then
        fs.create_directory(forest_directory)
    end
    hash_tree.frontier_forest_store(forest, forest_directory, directory .. "/" .. frontier_file)
    fs.sync_directory(forests_directory)
end

local function remove_forest_directory(directory)
    for _, name in ipairs(fs.list_directory(directory)) do
        fs.remove_file(directory .. "/" .. name)
    end
    fs.remove_directory(directory)
end

-- The files the layout creates next to state.json, which reopening removes when state.json does not
-- name them.
local EPOCH_FILE_PATTERNS = {
    "^frontier%-%d+%.json$",
    "^outputs%-frontier%-%d+%.json$",
    "^last%-output%-%d+%.json$",
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

-- state.json keeps the sealed epoch's outputs Merkle root proof inline. LastOutput is the schema of the
-- file that holds the epoch's last output.
local EPOCH_STATE_SCHEMAS = {
    EpochState = { outputs_merkle_root_proof = "OutputsMerkleRootProof", uarch_claims = "UarchClaims" },
    UarchClaims = { items = "Default" },
    OutputsMerkleRootProof = {
        iflags_y_data = "Base64",
        iflags_y_proof = "Proof",
        htif_tohost_data = "Base64",
        htif_tohost_proof = "Proof",
        tx_buffer_data = "Base64",
        tx_buffer_proof = "Proof",
    },
    LastOutput = { output_data = "Base64", output_proof = "Proof" },
}

local function get_input_path(directory, epoch_input_offset)
    return directory .. "/inputs/" .. epoch_input_offset .. ".bin"
end

-- A stored player keeps its inputs, its last output, and its state in its epoch directory.
local stored_player_meta = { __index = setmetatable({}, { __index = player_meta.__index }) }
local stored_player_methods = stored_player_meta.__index
stored_player_meta.__close = player_meta.__close

-- Clones an input into the epoch directory, so replay never depends on the caller's file.
function stored_player_methods:store_input(epoch_input_offset, path)
    local input_path = get_input_path(self.epoch_directory, epoch_input_offset)
    fs.clone_file(path, input_path)
    fs.sync_file(input_path)
    fs.sync_directory(self.epoch_directory .. "/inputs")
end

-- Returns nil past the applied inputs.
function stored_player_methods:read_input(epoch_input_offset)
    if epoch_input_offset >= self.input_count then
        return nil
    end
    return fs.read_file(get_input_path(self.epoch_directory, epoch_input_offset))
end

-- Commits the player's fields in state.json. The caller makes the files it names durable first.
-- Afterwards, the files only the previous state.json named and the evicted cache entries are removed.
local function store_epoch_state(self, root_hash, files, pad_bundle)
    local directory = self.epoch_directory
    local state = {
        version = 4,
        input_count = self.input_count,
        output_count = self.output_count,
        root_hash = cartesi.tohex(root_hash),
        epoch_stopped = self.epoch_stopped == true,
        initial_outputs_merkle_root = cartesi.tohex(hash_tree.frontier_get_root_hash(self.previous_outputs_frontier)),
        outputs_frontier = files.outputs_frontier,
        last_output = files.last_output,
        machine_cache = files.machine_cache,
    }
    if files.epoch_builder then
        state.epoch_builder = {
            frontier = files.epoch_builder,
            pad_bundle = cartesi.tohex(hash_tree.frontier_forest_get_root_hash(pad_bundle)),
        }
    else
        state.mcycle_forest = files.mcycle_forest
        state.outputs_merkle_root_proof = self.outputs_merkle_root_proof
        state.uarch_claims = map(self.uarch_claims, function(claim)
            return {
                epoch_input_offset = claim.epoch_input_offset,
                input_period_offset = claim.input_period_offset,
                forest = get_uarch_claim_name(claim.epoch_input_offset, claim.input_period_offset) .. ".json",
            }
        end)
    end
    fs.write_durable_file(
        cartesi.tojson(state, 2, "EpochState", EPOCH_STATE_SCHEMAS) .. "\n",
        directory .. "/state.json"
    )
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

-- Commits the boundary the epoch pair has reached. The backup keeps the previous boundary until the caller
-- commits the pair after this. The machine is destroyed and its directory synced before state.json records
-- the boundary.
function stored_player_methods:commit_epoch_state(pair, builder, last_output)
    local directory = self.epoch_directory
    local files = get_boundary_files(self.input_count)
    store_forest(builder.frontier, directory, "mcycle", files.epoch_builder)
    hash_tree.frontier_store(self.outputs_frontier, directory .. "/" .. files.outputs_frontier)
    self.machine_cache:store(directory .. "/" .. files.machine_cache)
    if self.output_count > 0 then
        files.last_output = get_last_output_file(self.output_count)
    end
    if last_output.output_proof then
        self.last_output = last_output
        fs.write_durable_file(
            cartesi.tojson(last_output, 2, "LastOutput", EPOCH_STATE_SCHEMAS) .. "\n",
            directory .. "/" .. files.last_output
        )
        fs.sync_directory(directory)
    end
    local root_hash = pair.machine:get_root_hash()
    pair.machine:destroy()
    pair.machine:sync_stored(pair.directory)
    store_epoch_state(self, root_hash, files, builder.pad_bundle)
end

-- Commits a uarch claim the player built. Its bundles, once opened, are stored with its forest.
function stored_player_methods:store_uarch_claim(claim)
    local directory = self.epoch_directory
    local name = get_uarch_claim_name(claim.epoch_input_offset, claim.input_period_offset)
    store_forest(claim.tree.forest, directory, name, name .. ".json")
    store_epoch_state(self, self.final_state_hash, self.state_files)
end

-- Writes the files load_epoch_checkpoint reads next to the final machine stored in a checkpoint directory.
local function store_checkpoint_files(self, directory)
    local outputs_root = self.outputs_merkle_root_proof.tx_buffer_data
    if outputs_root ~= hash_tree.frontier_get_root_hash(self.outputs_frontier) then
        self:report_anomaly("outputs_merkle_root_mismatch", "at the epoch's end")
    end
    hash_tree.frontier_store(self.outputs_frontier, directory .. "/outputs-frontier.json")
    fs.write_durable_file(cartesi.tojson({
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

-- Stores the next epoch's checkpoint under <directory>.tmp and renames it into place, so the directory
-- holds a complete checkpoint or does not exist. An existing one comes from an earlier attempt at this seal.
local function store_next_epoch_checkpoint(self, machine, directory)
    if fs.exists(directory) then
        return
    end
    local temporary_directory = directory .. ".tmp"
    remove_leftover_stored_machine(temporary_directory)
    machine:store(temporary_directory)
    machine:sync_stored(temporary_directory)
    store_checkpoint_files(self, temporary_directory)
    cartesi.machine:rename_stored(temporary_directory, directory)
end

-- Commits the epoch seal. The mcycle forest replaces the open epoch's builder. The next epoch's checkpoint is
-- stored first, while the player still owns the final machine, so a seal resent after a crash stores it again.
function stored_player_methods:seal_epoch_state(pair)
    if self.checkpoint_directory then
        store_next_epoch_checkpoint(self, pair.machine, self.checkpoint_directory)
    end
    local directory = self.epoch_directory
    -- Sealing called the machine after the last boundary commit, so its directory is synced again.
    pair.machine:destroy()
    pair.machine:sync_stored(pair.directory)
    store_forest(self.mcycle_forest, directory, "mcycle", MCYCLE_FOREST_FILE)
    store_epoch_state(self, self.final_state_hash, {
        outputs_frontier = self.state_files.outputs_frontier,
        last_output = self.state_files.last_output,
        machine_cache = self.state_files.machine_cache,
        mcycle_forest = MCYCLE_FOREST_FILE,
    })
    -- A sealed epoch no longer needs the backup
    remove_leftover_stored_machine(pair.directory .. ".revert")
end

-- Stores the checkpoint epoch 0 starts from (the template machine with an empty output history) the
-- way store_next_epoch_checkpoint does.
local function store_first_epoch_checkpoint(template_directory, geometry, directory)
    if fs.exists(directory) then
        return
    end
    local temporary_directory = directory .. ".tmp"
    remove_leftover_stored_machine(temporary_directory)
    cartesi.machine:clone_stored(template_directory, temporary_directory)
    cartesi.machine:sync_stored(temporary_directory)
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
    fs.write_durable_file(cartesi.tojson({
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

-- Removes everything the layout creates from an epoch directory. Any other name raises an error, so a
-- wrong directory is never cleared.
local function clear_epoch_directory(directory)
    for _, name in ipairs(fs.list_directory(directory)) do
        local path = directory .. "/" .. name
        if
            name == "machine"
            or name == "machine.revert"
            or name == "pair"
            or name == "pair.revert"
            or name == "agreed"
            or name == "agreed.revert"
        then
            remove_leftover_stored_machine(path)
        elseif name == "entries" then
            for _, entry in ipairs(fs.list_directory(path)) do
                remove_leftover_stored_machine(path .. "/" .. entry)
            end
            fs.remove_directory(path)
        elseif name == "forests" then
            for _, forest in ipairs(fs.list_directory(path)) do
                remove_forest_directory(path .. "/" .. forest)
            end
            fs.remove_directory(path)
        elseif name == "inputs" then
            for _, file in ipairs(fs.list_directory(path)) do
                fs.remove_file(path .. "/" .. file)
            end
            fs.remove_directory(path)
        elseif name == "state.json" or is_epoch_file(name) then
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

-- Removes a retired epoch's checkpoint and epoch directory. The checkpoint is renamed to
-- <checkpoint>.removed first, so a crash leaves a name that another call with the same arguments
-- completes.
local function remove_epoch_files(checkpoint_directory, epoch_directory)
    local removed_directory = checkpoint_directory .. ".removed"
    if fs.exists(checkpoint_directory) then
        cartesi.machine:rename_stored(checkpoint_directory, removed_directory)
    end
    if fs.exists(epoch_directory) then
        remove_epoch_directory(epoch_directory)
    end
    remove_leftover_stored_machine(removed_directory)
end

-- Creates the layout of an epoch directory without a state.json.
local function create_epoch_directory(directory)
    clear_epoch_directory(directory)
    for _, name in ipairs(EPOCH_SUBDIRECTORIES) do
        fs.create_directory(directory .. "/" .. name)
    end
    fs.sync_directory(directory)
end

-- The root hash of a stored machine, rehashed from its contents, or nil when there is none or it cannot
-- be loaded. A clone is durable only after its sync, so after a power loss its cached hash tree may not
-- match its contents.
local function get_stored_root_hash(directory)
    if not fs.exists(directory) then
        return nil
    end
    local loaded, machine = pcall(cartesi.machine, directory, { clear_hash_tree = true })
    if not loaded then
        return nil
    end
    local stored <close> = machine
    return stored:get_root_hash()
end

-- Brings the epoch machine and its backup to the recorded boundary. The backup holds it, unless a crash
-- came before the commit replaced it, when the epoch machine, synced at that boundary, holds it instead.
local function revert_interrupted_input(directory, root_hash)
    local machine_directory = directory .. "/machine"
    local backup_directory = machine_directory .. ".revert"
    if get_stored_root_hash(backup_directory) == root_hash then
        remove_leftover_stored_machine(machine_directory)
        cartesi.machine:clone_stored(backup_directory, machine_directory)
        return
    end
    assert(get_stored_root_hash(machine_directory) == root_hash, "the epoch machine does not match its state")
    remove_leftover_stored_machine(backup_directory)
    cartesi.machine:clone_stored(machine_directory, backup_directory)
    cartesi.machine:sync_stored(backup_directory)
end

-- The files a state.json names, keyed by the field that names them.
local function get_state_files(state)
    return {
        epoch_builder = state.epoch_builder and state.epoch_builder.frontier,
        outputs_frontier = state.outputs_frontier,
        last_output = state.last_output,
        machine_cache = state.machine_cache,
        mcycle_forest = state.mcycle_forest,
    }
end

-- Removes everything state.json does not reach, including inputs past its count.
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
        remove_leftover_stored_machine(directory .. "/" .. leftover)
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
    local forests = { mcycle = true }
    for _, claim in ipairs(state.uarch_claims or {}) do
        forests[get_uarch_claim_name(claim.epoch_input_offset, claim.input_period_offset)] = true
    end
    for _, name in ipairs(fs.list_directory(directory .. "/forests")) do
        local path = directory .. "/forests/" .. name
        if forests[name] then
            remove_files(path)
        else
            remove_forest_directory(path)
        end
    end
    remove_files(directory .. "/inputs", state.input_count)
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

--------------------------------------------------------------------------------
-- Agreed pair
--
-- While a sealed epoch is in dispute, a stored player advances a machine toward the start of the dispute
-- interval in idle time, so a unit that needs a machine there starts next to it instead of at a distant
-- cache entry. The bisection handlers record the step they answer, and idle time interprets it. The pair
-- advances only while the mcycle claim's dispute interval lies inside one gap between consecutive cache
-- entries, and it starts at the gap's first entry. It runs on agreed/, and its backup agreed.revert holds
-- the input boundary it last committed, which units start from. The pair only saves replay, so a reopen
-- removes it.
--------------------------------------------------------------------------------

local function remove_agreed_directories(directory)
    for _, name in ipairs({ "/agreed", "/agreed.revert" }) do
        remove_leftover_stored_machine(directory .. name)
    end
end

local function drop_agreed_pair(self)
    if self.agreed_pair then
        self.agreed_pair:close()
        self.agreed_pair, self.agreed_entry = nil, nil
    end
    remove_agreed_directories(self.epoch_directory)
end

-- The pair's backup is the entry units start from.
local function set_agreed_entry(self, epoch_input_offset)
    self.agreed_entry = {
        epoch_input_offset = epoch_input_offset,
        directory = self.epoch_directory .. "/agreed.revert",
        root_hash = self.agreed_pair.machine:get_root_hash(),
    }
end

-- Advances the agreed pair by one input toward the start of the mcycle claim's dispute interval, and returns
-- whether more remains. A pair past that start, or outside the gap the interval lies in, is dropped. A uarch
-- claim's bisection stays inside the input of the mcycle claim's last interval and leaves the pair alone.
function stored_player_methods:advance_agreed_pair()
    local bisection = self.bisection
    if self.trees[bisection.computation_hash].forest ~= self.mcycle_forest then
        return false
    end
    local periods_per_input = self.geometry.periods_per_input
    local first = math.min(bisection.position // periods_per_input, self.input_count)
    local last = math.min((bisection.position + (1 << bisection.height) - 1) // periods_per_input, self.input_count)
    local start = find_nearest_entry(self.machine_cache, first)
    local inside = start == find_nearest_entry(self.machine_cache, last) and start.epoch_input_offset < first
    local offset = self.agreed_entry and self.agreed_entry.epoch_input_offset
    if offset and not (inside and start.epoch_input_offset <= offset and offset <= first) then
        drop_agreed_pair(self)
    end
    if not inside then
        return false
    end
    if not self.agreed_pair then
        local agreed_directory = self.epoch_directory .. "/agreed"
        remove_agreed_directories(self.epoch_directory)
        cartesi.machine:clone_stored(start.directory, agreed_directory)
        local pair <close> =
            new_stored_machine_pair(new_stored_machine(start.root_hash, agreed_directory), agreed_directory)
        self.agreed_pair = pair:move()
        set_agreed_entry(self, start.epoch_input_offset)
        return true
    end
    offset = self.agreed_entry.epoch_input_offset
    if offset == first then
        return false
    end
    self:run_to_epoch_input_offset(self.agreed_pair, offset, offset + 1)
    set_agreed_entry(self, offset + 1)
    return offset + 1 < first
end

-- Pending inputs come first. A sealed epoch has none, and advances its agreed pair once it bisects.
function stored_event_handler.idle(self)
    if self:has_pending_input() then
        return event_handler.idle(self)
    end
    return self.bisection ~= nil and self:advance_agreed_pair()
end

-- The bisection handlers record the step they answer, which idle time interprets.
function stored_event_handler.reveal_bisection(self, computation_hash, position, height, other_left_node)
    self.bisection = { computation_hash = computation_hash, position = position, height = height }
    return event_handler.reveal_bisection(self, computation_hash, position, height, other_left_node)
end

function stored_event_handler.seal_divergence(self, computation_hash, position, other_left_node)
    self.bisection = { computation_hash = computation_hash, position = position, height = 1 }
    return event_handler.seal_divergence(self, computation_hash, position, other_left_node)
end

-- A unit starts from the agreed pair's backup when it is nearer than the cache entry, without going past.
function stored_player_methods:new_machine_pair_at_epoch_input_offset(epoch_input_offset)
    local entry = self.agreed_entry
    if
        entry
        and entry.epoch_input_offset <= epoch_input_offset
        and entry.epoch_input_offset > find_nearest_entry(self.machine_cache, epoch_input_offset).epoch_input_offset
    then
        local pair <close> = self.machine_cache:new_machine_pair_from_entry(entry)
        self:run_to_epoch_input_offset(pair, entry.epoch_input_offset, epoch_input_offset)
        return pair:move()
    end
    return player_meta.__index.new_machine_pair_at_epoch_input_offset(self, epoch_input_offset)
end

-- The agreed pair's machine is released with the player's.
stored_player_meta.__close = function(self)
    if self.agreed_pair then
        self.agreed_pair:close()
        self.agreed_pair = nil
    end
    player_meta.__close(self)
end

-- Reopens an epoch directory at the boundary or seal its state.json records. An open epoch gets
-- its epoch pair and builder back. A sealed epoch restores and registers its mcycle and uarch
-- trees, with no epoch pair.
local function reopen_epoch_directory(self)
    local directory = self.epoch_directory
    local state = cartesi.fromjson(fs.read_file(directory .. "/state.json"), "EpochState", EPOCH_STATE_SCHEMAS)
    assert(state.version == 4, "unsupported epoch state version")
    assert(
        cartesi.fromhex(state.initial_outputs_merkle_root)
            == hash_tree.frontier_get_root_hash(self.previous_outputs_frontier),
        "the epoch directory continues a different output history"
    )
    local root_hash = cartesi.fromhex(state.root_hash)
    revert_interrupted_input(directory, root_hash)
    local machine_directory = directory .. "/machine"
    self.machine_cache =
        load_stored_machine_cache(directory, machine_directory, directory .. "/" .. state.machine_cache)
    remove_epoch_leftovers(directory, state, self.machine_cache)
    self.state_files = get_state_files(state)
    self.input_count, self.output_count = state.input_count, state.output_count
    -- Pending inputs are not stored. A restarted bridge delivers them again.
    self.pending_input_count = 0
    self.epoch_stopped = state.epoch_stopped
    if self.epoch_stopped then
        -- The stored flag does not identify the original stopping input or cause.
        self:report_anomaly("execution_stopped", "when reopening an already stopped epoch")
    end
    self.outputs_frontier = load_outputs_frontier(directory .. "/" .. state.outputs_frontier)
    assert(
        hash_tree.frontier_get_leaf_count(self.outputs_frontier)
            == hash_tree.frontier_get_leaf_count(self.previous_outputs_frontier) + self.output_count,
        "the outputs frontier does not match the output count"
    )
    if state.last_output then
        self.last_output =
            cartesi.fromjson(fs.read_file(directory .. "/" .. state.last_output), "LastOutput", EPOCH_STATE_SCHEMAS)
        assert(
            self.last_output.output_proof.root_hash == hash_tree.frontier_get_root_hash(self.outputs_frontier),
            "the last output does not match the outputs frontier"
        )
    end
    local forests_directory = directory .. "/forests"
    if state.epoch_builder then
        self.epoch_pair = new_stored_machine_pair(new_stored_machine(root_hash, machine_directory), machine_directory)
        if
            not self.epoch_stopped
            and self.epoch_pair.machine:read_memory(CMIO_TX_BUFFER_ADDRESS, WORD_SIZE)
                ~= hash_tree.frontier_get_root_hash(self.outputs_frontier)
        then
            self:report_anomaly("outputs_merkle_root_mismatch", "at input %d", self.input_count)
        end
        local builder = self:new_mcycle_computation_hash_builder()
        builder.frontier = hash_tree.frontier_forest_load(
            forests_directory .. "/mcycle",
            directory .. "/" .. state.epoch_builder.frontier
        )
        builder.pad_bundle = new_mcycle_pad_bundle(
            get_mcycle_sample_hash(self.epoch_pair.machine),
            builder.bundle_height,
            cartesi.fromhex(state.epoch_builder.pad_bundle)
        )
        builder.input_bundle_count = 0
        self.epoch_builder = builder
        return
    end
    -- A sealed epoch no longer needs the backup
    remove_leftover_stored_machine(machine_directory .. ".revert")
    remove_agreed_directories(directory)
    self.final_state_hash = root_hash
    self.outputs_merkle_root_proof = state.outputs_merkle_root_proof
    if self.outputs_merkle_root_proof.tx_buffer_data ~= hash_tree.frontier_get_root_hash(self.outputs_frontier) then
        self:report_anomaly("outputs_merkle_root_mismatch", "at the epoch's end")
    end
    self.mcycle_forest =
        hash_tree.frontier_forest_load(forests_directory .. "/mcycle", directory .. "/" .. state.mcycle_forest)
    local mcycle_tree = self:new_mcycle_tree()
    self.trees[mcycle_tree:get_root_hash()] = mcycle_tree
    for _, stored in ipairs(state.uarch_claims) do
        local forest = hash_tree.frontier_forest_load(
            forests_directory .. "/" .. get_uarch_claim_name(stored.epoch_input_offset, stored.input_period_offset),
            directory .. "/" .. stored.forest
        )
        local tree = self:new_uarch_tree(stored.epoch_input_offset, stored.input_period_offset, forest)
        self.uarch_claims[#self.uarch_claims + 1] = {
            epoch_input_offset = stored.epoch_input_offset,
            input_period_offset = stored.input_period_offset,
            tree = tree,
        }
        self.trees[tree:get_root_hash()] = tree
    end
end

-- A stored player runs on stored machines in an existing epoch directory and reopens the epoch that
-- directory holds. With a checkpoint directory, the epoch seal stores the next epoch's checkpoint there.
local function new_stored_player(
    dapp_contract,
    label,
    previous_outputs_frontier,
    epoch_directory,
    checkpoint_directory,
    anomaly_handler
)
    local self <close> =
        new_empty_player(stored_player_meta, dapp_contract, label, previous_outputs_frontier, anomaly_handler)
    self.event_handler = stored_event_handler
    self.epoch_directory = epoch_directory
    self.checkpoint_directory = checkpoint_directory
    if fs.exists(epoch_directory .. "/state.json") then
        reopen_epoch_directory(self)
        return self:move()
    end
    local initial_state_hash = dapp_contract.initial_state_hash
    create_epoch_directory(epoch_directory)
    local machine_directory = epoch_directory .. "/machine"
    cartesi.machine:clone_stored(
        dapp_contract.machine_directory or cartesi.tohex(initial_state_hash),
        machine_directory
    )
    -- The epoch's first machine rebuilds its hash tree, so nothing cached in the clone affects the epoch.
    self.epoch_pair = new_stored_machine_pair(
        new_stored_machine(initial_state_hash, machine_directory, { clear_hash_tree = true }),
        machine_directory
    )
    self.machine_cache = new_stored_machine_cache(epoch_directory, machine_directory, self.epoch_pair.machine)
    open_epoch(self)
    self:commit_epoch_state(self.epoch_pair, self.epoch_builder, {})
    self.epoch_pair:commit()
    return self:move()
end

-- Restore the public bootstrap inputs, leaving machine ownership to the player.
local function load_epoch_checkpoint(directory)
    local manifest = cartesi.fromjson(fs.read_file(directory .. "/epoch.json"))
    assert(manifest.version == 2, "unsupported player checkpoint version")
    assert(
        math.type(manifest.output_count) == "integer" and manifest.output_count >= 0,
        "invalid checkpoint output count"
    )
    local frontier = load_outputs_frontier(directory .. "/outputs-frontier.json")
    assert(hash_tree.frontier_get_leaf_count(frontier) == manifest.output_count, "checkpoint output count mismatch")
    return {
        initial_state_hash = cartesi.fromhex(manifest.final_state_hash),
        machine_directory = directory,
        geometry = new_geometry(manifest.log2_mcycles_per_period),
    },
        frontier,
        manifest
end

return {
    load_epoch_checkpoint = load_epoch_checkpoint,
    store_first_epoch_checkpoint = store_first_epoch_checkpoint,
    remove_epoch_directory = remove_epoch_directory,
    remove_epoch_files = remove_epoch_files,
    new_stored_player = new_stored_player,
    stored_event_handler = stored_event_handler,
}
