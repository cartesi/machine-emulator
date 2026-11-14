-- Drives the PRT stored player (doc/recipes/prt.lua, loaded as a module, unchanged) for bugs/R1-O2-1/test.lua.
--
--   lua5.4 player.lua <mode> <epoch_directory> <template_directory> <input0> [<input1> ...]
--
-- mode "run":   open (or reopen) the stored player in <epoch_directory>, deliver every input as the
--               chain listener does (a relaunched listener delivers the earlier ones again), run them in idle
--               time, close the player, and print "ROOT <hex>" with the root hash its state.json records.
-- mode "crash": open the stored player, deliver <input0> and run it, with a model of a power loss of the
--               host: the process dies (os.exit, no cleanup) right before the player syncs the clone of the
--               epoch machine it makes for its backup, and that unsynced clone loses one 4 KiB block of its
--               cached hash-tree data (as unflushed delayed-allocation data reads back as a hole). Nothing
--               else is touched: every directory the player had already synced stays as it was.
--               Exits 99 when the modelled power loss happened, 3 if the player never synced such a clone.
local mode, epoch_directory, template_directory = arg[1], arg[2], arg[3]
local input_paths = table.pack(table.unpack(arg, 4))

local cartesi = require("cartesi")
local prt = require("prt")

local function read_file(path)
    local f = assert(io.open(path, "rb"))
    local s = f:read("a")
    f:close()
    return s
end

local initial_state_hash
do
    local m <close> = cartesi.machine(template_directory, { clear_hash_tree = true })
    initial_state_hash = m:get_root_hash()
end

local dapp_contract = {
    initial_state_hash = initial_state_hash,
    machine_directory = template_directory,
    geometry = prt.new_geometry(10),
    max_allowance = 4,
    response_budget = 4,
}

local function find_ram_dht(directory)
    local p = io.popen("ls '" .. directory .. "'")
    local name
    for line in p:lines() do
        if line:match("^0000000080000000%-%x+%.dht$") then
            name = line
        end
    end
    p:close()
    return assert(name and directory .. "/" .. name, "no RAM dense hash tree in " .. directory)
end

-- The power loss model: one 4 KiB block of the RAM dense hash tree (for the 64 MiB RAM: tree indices
-- 16384..16511, the leaf hashes of RAM pages 0..127, 32 bytes each) reads back as zeros.
local function lose_writeback(directory)
    local dht = find_ram_dht(directory)
    local f = assert(io.open(dht, "r+b"))
    assert(f:seek("set", 16384 * 32))
    assert(f:write(string.rep("\0", 4096)))
    f:close()
end

if mode == "crash" then
    -- The clones made after arming whose sync has not happened yet.
    local index = debug.getmetatable(cartesi.machine).__index
    local clone_stored, sync_stored = index.clone_stored, index.sync_stored
    local armed, unsynced = false, {}
    local epoch_machine = epoch_directory .. "/machine"
    index.clone_stored = function(self, from, to, ...)
        clone_stored(self, from, to, ...)
        -- The backup of the epoch pair is a clone of the epoch machine (machine cache entries also are,
        -- but they are synced at once and are not the subject of this test).
        if armed and from == epoch_machine and not to:find("/entries/", 1, true) then
            unsynced[to] = true
        end
    end
    index.sync_stored = function(self, directory, ...)
        if armed and unsynced[directory] then
            lose_writeback(directory)
            io.stdout:write("POWER LOSS before syncing ", directory, "\n")
            io.stdout:flush()
            os.exit(99, false) -- no __close, no __gc: the process is gone
        end
        return sync_stored(self, directory, ...)
    end
    local player = prt.new_stored_player(dapp_contract, "honest", nil, epoch_directory)
    armed = true
    player.event_handler.input_added(player, 0, input_paths[1])
    while player.event_handler.idle(player) do
    end
    io.stdout:write("no unsynced backup clone was ever synced\n")
    os.exit(3, false)
elseif mode == "run" then
    do
        local player <close> = prt.new_stored_player(dapp_contract, "honest", nil, epoch_directory)
        for i = 1, input_paths.n do
            player.event_handler.input_added(player, i - 1, input_paths[i])
        end
        while player.event_handler.idle(player) do
        end
        assert(player.input_count == input_paths.n, "not every input ran")
    end
    local state = cartesi.fromjson(read_file(epoch_directory .. "/state.json"))
    io.stdout:write("ROOT ", state.root_hash, "\n")
    os.exit(0, true)
else
    error("unknown mode " .. tostring(mode))
end
