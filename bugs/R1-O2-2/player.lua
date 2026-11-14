-- Child process of test.lua: one run of the PRT stored player (doc/recipes/prt.lua) on an epoch directory.
--
--   lua5.4 player.lua seal-crash <epoch_dir> <template_dir> <root_hex> <input_file>
--       Opens a new epoch, runs one input and seals the epoch. The process stops abruptly (os.exit without
--       closing anything, like kill -9) at the moment seal_epoch_state has committed the sealed state.json
--       and is about to remove machine.revert. Exits 17 when it stopped there.
--   lua5.4 player.lua reopen <epoch_dir> <template_dir> <root_hex>
--       Relaunch: reopens the epoch directory as the player does after a stop. Exits 0 on success, 3 if the
--       reopen raised an error (message on stderr).
--   lua5.4 player.lua reopen-synced-clone <epoch_dir> <template_dir> <root_hex>
--       Control: the same reopen, with every clone_stored followed by sync_stored (what a fix could do).
local cartesi = require("cartesi")
local fs = require("cartesi.filesystem")
local prt = require("prt")

local mode, epoch_directory, template_directory, root_hex, input_file = table.unpack(arg)

local dapp_contract = {
    initial_state_hash = cartesi.fromhex(root_hex),
    machine_directory = template_directory,
    geometry = prt.new_geometry(10),
    inputs = {},
}

if mode == "seal-crash" then
    local player = prt.new_stored_player(dapp_contract, "honest", nil, epoch_directory)
    player.event_handler.input_added(player, 0, input_file)
    repeat
    until not player.event_handler.idle(player)
    -- Stop at the first look for machine.revert once the sealed state.json is committed (seal_epoch_state:
    -- "A sealed epoch no longer needs the backup").
    local backup = epoch_directory .. "/machine.revert"
    local exists = fs.exists
    fs.exists = function(path, ...)
        if path == backup then
            local state = cartesi.fromjson(fs.read_file(epoch_directory .. "/state.json"))
            if state.mcycle_forest and not state.epoch_builder then
                io.stderr:write("player: stopped after the sealed state.json commit, before removing machine.revert\n")
                io.stderr:flush()
                os.exit(17, false) -- no __close/__gc: the disk is left as a kill -9 leaves it
            end
        end
        return exists(path, ...)
    end
    player.event_handler.epoch_sealed(player, 1)
    io.stderr:write("player: the seal completed without reaching the injection point\n")
    os.exit(4, false)
elseif mode == "reopen" or mode == "reopen-synced-clone" then
    if mode == "reopen-synced-clone" then
        -- Control only (a stand-in for a fix): every clone is synced right after it is made.
        local methods = getmetatable(cartesi.machine).__index
        local clone_stored = methods.clone_stored
        methods.clone_stored = function(self, from, to)
            clone_stored(self, from, to)
            methods.sync_stored(self, to)
        end
    end
    local ok, err = pcall(function()
        local player <close> = prt.new_stored_player(dapp_contract, "honest", nil, epoch_directory)
        assert(player.final_state_hash, "the reopened epoch is not sealed")
        assert(player.mcycle_forest, "the reopened epoch has no mcycle forest")
    end)
    if not ok then
        io.stderr:write("player: reopen failed: ", tostring(err), "\n")
        os.exit(3, false)
    end
    os.exit(0, true)
else
    io.stderr:write("player: unknown mode ", tostring(mode), "\n")
    os.exit(2, false)
end
