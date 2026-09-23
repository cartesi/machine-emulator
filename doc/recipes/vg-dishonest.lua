-- Complete dishonest VG roles. Their local execution choices confer no right to
-- answer for another player. The fabulist is a test-only outsider in vg-test.lua.
--   vg-dishonest.lua forger <address> <initial-hash> <input-index> <private-file>
--   vg-dishonest.lua tamperer <address> <initial-hash> <input-index> <mcycle-offset>
--   vg-dishonest.lua quitter <address> <initial-hash>
local cartesi = require("cartesi")
local util = require("cartesi.util")
local vg = require("rolling-verification-game")
local vgu = require("vgu")

local function read_forged_input(self, index, filename)
    return util.read_file(index == self.forged_index and self.private_filename or filename)
end
local function new_forger(initial_hash, input_index, private_filename)
    local player = vg.new_player(initial_hash, "forger")
    player.forged_index, player.private_filename = input_index, private_filename
    player.read_input = read_forged_input
    return player
end

local function corrupt(self, entry)
    if entry.strategy.tampered or entry.input_index ~= self.tampered_index then
        return
    end
    local config = entry.machine:get_initial_config()
    entry.machine:write_memory(cartesi.AR_RAM_START + config.ram.length - 8, "CORRUPT!")
    entry.strategy.tampered = true
end
local function run_tampered(self, entry, target, sink)
    if entry.input_index == self.tampered_index and not entry.strategy.tampered then
        local point = vg.usaturating_add(entry.input_mcycle_boundary, self.tampered_offset)
        if math.ult(point, target) then
            vg.player_methods.run_to(self, entry, point, sink)
            if entry.machine:read_reg("mcycle") == point then
                corrupt(self, entry)
            end
        end
    end
    return vg.player_methods.run_to(self, entry, target, sink)
end
local function run_tampered_uarch(self, entry, target)
    if entry.input_mcycle_offset == self.tampered_offset and target > 0 then
        corrupt(self, entry)
    end
    return vg.player_methods.run_uarch(self, entry, target)
end
local function new_tamperer(initial_hash, input_index, mcycle_offset)
    local player = vg.new_player(initial_hash, "tamperer")
    player.tampered_index, player.tampered_offset = input_index, mcycle_offset
    player.run_to, player.run_uarch = run_tampered, run_tampered_uarch
    return player
end

local function acknowledge()
    return true
end
local function quit(self)
    self.done = true
    return cartesi.keccak256("a fabricated final state")
end
local quitter_events = {
    initial_state = acknowledge,
    input_added = acknowledge,
    epoch_sealed = acknowledge,
    commit_final_hash = quit,
}
local function close_quitter() end
local quitter_meta = { __close = close_quitter }
local function new_quitter()
    return setmetatable({ label = "quitter", event_handler = quitter_events }, quitter_meta)
end
local roles = { new_forger = new_forger, new_tamperer = new_tamperer, new_quitter = new_quitter }
if ... == "vg-dishonest" then
    return roles
end
local role, address = assert(arg[1], "missing role"), assert(arg[2], "missing referee address")
local initial_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
local selected
if role == "forger" then
    selected = new_forger(initial_hash, assert(tonumber(arg[4])), assert(arg[5]))
elseif role == "tamperer" then
    selected = new_tamperer(initial_hash, assert(tonumber(arg[4])), assert(tonumber(arg[5])))
elseif role == "quitter" then
    selected = new_quitter()
else
    error("unknown role: " .. role)
end
local player <close> = selected
vgu.run_client(player, address)
