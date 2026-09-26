-- Complete dishonest VG roles. Their local execution choices confer no right to
-- answer for another player. The fabulist is a test-only outsider in vg-test.lua.
--   vg-dishonest.lua forger <address> <initial-hash> <input-index> <private-file>
--   vg-dishonest.lua tamperer <address> <initial-hash> <input-index> <mcycle-offset>
--   vg-dishonest.lua quitter <address> <initial-hash>
local cartesi = require("cartesi")
local util = require("cartesi.util")
local vg = require("rolling-verification-game")
local vgu = require("vgu")

local function read_forged_input(self, index, path)
    return util.read_file(index == self.forged_index and self.private_path or path)
end
local function new_forger(initial_hash, input_index, private_path)
    local player = vg.new_player(initial_hash, "forger")
    player.forged_index, player.private_path = input_index, private_path
    player.read_input = read_forged_input
    return player
end

local function corrupt(machine)
    local config = machine:get_initial_config()
    machine:write_memory(cartesi.AR_RAM_START + config.ram.length - 8, "CORRUPT!")
end
local function run_tampered(self, pair, epoch_input_offset, mcycle_end, on_yield_automatic)
    if epoch_input_offset == self.tampered_index and not pair.tampered then
        local point = vg.usaturating_add(pair.backup:read_reg("mcycle"), self.tampered_offset)
        if math.ult(point, mcycle_end) then
            local break_reason, yield_reason, data =
                vg.player_methods.run_to_stop(self, pair, epoch_input_offset, point, on_yield_automatic)
            if break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                return break_reason, yield_reason, data
            end
            if pair.machine:read_reg("mcycle") == point then
                corrupt(pair.machine)
                pair.tampered = true
            end
        end
    end
    return vg.player_methods.run_to_stop(self, pair, epoch_input_offset, mcycle_end, on_yield_automatic)
end
local function run_tampered_uarch(self, pair, epoch_input_offset, input_mcycle_offset, target)
    local machine = pair.machine
    local cycle = machine:read_reg("uarch_cycle")
    if input_mcycle_offset == 0 and cycle == 0 and target > 0 then
        self:run_advance_state_input(pair, epoch_input_offset, 0)
    end
    if
        epoch_input_offset == self.tampered_index
        and input_mcycle_offset == self.tampered_offset
        and cycle == 0
        and target > 0
    then
        corrupt(machine)
        pair.tampered = true
    end
    return machine:run_uarch(target)
end
-- Only the dishonest role knows how to snapshot and restore its bookkeeping.
-- Forking the pair carries these scalar fields and shared methods with it.
local function snapshot_tampered(pair)
    vg.advancing_pair_methods.snapshot(pair)
    pair.tampered_before_input = pair.tampered
end
local function commit_tampered(pair)
    vg.advancing_pair_methods.commit(pair)
    pair.tampered_before_input = nil
end
local function revert_tampered(pair)
    local tampered = pair.tampered_before_input
    vg.advancing_pair_methods.revert(pair)
    pair.tampered = tampered
end
local function new_tamperer(initial_hash, input_index, mcycle_offset)
    local player = vg.new_player(initial_hash, "tamperer")
    player.tampered_index, player.tampered_offset = input_index, mcycle_offset
    player.run_to_stop, player.run_uarch = run_tampered, run_tampered_uarch
    for _, pair in ipairs({ player.initial, player.latest, player.agreed }) do
        pair.snapshot, pair.commit, pair.revert = snapshot_tampered, commit_tampered, revert_tampered
    end
    return player
end

local function acknowledge() end
local function quit(self)
    self.done = true
    return cartesi.keccak256("a fabricated final state")
end
local quitter_events = {
    initial_state = acknowledge,
    input_added = acknowledge,
    epoch_sealed = acknowledge,
    commit_claim = quit,
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
