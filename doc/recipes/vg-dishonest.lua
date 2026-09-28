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
-- Execution overrides live on the dishonest machine, leaving the shared input
-- lifecycle intact. Forking preserves the strategy; rollback restores corruption
-- state while the logical input index continues past the rejected input.
local tampered_machine_meta_methods = {}
local tampered_machine_meta = {
    __index = function(self, name)
        return tampered_machine_meta_methods[name] or util.forward_method(self, self.machine, name)
    end,
}

function tampered_machine_meta_methods:shutdown_server()
    self.machine:shutdown_server()
end
tampered_machine_meta.__close = tampered_machine_meta_methods.shutdown_server

function tampered_machine_meta_methods:fork_server()
    return setmetatable({
        machine = assert(self.machine:fork_server()),
        epoch_input_offset = self.epoch_input_offset,
        input_mcycle_boundary = self.input_mcycle_boundary,
        tampered_index = self.tampered_index,
        tampered_offset = self.tampered_offset,
        tampered = self.tampered,
    }, tampered_machine_meta)
end

function tampered_machine_meta_methods:swap(other)
    self.machine:swap(other.machine)
    self.tampered, other.tampered = other.tampered, self.tampered
end

function tampered_machine_meta_methods:send_cmio_response(reason, data, revert_root_hash)
    self.epoch_input_offset = self.epoch_input_offset + 1
    self.input_mcycle_boundary = self.machine:read_reg("mcycle")
    return self.machine:send_cmio_response(reason, data, revert_root_hash)
end

function tampered_machine_meta_methods:run(mcycle_end)
    if self.epoch_input_offset == self.tampered_index and not self.tampered then
        local point = vg.usaturating_add(self.input_mcycle_boundary, self.tampered_offset)
        if math.ult(point, mcycle_end) then
            local break_reason = self.machine:run(point)
            if break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                return break_reason
            end
            if self.machine:read_reg("mcycle") == point then
                corrupt(self.machine)
                self.tampered = true
            end
        end
    end
    return self.machine:run(mcycle_end)
end

function tampered_machine_meta_methods:run_uarch(uarch_cycle_end)
    if
        self.epoch_input_offset == self.tampered_index
        and self.machine:read_reg("mcycle") == vg.usaturating_add(self.input_mcycle_boundary, self.tampered_offset)
        and self.machine:read_reg("uarch_cycle") == 0
        and uarch_cycle_end > 0
        and not self.tampered
    then
        corrupt(self.machine)
        self.tampered = true
    end
    return self.machine:run_uarch(uarch_cycle_end)
end

local function new_tamperer(initial_hash, input_index, input_mcycle_offset)
    local player = vg.new_player(initial_hash, "tamperer")
    for _, pair in ipairs({ player.initial, player.latest, player.agreed_machine, player.tentative_machine }) do
        for _, key in ipairs({ "machine", "backup" }) do
            pair[key] = setmetatable({
                machine = pair[key],
                epoch_input_offset = -1,
                tampered_index = input_index,
                tampered_offset = input_mcycle_offset,
            }, tampered_machine_meta)
        end
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
