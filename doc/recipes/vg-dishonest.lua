-- Complete dishonest VG roles. Their local execution choices confer no right to
-- answer for another player.
--   vg-dishonest.lua forger <address> <initial-hash> <input-index> <private-file>
--   vg-dishonest.lua fabulist <address> <initial-hash> <input-index> <private-file> <claimed-hash>
--   vg-dishonest.lua tamperer <address> <initial-hash> <input-index> <mcycle-offset>
--   vg-dishonest.lua no-rollback <address> <initial-hash>
--   vg-dishonest.lua quitter <address> <initial-hash>
--   vg-dishonest.lua idle <address> <initial-hash>
local cartesi = require("cartesi")
local util = require("cartesi.util")
local vg = require("vg")
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

local fabulist_events = setmetatable({}, { __index = vg.event_handler })
function fabulist_events:commit_claim()
    return self.claimed_final_hash
end

-- Copy a final claim while answering every bisection with the forger's history.
local function new_fabulist(initial_hash, input_index, private_path, claimed_final_hash)
    assert(type(claimed_final_hash) == "string" and #claimed_final_hash == 32, "invalid claimed final hash")
    local player = new_forger(initial_hash, input_index, private_path)
    player.label = "fabulist"
    player.claimed_final_hash = claimed_final_hash
    player.event_handler = fabulist_events
    return player
end

local function no_defense()
    error("the idle player never supplies a defense")
end

local idle_events = setmetatable({}, { __index = vg.event_handler })
function idle_events:reveal_bisection()
    return vgu.schedule_response(self, math.maxinteger, no_defense)
end

-- Compute and claim honestly, then let the first bisection request time out.
local function new_idle(initial_hash)
    local player = vg.new_player(initial_hash, "idle")
    player.event_handler = idle_events
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
        input_mcycle_base = self.input_mcycle_base,
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
    self.input_mcycle_base = self.machine:read_reg("mcycle")
    return self.machine:send_cmio_response(reason, data, revert_root_hash)
end

function tampered_machine_meta_methods:run(mcycle_end)
    if self.epoch_input_offset == self.tampered_index and not self.tampered then
        local point = vg.usaturating_add(self.input_mcycle_base, self.tampered_offset)
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
        and self.machine:read_reg("mcycle") == vg.usaturating_add(self.input_mcycle_base, self.tampered_offset)
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
    local function new_tampered_machine(self, initial_state_hash)
        return setmetatable({
            machine = vg.player_methods.new_machine(self, initial_state_hash),
            epoch_input_offset = -1,
            tampered_index = input_index,
            tampered_offset = input_mcycle_offset,
        }, tampered_machine_meta)
    end
    return vg.new_player(initial_hash, "tamperer", nil, { new_machine = new_tampered_machine })
end

local function ignore_rollback(pair)
    pair:commit()
end

local function new_no_rollback_pair(self, epoch_input_offset)
    local pair = vg.player_methods.new_machine_pair_at_epoch_input_offset(self, epoch_input_offset)
    pair.revert = ignore_rollback
    return pair
end

local function new_no_rollback(initial_hash)
    local player = vg.new_player(initial_hash, "no-rollback", nil, {
        new_machine_pair_at_epoch_input_offset = new_no_rollback_pair,
    })
    player.epoch_pair.revert = ignore_rollback
    return player
end

local function acknowledge() end
local function quit(self)
    self.done = true
    return cartesi.keccak256("a fabricated final state")
end
local quitter_events = {
    input_added = acknowledge,
    epoch_sealed = acknowledge,
    commit_claim = quit,
}
local function close_quitter() end
local quitter_meta = { __close = close_quitter }
local function new_quitter()
    return setmetatable({ label = "quitter", event_handler = quitter_events }, quitter_meta)
end
local roles = {
    new_forger = new_forger,
    new_fabulist = new_fabulist,
    new_idle = new_idle,
    new_tamperer = new_tamperer,
    new_no_rollback = new_no_rollback,
    new_quitter = new_quitter,
}
if ... == "vg-dishonest" then
    return roles
end
local role, address = assert(arg[1], "missing role"), assert(arg[2], "missing referee address")
local initial_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
local selected
if role == "forger" then
    selected = new_forger(initial_hash, assert(tonumber(arg[4])), assert(arg[5]))
elseif role == "fabulist" then
    selected = new_fabulist(initial_hash, assert(tonumber(arg[4])), assert(arg[5]), cartesi.fromhex(assert(arg[6])))
elseif role == "idle" then
    selected = new_idle(initial_hash)
elseif role == "tamperer" then
    selected = new_tamperer(initial_hash, assert(tonumber(arg[4])), assert(tonumber(arg[5])))
elseif role == "no-rollback" then
    selected = new_no_rollback(initial_hash)
elseif role == "quitter" then
    selected = new_quitter()
else
    error("unknown role: " .. role)
end
local player <close> = selected
vgu.run_client(player, address)
