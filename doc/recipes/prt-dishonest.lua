-- Dishonest players use the same driver, claims, and protocol handlers as the honest
-- player. Only their machine or computation-hash object tells a different history.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local cartesi_jsonrpc = require("cartesi.jsonrpc")
local prtu = require("prtu")
local util = require("cartesi.util")
local keccak = cartesi.keccak256

-- Machine and computation-hash wrappers belong to the strategies, not the honest
-- implementation. A native machine never carries this private input bookkeeping.
local machine_methods = {}
local machine_meta = {
    __close = function(self)
        local machine <close> = self.machine -- luacheck: ignore 211
    end,
    __index = function(self, name)
        local method = self.overrides[name] or machine_methods[name]
        if not method then
            method = function(object, ...)
                return object.machine[name](object.machine, ...)
            end
            machine_methods[name] = method
        end
        return method
    end,
}

local function wrap_machine(machine, overrides)
    return setmetatable({ machine = machine, overrides = overrides, state = {} }, machine_meta)
end

function machine_methods:fork_server()
    local fork = wrap_machine(assert(self.machine:fork_server()), self.overrides)
    fork:set_cleanup_call(cartesi_jsonrpc.SHUTDOWN)
    for key, value in pairs(self.state) do
        fork.state[key] = value
    end
    return fork
end

function machine_methods:swap(other)
    self.machine:swap(other.machine)
    self.state, other.state = other.state, self.state
end

-- Call the original collector methods with the wrapper as self, so internal
-- calls pass through its overrides too. Collector state stays on the original.
local function wrap_computation_hash(claim, overrides)
    return setmetatable({}, {
        __index = function(_, name)
            local value = overrides[name]
            if value ~= nil then
                return value
            end
            return claim[name]
        end,
        __newindex = function(_, name, value)
            claim[name] = value
        end,
    })
end

local function begin_input(machine, input_index, input_base)
    if machine.state.input_index ~= input_index or machine.state.input_base ~= input_base then
        machine.state = { input_index = input_index, input_base = input_base }
    end
end

local function observe_input(claim, machine)
    return wrap_computation_hash(claim, {
        begin_input = function(self, input_index, input_base, revert_to)
            begin_input(machine, input_index, input_base)
            return claim.begin_input(self, input_index, input_base, revert_to)
        end,
    })
end

-- The collectors already receive input coordinates, including plain replay's
-- null collector. Observe that lifecycle to supply the strategy's private state.
-- The input-inclusion proof logs delivery directly, so its handler supplies the
-- index for that one path. No extra machine methods are required by the player.
local function use_machine(player, overrides)
    local proof_input
    local log_send = overrides.log_send_cmio_response
    overrides.log_send_cmio_response = function(machine, ...)
        if proof_input ~= nil then
            begin_input(machine, proof_input, machine:read_reg("mcycle"))
        end
        if log_send then
            return log_send(machine, ...)
        end
        return machine.machine:log_send_cmio_response(...)
    end
    local prove = player.prove_state_transition
    player.prove_state_transition = function(self, input_index, ...)
        proof_input = input_index
        local result = prove(self, input_index, ...)
        proof_input = nil
        return result
    end
    local new_machine = player.new_machine
    player.new_machine = function(initial_state_hash)
        return wrap_machine(new_machine(initial_state_hash), overrides)
    end
    for _, checkpoint in ipairs(player.machine_cache.checkpoints) do
        checkpoint.machine = wrap_machine(checkpoint.machine, overrides)
    end
    for _, name in ipairs({ "new_mcycle_computation_hash", "new_uarch_computation_hash" }) do
        local make = player[name]
        player[name] = function(self, machine, window)
            return observe_input(make(self, machine, window), machine)
        end
    end
    local new_null = player.new_null_computation_hash
    player.new_null_computation_hash = function(machine)
        return observe_input(new_null(machine), machine)
    end
    return player
end

local function role_options(label, options)
    local result = {}
    for key, value in pairs(options or {}) do
        result[key] = value
    end
    result.label = label
    return result
end

-- The forged bytes enter through the machine, including when producing the input
-- transition's log. The contract inputs remain untouched and verification trusts them.
local function new_forger(dapp_contract, input_index, forged_data, options)
    local player = prt.new_honest(dapp_contract, role_options("forger", options))
    local overrides = {}
    for _, name in ipairs({ "send_cmio_response", "log_send_cmio_response" }) do
        overrides[name] = function(machine, reason, data, revert_state_hash)
            if machine.state.input_index == input_index then
                data = forged_data
            end
            return machine.machine[name](machine.machine, reason, data, revert_state_hash)
        end
    end
    return use_machine(player, overrides)
end

-- A checkpoint exactly at the corruption point still holds the agreed state.
-- Corruption happens only when executing or collecting the transition out of it.
-- The private machine wrapper copies this state on fork and restores it on rollback.
local function new_tamperer(dapp_contract, input_index, bundle_offset, options)
    local player = prt.new_honest(dapp_contract, role_options("tamperer", options))
    local offset = bundle_offset << (prt.LOG2_MCYCLE_BUNDLE + dapp_contract.geometry.log2_mcycles_per_period)
    local function tamper_point(machine)
        local context = machine.state
        if context.input_index ~= input_index or context.tampered then
            return nil
        end
        if math.ult(cartesi.MCYCLE_MAX - context.input_base, offset) then
            return nil
        end
        return context.input_base + offset
    end
    local function apply(machine)
        local point = tamper_point(machine)
        if
            point
            and machine:read_reg("mcycle") == point
            and machine:read_reg("iflags_Y") == 0
            and machine:read_reg("iflags_H") == 0
        then
            local ram_length = machine:get_initial_config().ram.length
            machine:write_memory(cartesi.AR_RAM_START + ram_length - 8, "CORRUPT!")
            machine.state.tampered = true
        end
    end
    local function collection_target(machine, target)
        apply(machine)
        local point = tamper_point(machine)
        if point and math.ult(machine:read_reg("mcycle"), point) and math.ult(point, target) then
            return point
        end
        return target
    end
    return use_machine(player, {
        run = function(machine, target)
            local point = tamper_point(machine)
            if point and math.ult(machine:read_reg("mcycle"), point) and math.ult(point, target) then
                local reason = machine.machine:run(point)
                if reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                    return reason
                end
            end
            if point and math.ult(point, target) then
                apply(machine)
            end
            return machine.machine:run(target)
        end,
        collect_mcycle_root_hashes = function(machine, target, ...)
            return machine.machine:collect_mcycle_root_hashes(collection_target(machine, target), ...)
        end,
        collect_uarch_cycle_root_hashes = function(machine, target, ...)
            return machine.machine:collect_uarch_cycle_root_hashes(collection_target(machine, target), ...)
        end,
        run_uarch = function(machine, ...)
            apply(machine)
            return machine.machine:run_uarch(...)
        end,
        log_step_uarch = function(machine, ...)
            apply(machine)
            return machine.machine:log_step_uarch(...)
        end,
    })
end

-- Replace a sample as it enters the computation hash. The append contract also
-- covers repeated padding and complete instruction forests. Only the affected
-- group is split; its neighbors keep their compressed representation.
local function lie_about_leaf(claim, leaf, fake_hash, unbundle)
    local append = claim.append
    local function append_lie(self, value, count, height)
        if count == 0 or leaf < self.next_leaf or leaf >= self.next_leaf + (count << height) then
            return append(self, value, count, height)
        end
        local prefix = (leaf - self.next_leaf) >> height
        append(self, value, prefix, height)
        if height == 0 then
            append(self, fake_hash, 1, 0)
        elseif height == self.log2_bundle then
            -- Unbundling uses the selected factory again, now with individual
            -- leaves. Its replacement is authenticated by the ordinary tree.
            local forest = self:unbundle(self.next_leaf, height)
            append(self, hash_tree.frontier_forest_get_root_hash(forest), 1, height)
        else
            for i = 0, (1 << (height - self.log2_bundle)) - 1 do
                self:append(hash_tree.frontier_forest_get_node(value, i, 0), 1, self.log2_bundle)
            end
        end
        append(self, value, count - prefix - 1, height)
    end
    return wrap_computation_hash(claim, { append = append_lie, unbundle = unbundle })
end

local function new_fabulist(dapp_contract, input_index, leaf_offset, options)
    local player = prt.new_honest(dapp_contract, role_options("fabulist", options))
    local epoch_period_index = input_index * dapp_contract.geometry.periods_per_input + leaf_offset
    local fake_hash = keccak("fabulist")
    local new_mcycle = player.new_mcycle_computation_hash
    player.new_mcycle_computation_hash = function(self, machine, window)
        local claim = new_mcycle(self, machine, window)
        return lie_about_leaf(claim, epoch_period_index, fake_hash, function(_, first_leaf)
            return self:refine_mcycle_claim(first_leaf >> prt.LOG2_MCYCLE_BUNDLE)
        end)
    end
    local new_uarch = player.new_uarch_computation_hash
    player.new_uarch_computation_hash = function(self, machine, window)
        local claim = new_uarch(self, machine, window)
        if window.epoch_period_index == epoch_period_index then
            return lie_about_leaf(claim, (1 << self.geometry.uarch_height) - 1, fake_hash, function(_, first_leaf)
                return self:refine_uarch_claim(input_index + 1, leaf_offset, first_leaf >> prt.LOG2_UARCH_BUNDLE)
            end)
        end
        return claim
    end
    return player
end

-- The quitter never executes the guest. Its machine stays at the initial yield,
-- its collector substitutes a made-up state at every position, and it disconnects
-- after posting that claim. The disconnect is its only protocol-level deviation.
local function new_quitter(dapp_contract, options)
    local player = prt.new_honest(dapp_contract, role_options("quitter", options))
    use_machine(player, { send_cmio_response = function() end })
    local make = player.new_mcycle_computation_hash
    player.new_mcycle_computation_hash = function(self, machine, window)
        local claim = make(self, machine, window)
        return wrap_computation_hash(claim, {
            cache_machine = false,
            append = function(collector, _, count, height)
                local fake_hash = keccak("quitter")
                for _ = 1, height do
                    fake_hash = keccak(fake_hash, fake_hash)
                end
                return claim.append(collector, fake_hash, count, height)
            end,
        })
    end
    local commit = player.commit_mcycle_claim
    player.commit_mcycle_claim = function(self)
        self.done = true
        return commit(self)
    end
    return player
end

if ... == "prt-dishonest" then
    return {
        new_forger = new_forger,
        new_tamperer = new_tamperer,
        new_fabulist = new_fabulist,
        new_quitter = new_quitter,
    }
end

-- The dishonest demonstration roles have their own entry point.
-- prt-dishonest.lua <role> <address> <initial-state-hash> [role arguments] <inputs...>
local role = assert(arg[1], "missing role")
local server_address = assert(arg[2], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[3], "missing initial state hash"))
assert(#initial_state_hash == 32, "invalid initial state hash")
local next_argument = 4
local function take_argument(message)
    local value = assert(arg[next_argument], message)
    next_argument = next_argument + 1
    return value
end
local make_player
if role == "quitter" then
    make_player = new_quitter
elseif role == "forger" then
    local index = assert(tonumber(take_argument("missing forged input index")), "invalid forged input index")
    local data = util.read_file(take_argument("missing forged input file"))
    make_player = function(contract)
        return new_forger(contract, index, data)
    end
elseif role == "tamperer" or role == "fabulist" then
    local input_index = assert(tonumber(take_argument("missing input index")), "invalid input index")
    local offset = assert(tonumber(take_argument("missing offset")), "invalid offset")
    local make = role == "tamperer" and new_tamperer or new_fabulist
    make_player = function(contract)
        return make(contract, input_index, offset)
    end
else
    error("unknown role: " .. role)
end
local inputs = {}
for i = next_argument, #arg do
    inputs[#inputs + 1] = util.read_file(arg[i])
end
prtu.run_client(
    make_player({
        initial_state_hash = initial_state_hash,
        inputs = inputs,
        geometry = prt.new_geometry(10),
    }),
    server_address
)
