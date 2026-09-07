-- Dishonest players use the same driver, claims, and protocol handlers as the honest
-- player. Only their machine or computation-hash object tells a different history.
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local prt = require("prt")
local keccak = cartesi.keccak256

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
    options = role_options("forger", options)
    options.new_machine = function(initial_state_hash)
        local overrides = {}
        for _, name in ipairs({ "send_cmio_response", "log_send_cmio_response" }) do
            overrides[name] = function(machine, reason, data, revert_state_hash)
                if machine.context.input_index == input_index then
                    data = forged_data
                end
                return machine.remote[name](machine.remote, reason, data, revert_state_hash)
            end
        end
        return prt.new_machine(initial_state_hash, overrides)
    end
    return prt.new_player(dapp_contract, options)
end

-- A checkpoint exactly at the corruption point still holds the agreed state.
-- Corruption happens only when executing or collecting the transition out of it.
-- The machine adapter copies this context on fork and restores it on rollback.
local function new_tamperer(dapp_contract, input_index, bundle_offset, options)
    options = role_options("tamperer", options)
    local offset = bundle_offset << (prt.LOG2_MCYCLE_BUNDLE + dapp_contract.geometry.log2_mcycles_per_period)
    options.new_machine = function(initial_state_hash)
        local function tamper_point(machine)
            local context = machine.context
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
                machine.context.tampered = true
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
        return prt.new_machine(initial_state_hash, {
            run = function(machine, target)
                local point = tamper_point(machine)
                if point and math.ult(machine:read_reg("mcycle"), point) and math.ult(point, target) then
                    local reason = machine.remote:run(point)
                    if reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then
                        return reason
                    end
                end
                if point and math.ult(point, target) then
                    apply(machine)
                end
                return machine.remote:run(target)
            end,
            collect_mcycle_root_hashes = function(machine, target, ...)
                return machine.remote:collect_mcycle_root_hashes(collection_target(machine, target), ...)
            end,
            collect_uarch_cycle_root_hashes = function(machine, target, ...)
                return machine.remote:collect_uarch_cycle_root_hashes(collection_target(machine, target), ...)
            end,
            run_uarch = function(machine, ...)
                apply(machine)
                return machine.remote:run_uarch(...)
            end,
            log_step_uarch = function(machine, ...)
                apply(machine)
                return machine.remote:log_step_uarch(...)
            end,
        })
    end
    return prt.new_player(dapp_contract, options)
end

-- Replace a sample as it enters the computation hash. The append contract also
-- covers repeated padding and complete instruction forests. Only the affected
-- group is split; its neighbors keep their compressed representation.
local function lie_about_leaf(claim, leaf, fake_hash)
    local append = claim.append
    claim.append = function(self, value, count, height)
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
    return claim
end

local function new_fabulist(dapp_contract, input_index, leaf_offset, options)
    options = role_options("fabulist", options)
    local epoch_period_index = input_index * dapp_contract.geometry.periods_per_input + leaf_offset
    local fake_hash = keccak("fabulist")
    options.new_mcycle_computation_hash = function(player, machine, window)
        return lie_about_leaf(prt.new_mcycle_computation_hash(player, machine, window), epoch_period_index, fake_hash)
    end
    options.new_uarch_computation_hash = function(player, machine, window)
        local claim = prt.new_uarch_computation_hash(player, machine, window)
        if window.epoch_period_index == epoch_period_index then
            lie_about_leaf(claim, (1 << player.geometry.uarch_height) - 1, fake_hash)
        end
        return claim
    end
    return prt.new_player(dapp_contract, options)
end

-- The quitter never executes the guest. Its machine stays at the initial yield,
-- its collector substitutes a made-up state at every position, and it disconnects
-- after posting that claim. The disconnect is its only protocol-level deviation.
local function new_quitter(dapp_contract, options)
    options = role_options("quitter", options)
    options.new_machine = function(initial_state_hash)
        return prt.new_machine(initial_state_hash, { send_cmio_response = function() end })
    end
    options.new_mcycle_computation_hash = function(player, machine, window)
        local claim = prt.new_mcycle_computation_hash(player, machine, window)
        local append = claim.append
        claim.cache_machine = false
        claim.append = function(self, _, count, height)
            local fake_hash = keccak("quitter")
            for _ = 1, height do
                fake_hash = keccak(fake_hash, fake_hash)
            end
            return append(self, fake_hash, count, height)
        end
        return claim
    end
    local player = prt.new_player(dapp_contract, options)
    local commit = player.commit_mcycle_claim
    player.commit_mcycle_claim = function(self)
        self.done = true
        return commit(self)
    end
    return player
end

return {
    new_forger = new_forger,
    new_tamperer = new_tamperer,
    new_fabulist = new_fabulist,
    new_quitter = new_quitter,
}
