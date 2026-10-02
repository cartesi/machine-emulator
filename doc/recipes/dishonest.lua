-- A composite presents the machine interface backed by two machines and switches from the
-- first to the second at a given point (mcycle offset from a cheat input's feed, uarch_cycle),
-- reporting the first up to and including the point and the second after. run pins the step's
-- mcycle, since the uarch advances mcycle on its own and a live read mid-step would place the
-- switch wrong. Only the active machine advances between input boundaries, the second having
-- been positioned at the switch point ahead of time. Forking forks both. Only the switching
-- methods are defined below, the rest fall through to the active machine.
-- The rolling test fixture selects the cheat input by its explicit epoch index.
-- Forking and rollback preserve the strategy together with the machine state.
-- Every mutable field lives in the instance's single data table, so forking copies it whole
-- and trading places with another composite swaps it whole, with no field list to maintain.
-- First access caches the result on the instance, so later accesses skip __index. A defined
-- method copies over as is. An undefined key naming a function on the active machine becomes a
-- forwarding method, built once and shared on composite_meta. Any other value passes through
-- uncached, since it may change.
local cartesi = require("cartesi")

local composite_meta = {}
composite_meta.__index = function(self, key)
    local method = composite_meta[key]
    if not method then
        local active_val = self.data.active[key]
        if type(active_val) == "function" then
            method = function(this, ...)
                return this.data.active[key](this.data.active, ...)
            end
            composite_meta[key] = method
        else
            return active_val
        end
    end
    self[key] = method
    return method
end

-- Runs the idle machine to the target, resuming through automatic yields and dropping their
-- outputs, which only the active machine reports.
local function run_idle(machine, target)
    local break_reason
    repeat
        break_reason = machine:run(target)
    until break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY
end

-- True for positions strictly after the cheat point (lexicographic on the pair). Positions
-- before the cheat input's feed are never past, and the offsets of positions after it only grow.
local function past_cheat(data, mcycle, uarch_cycle)
    if not data.cheated then
        return false
    end
    if mcycle - data.feed_mcycle ~= data.cheat_offset then
        return mcycle - data.feed_mcycle > data.cheat_offset
    end
    return uarch_cycle > data.cheat_uarch_cycle
end

-- The composite for vg.lua, cheating at an (mcycle offset, uarch_cycle)
-- point of the input at cheat_input_index. Both machines start at the same input
-- boundary.
local function new_rolling_composite_machine(
    real_machine,
    cheat_input_index,
    cheat_offset,
    cheat_uarch_cycle,
    cheat_machine,
    cheat_data
)
    return setmetatable({
        data = {
            real_machine = real_machine,
            cheat_machine = cheat_machine,
            active = real_machine,
            mcycle = 0,
            cheated = false,
            feed_mcycle = 0,
            cheat_offset = cheat_offset,
            cheat_uarch_cycle = cheat_uarch_cycle,
            cheat_input_index = cheat_input_index,
            cheat_data = cheat_data,
        },
    }, composite_meta)
end

function composite_meta.fork_server(self)
    local data = {}
    for key, value in pairs(self.data) do
        data[key] = value
    end
    data.real_machine = assert(self.data.real_machine:fork_server())
    data.cheat_machine = assert(self.data.cheat_machine:fork_server())
    data.active = self.data.active == self.data.real_machine and data.real_machine or data.cheat_machine
    return setmetatable({ data = data }, composite_meta)
end

-- Both machines take every input, the idle one first catching up to its own input boundary.
-- Each records its own root hash, since their states diverge past the cheat input's feed. The
-- cheat machine takes the doctored input in place of the cheat input and is then run to the
-- switch point, where later rounds expect to find it.
function composite_meta.set_input_index(self, index)
    self.data.input_index = index
end

function composite_meta.send_cmio_response(self, reason, input, _)
    local data = self.data
    for _, machine in ipairs({ data.real_machine, data.cheat_machine }) do
        run_idle(machine, math.maxinteger)
        local fed = data.input_index == data.cheat_input_index and machine == data.cheat_machine and data.cheat_data
            or input
        local revert_root_hash = machine:get_root_hash()
        machine:send_cmio_response(reason, fed, revert_root_hash)
    end
    if data.input_index == data.cheat_input_index then
        data.cheated, data.feed_mcycle = true, data.real_machine:read_reg("mcycle")
        run_idle(data.cheat_machine, data.feed_mcycle + data.cheat_offset)
    end
    -- The reported boundary is the active machine's, pinned at its own mcycle.
    data.active = past_cheat(data, data.real_machine:read_reg("mcycle"), 0) and data.cheat_machine or data.real_machine
    data.mcycle = data.active:read_reg("mcycle")
end

function composite_meta.run(self, m)
    local data = self.data
    data.mcycle = m
    data.active = past_cheat(data, m, 0) and data.cheat_machine or data.real_machine
    return data.active:run(m)
end

-- The uarch stays within the pinned mcycle, so the switch is judged against that, not the
-- live mcycle the uarch advances.
function composite_meta.run_uarch(self, u)
    local data = self.data
    data.active = past_cheat(data, data.mcycle, u) and data.cheat_machine or data.real_machine
    data.active:run_uarch(u)
end

function composite_meta.shutdown_server(self)
    self.data.real_machine:shutdown_server()
    self.data.cheat_machine:shutdown_server()
end

-- Trading places trades the data tables. The other machine is always a composite too (a fork
-- of one), so both sides carry one.
function composite_meta.swap(self, other)
    self.data, other.data = other.data, self.data
end

-- The log methods always report the second machine, rolled to the current position. self is
-- always an ephemeral fork here, so rolling it forward in place is fine.
function composite_meta.log_step_uarch(self, log_type)
    local data = self.data
    data.cheat_machine:run_uarch(data.active:read_reg("uarch_cycle"))
    return data.cheat_machine:log_step_uarch(log_type)
end
function composite_meta.log_reset_uarch(self, log_type)
    local data = self.data
    data.cheat_machine:run_uarch(data.active:read_reg("uarch_cycle"))
    return data.cheat_machine:log_reset_uarch(log_type)
end

return { new_rolling_composite_machine = new_rolling_composite_machine }
