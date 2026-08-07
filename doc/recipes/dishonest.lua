-- A composite presents the machine interface backed by two machines and switches from the
-- first to the second at a given point (mcycle offset from a cheat input's feed, uarch_cycle),
-- reporting the first up to and including the point and the second after. run pins the step's
-- mcycle, since the uarch advances mcycle on its own and a live read mid-step would place the
-- switch wrong. Only the active machine advances between input boundaries, the second having
-- been positioned at the switch point ahead of time. Forking forks both. Only the switching
-- methods are defined below, the rest fall through to the active machine.
-- In verification-game.lua the machine takes no inputs, so the point is an absolute (mcycle,
-- uarch_cycle) pair, with offsets measured from mcycle 0 and the cheat machine positioned at
-- construction. In rolling-verification-game.lua inputs flow through the composite, which
-- recognizes the cheat input by its bytes, feeds the cheat machine a doctored input in its
-- place, and positions it right after. Recognizing the input by its bytes survives rollbacks,
-- since a rolled-back feed disappears with the fork that made it.
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

-- The composite for verification-game.lua, cheating at an absolute (mcycle, uarch_cycle) point
-- of a machine that takes no inputs. The cheat machine is run to the switch mcycle once, here.
local function new_composite_machine(real_machine, cheat_mcycle, cheat_uarch_cycle, cheat_machine)
    cheat_machine:run(cheat_mcycle)
    return setmetatable({
        data = {
            real_machine = real_machine,
            cheat_machine = cheat_machine,
            active = real_machine,
            mcycle = 0,
            cheated = true,
            feed_mcycle = 0,
            cheat_offset = cheat_mcycle,
            cheat_uarch_cycle = cheat_uarch_cycle,
        },
    }, composite_meta)
end

-- The composite for rolling-verification-game.lua, cheating at an (mcycle offset, uarch_cycle)
-- point of the input whose bytes match cheat_input_data. Both machines start at the same input
-- boundary.
local function new_rolling_composite_machine(
    real_machine,
    cheat_input_data,
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
            cheat_input_data = cheat_input_data,
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
    data.active = data.real_machine
    return setmetatable({ data = data }, composite_meta)
end

-- Both machines take every input, the idle one first catching up to its own input boundary.
-- Each records its own root hash, since their states diverge past the cheat input's feed. The
-- cheat machine takes the doctored input in place of the cheat input and is then run to the
-- switch point, where later rounds expect to find it.
function composite_meta.send_cmio_response(self, reason, input, _)
    local data = self.data
    for _, machine in ipairs({ data.real_machine, data.cheat_machine }) do
        run_idle(machine, math.maxinteger)
        local fed = input == data.cheat_input_data and machine == data.cheat_machine and data.cheat_data or input
        local revert_root_hash = machine:get_root_hash()
        machine:send_cmio_response(reason, fed, revert_root_hash)
    end
    if input == data.cheat_input_data then
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
function composite_meta.log_step_uarch(self, ...)
    local data = self.data
    data.cheat_machine:run_uarch(data.active:read_reg("uarch_cycle"))
    return data.cheat_machine:log_step_uarch(...)
end
function composite_meta.log_reset_uarch(self, ...)
    local data = self.data
    data.cheat_machine:run_uarch(data.active:read_reg("uarch_cycle"))
    return data.cheat_machine:log_reset_uarch(...)
end

return { new_composite_machine = new_composite_machine, new_rolling_composite_machine = new_rolling_composite_machine }
