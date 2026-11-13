-- Runs run-rolling-calculator-from-storage.lua (or the script given as the argument) with a cartesi module
-- that records the stored-machine operations, and checks that they rely only on the persistence guarantee.
-- A directory used by a machine with sharing holds a valid machine only after that machine is destroyed
-- and the directory synced, and a clone is durable only after its sync.

local cartesi = require("cartesi")

local script = arg[1] or "run-rolling-calculator-from-storage.lua"

-- The operations that touch stored directories, each recorded with its arguments
local RECORDED = {
    destroy = true,
    load = true,
    sync_stored = true,
    clone_stored = true,
    remove_stored = true,
    rename_stored = true,
}
local operations = {}
local function record(name, ...)
    local operation = { name = name }
    for i = 1, select("#", ...) do
        operation[i] = (select(i, ...))
    end
    operations[#operations + 1] = operation
end

-- Forwards every method to the target, recording the stored-machine operations
local function new_recorder(target)
    return function(_, name)
        return function(_, ...)
            if RECORDED[name] then
                record(name, ...)
            end
            return target[name](target, ...)
        end
    end
end

local recording_machine = setmetatable({}, {
    __call = function(_, directory, ...)
        record("new", directory, ...)
        return setmetatable({}, { __index = new_recorder(cartesi.machine(directory, ...)) })
    end,
    __index = new_recorder(cartesi.machine),
})
package.loaded.cartesi = setmetatable({ machine = recording_machine }, { __index = cartesi })
dofile(script)

-- Replays the operations, tracking whether the machine directory is in use and which clones are synced
local in_use = false
local synced = {}
local last = nil
for _, operation in ipairs(operations) do
    local name, first, second = operation.name, operation[1], operation[2]
    if name == "new" or name == "load" then
        in_use = first == "machine"
    elseif name == "destroy" then
        in_use = false
    elseif name == "sync_stored" then
        assert(not in_use or first ~= "machine", "machine was synced while a machine used it")
        synced[first] = true
    elseif name == "clone_stored" then
        assert(second ~= "machine.revert", "the backup was cloned in place instead of renamed into place")
        synced[second] = false
    elseif name == "rename_stored" then
        assert(synced[first], "the backup was renamed into place before its clone was synced")
    end
    if first == "machine" then
        last = name
    end
end
assert(not in_use and last == "sync_stored", "the script did not end by syncing its destroyed machine")
print("stored-machine operations follow the persistence guarantee")
