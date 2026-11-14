-- Second incarnation of the honest player after its stop: exactly the role `prt.lua honest <address>
-- <hash> <label> <epoch-directory>` on the epoch directory the first incarnation left (a sealed epoch,
-- which new_stored_player reopens with its mcycle tree), with two additions:
--  * before connecting, it checks that the reopened player holds the tree of the claim it posted
--    (<state-dir>/claim.hex) and can open its root, and records that in <state-dir>/restarted-holds;
--  * it logs every request it receives to stderr ("received <event> <first argument>").
--   lua5.4 honest-restarted.lua <address> <initial-state-hash> <label> <epoch-directory> <state-dir>
local cartesi = require("cartesi")
local prt = require("prt")
local prtu = require("prtu")

local address = assert(arg[1], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[2], "missing initial state hash"))
local label = assert(arg[3], "missing label")
local epoch_directory = assert(arg[4], "missing epoch directory")
local state_dir = assert(arg[5], "missing state directory")

local function read_file(path)
    local f = assert(io.open(path, "r"))
    local data = f:read("a")
    f:close()
    return data
end

local dapp_contract = prt.new_dapp_contract(initial_state_hash, {})
local player <close> = prt.new_stored_player(dapp_contract, label, nil, epoch_directory)

local claim_hex = read_file(state_dir .. "/claim.hex"):gsub("%s+", "")
local claim_hash = cartesi.fromhex(claim_hex)
local tree = assert(player.trees[claim_hash], "the reopened player does not hold its claim's tree")
local left, right = tree:get_child_hashes(player, 0, tree.height)
assert(cartesi.keccak256(left, right) == claim_hash, "the reopened tree does not open to the claim")
do
    local f = assert(io.open(state_dir .. "/restarted-holds", "w"))
    f:write(claim_hex, "\n")
    f:close()
end
io.stderr:write(label .. ": reopened epoch directory, holds claim " .. claim_hex .. "\n")
io.stderr:flush()

local base = player.event_handler
player.event_handler = setmetatable({}, {
    __index = function(_, name)
        local handler = base[name]
        if type(handler) ~= "function" then
            return handler
        end
        return function(self, first, ...)
            local shown = type(first) == "string" and #first == 32 and cartesi.tohex(first) or tostring(first)
            io.stderr:write(string.format("%s: received %s %s\n", label, name, shown))
            io.stderr:flush()
            return handler(self, first, ...)
        end
    end,
})

prtu.run_client(player, address)
