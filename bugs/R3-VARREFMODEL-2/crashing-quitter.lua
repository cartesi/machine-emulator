-- A claimant whose process dies after posting its claim: the quitter of prt-dishonest.lua
-- (same fabricated claim), but at the first request after its claim, where the quitter would
-- announce its departure with a "done" reply, this process exits instead. The kernel closes
-- its socket (FIN) without any reply, as when a player process crashes or is killed.
--   lua5.4 crashing-quitter.lua <address> <initial-state-hash> [<label>]
local cartesi = require("cartesi")
local prt = require("prt")
local prtu = require("prtu")
local dishonest = require("prt-dishonest")

local address = assert(arg[1], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[2], "missing initial state hash"))
local label = arg[3] or "crasher"
local dapp_contract = prt.new_dapp_contract(initial_state_hash, {})
local player = dishonest.new_quitter(dapp_contract, label)

local commit = player.event_handler.commit_mcycle_claim
player.event_handler.commit_mcycle_claim = function(self, ...)
    local claim = commit(self, ...)
    self.event_handler = setmetatable({}, {
        __index = function(_, name)
            return function()
                io.stderr:write(label .. ": process dies at " .. name .. " (no reply, socket closed by exit)\n")
                io.stderr:flush()
                os.exit(3, false)
            end
        end,
    })
    return claim
end
prtu.run_client(player, address)
