-- A claimant that posts a claim (the quitter's fabricated one) and then stops processing:
-- it keeps its connection open but never answers another request. Advance-time
-- notifications are answered by the transport's client loop until the first request that
-- needs a handler arrives after the claim; that request, and everything queued behind it,
-- is never answered. This is the "connects and never answers" player of doc/README.md
-- ("Clocks and logical time"), holding a claim in one match.
--   lua5.4 silent-quitter.lua <address> <initial-state-hash> [<label>]
local cartesi = require("cartesi")
local socket = require("socket")
local prt = require("prt")
local prtu = require("prtu")
local dishonest = require("prt-dishonest")

local address = assert(arg[1], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[2], "missing initial state hash"))
local label = arg[3] or "silent"
local dapp_contract = prt.new_dapp_contract(initial_state_hash, {})
local player <close> = dishonest.new_quitter(dapp_contract, label)

local function go_silent(name)
    io.stderr:write(label .. ": stops answering at " .. name .. ", connection kept open\n")
    io.stderr:flush()
    while true do
        socket.sleep(3600)
    end
end

local commit = player.event_handler.commit_mcycle_claim
player.event_handler.commit_mcycle_claim = function(self, ...)
    local claim = commit(self, ...)
    self.event_handler = setmetatable({}, {
        __index = function(_, name)
            return function()
                go_silent(name)
            end
        end,
    })
    return claim
end
prtu.run_client(player, address)
