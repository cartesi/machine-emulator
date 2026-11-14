-- First incarnation of the honest player: exactly the role `prt.lua honest <address> <hash> <label>
-- <epoch-directory>` (a stored player over an epoch directory), with two hooks:
--  * it writes the computation hash of the claim it posts to <state-dir>/claim.hex;
--  * with mode "restart", at the first reveal_bisection request for its claim it stops: it writes
--    <state-dir>/stopping (the request's arguments), waits for <state-dir>/go, and then leaves with an
--    announced departure ("done" reply), so the referee model does not crash on an EOF
--    (R3-VARREFMODEL-2). While it waits, its reply to the referee's request is outstanding, so the
--    referee's logical clock cannot advance: whatever happens meanwhile happens in the same block.
-- With mode "control" it is the unchanged honest player.
--   lua5.4 honest-first.lua <address> <initial-state-hash> <label> <epoch-directory> <state-dir> <mode>
local cartesi = require("cartesi")
local prt = require("prt")
local prtu = require("prtu")
local socket = require("socket")

local address = assert(arg[1], "missing referee address")
local initial_state_hash = cartesi.fromhex(assert(arg[2], "missing initial state hash"))
local label = assert(arg[3], "missing label")
local epoch_directory = assert(arg[4], "missing epoch directory")
local state_dir = assert(arg[5], "missing state directory")
local mode = assert(arg[6], "missing mode")
assert(mode == "restart" or mode == "control", "mode must be restart or control")

local function write_file(path, data)
    local f = assert(io.open(path, "w"))
    f:write(data)
    f:close()
end

local dapp_contract = prt.new_dapp_contract(initial_state_hash, {})
local player <close> = prt.new_stored_player(dapp_contract, label, nil, epoch_directory)

local base = player.event_handler
local handlers = setmetatable({}, { __index = base })
player.event_handler = handlers

function handlers.commit_mcycle_claim(self, ...)
    local claim = base.commit_mcycle_claim(self, ...)
    local computation_hash = cartesi.keccak256(claim.computation_hash_left, claim.computation_hash_right)
    write_file(state_dir .. "/claim.hex", cartesi.tohex(computation_hash))
    return claim
end

local stopped = false
function handlers.reveal_bisection(self, computation_hash, position, height, other_left_node)
    if mode == "restart" and not stopped then
        stopped = true
        write_file(
            state_dir .. "/stopping",
            string.format("reveal_bisection %s %d %d\n", cartesi.tohex(computation_hash), position, height)
        )
        io.stderr:write(label .. ": stopping at reveal_bisection (reply outstanding)\n")
        io.stderr:flush()
        local f
        repeat
            socket.sleep(0.1)
            f = io.open(state_dir .. "/go", "r")
        until f
        f:close()
        io.stderr:write(label .. ": leaving with an announced departure (done)\n")
        io.stderr:flush()
        return "done"
    end
    return base.reveal_bisection(self, computation_hash, position, height, other_left_node)
end

prtu.run_client(player, address)
