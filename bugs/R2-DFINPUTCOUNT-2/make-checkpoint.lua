-- Stores epoch 0's checkpoint for crisium.lua, as doc/recipes/prt-demo.lua does for its players:
-- prt.store_first_epoch_checkpoint(template, geometry of the deployed tournament factory, directory).
-- Usage: lua5.4 make-checkpoint.lua RPC_URL FACTORY DAVE_DIR TEMPLATE_DIR CHECKPOINT_DIR
local rpc_client = require("prt-rpc")
local eth = require("prt-ethereum")
local prt = require("prt")
local bridge = require("prt-bridge")

local rpc, factory, dave, template, directory = table.unpack(arg)
assert(rpc and factory and dave and template and directory, "usage: make-checkpoint.lua RPC FACTORY DAVE TEMPLATE DIR")
local chain = rpc_client.new(rpc)
local abi = eth.abi({ (eth.artifact(dave .. "/prt/contracts/out", "MultiLevelTournamentFactory")) })
local geometry = bridge.read_geometry(chain, abi, factory:lower())
prt.store_first_epoch_checkpoint(template, geometry, directory)
local _, _, manifest = prt.load_epoch_checkpoint(directory)
io.write(manifest.final_state_hash:lower(), "\n")
