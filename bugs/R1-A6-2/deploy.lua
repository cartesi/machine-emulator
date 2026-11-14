-- Deploys one Dave build with doc/recipes/prt-deploy.lua and prints "<application> <state transition>".
-- Run from a directory that holds the recipe wallets (wallets/player-0, wallets/password).
--   PRT_DAVE_DIR=<dave build> lua5.4 deploy.lua <rpc-url> <template-hash> [<pristine-hash-hex> <marchid>]
-- prt-deploy.lua checks the verifier it deploys against the emulator constants of the process that runs it.
-- The optional arguments set those constants to the verifier's own values, so that the deployment goes ahead
-- whatever prt-deploy.lua checks (now or after a fix): this script stands for the deployer of a deployment of
-- another version, whose own emulator matches its verifier. The player under test runs in a separate process
-- with this build's real constants.
local cartesi = require("cartesi")
local rpc_url, template_hash, pristine, marchid = arg[1], arg[2], arg[3], arg[4]
assert(rpc_url and template_hash, "usage: deploy.lua <rpc-url> <template-hash> [<pristine-hash-hex> <marchid>]")
if pristine then
    cartesi.UARCH_PRISTINE_STATE_HASH = cartesi.fromhex(pristine)
end
if marchid then
    cartesi.MARCHID = assert(math.tointeger(tonumber(marchid)))
end
local rpc_client = require("prt-rpc")
local prt_deploy = require("prt-deploy")
local d = prt_deploy.deploy(rpc_client.new(rpc_url), template_hash)
io.write(d.app, " ", d.stf, "\n")
