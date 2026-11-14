-- Deploys a Dave build with doc/recipes/prt-deploy.lua and prints the deployment as JSON (chain/deploy.sh).
local json = require("dkjson")
local rpc_client = require("prt-rpc")
local prt_deploy = require("prt-deploy")
local chain = rpc_client.new(os.getenv("PRT_RPC_URL"))
local d = prt_deploy.deploy(chain, assert(arg[1], "missing template hash"))
io.write(json.encode({
    variant = os.getenv("PRT_VARIANT"),
    dave_directory = prt_deploy.dave_directory,
    rpc_url = os.getenv("PRT_RPC_URL"),
    stf = d.stf,
    factory = d.factory,
    input_box = d.input_box,
    app = d.app,
    consensus = d.consensus,
    staging_period = d.staging_period,
    uarch_pristine_hash = d.uarch_pristine_hash,
    geometry = d.geometry,
}, { indent = true }), "\n")
