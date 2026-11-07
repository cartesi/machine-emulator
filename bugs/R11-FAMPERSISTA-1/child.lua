-- Loads the stored machine sharing all its files (SHARING_ALL), brings the hash tree up to date (so the shared
-- dirty-page tree is clean), then runs it in place with plain run(). Never returns (the guest spins).
local cartesi = require("cartesi")
local dir = arg[1]
local m = cartesi.new()
m:load(dir, nil, cartesi.SHARING_ALL)
m:get_root_hash()
m:run(cartesi.MCYCLE_MAX)
io.stderr:write("child returned unexpectedly\n")
os.exit(3)
