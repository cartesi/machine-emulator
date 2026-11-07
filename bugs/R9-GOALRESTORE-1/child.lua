-- Loads the stored machine sharing all its files and runs it in place; never returns (the guest spins).
-- mode "collect": collect_mcycle_root_hashes with a sampling period of 2^40 mcycles (as builder:run in the PRT player).
-- mode "run": plain run (control).
local cartesi = require("cartesi")
local dir, mode = arg[1], arg[2]
local m = cartesi.new()
m:load(dir, nil, cartesi.SHARING_ALL)
if mode == "collect" then
    m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, 40, 0, 0)
else
    m:run(cartesi.MCYCLE_MAX)
end
io.stderr:write("child returned unexpectedly\n")
os.exit(3)
