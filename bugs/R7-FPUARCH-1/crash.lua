-- Crash stage, run under gdb (kill-after-leaf-store.py): reopens the stored machine exactly as
-- doc/recipes/prt.lua new_stored_machine does (load with SHARING_ALL, then get_root_hash, which
-- hashes and cleans every page). It then asks for the root hash again at the same state, as the
-- player does when it commits the boundary or answers for a claim. That update marks the write-TLB
-- page dirty again; gdb SIGKILLs the process right after that page's leaf byte is stored in the
-- shared dirty-page tree file, before its parent.
local cartesi = require("cartesi")
local m = cartesi.new()
m:load(arg[1], nil, cartesi.SHARING_ALL)
local root = m:get_root_hash()
assert(m:get_root_hash() == root)
print("CRASH-STAGE-NOT-KILLED")
