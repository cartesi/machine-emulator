-- Crash stage, run under gdb (kill-after-data-store.py): reopens a stored machine with SHARING_ALL, as a node that
-- keeps its machine on disk does, computes its root hash (bringing the shared hash tree up to date), and then makes
-- one host write to RAM through write_memory or write_word. gdb SIGKILLs the process the instant the shared RAM byte
-- changes, before the API call marks the page dirty in the shared .dpt file.
local cartesi = require("cartesi")
local C = dofile("common.lua")
local m = cartesi.new()
m:load(arg[1], nil, cartesi.SHARING_ALL)
m:get_root_hash()
C.apply(m, arg[2])
print("CRASH-STAGE-NOT-KILLED")
