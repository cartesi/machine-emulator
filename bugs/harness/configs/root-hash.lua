-- Prints the root hash (hex) of a stored machine: lua5.4 root-hash.lua <dir>
local c = require("cartesi")
local m <close> = c.machine(assert(arg[1], "usage: root-hash.lua <stored machine dir>"), {})
io.write(c.tohex(m:get_root_hash()), "\n")
