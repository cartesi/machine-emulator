-- child.lua <dir>: adopt a stored machine as O1 requires (load without sharing, rebuilding the cached hash-tree
-- data with clear_hash_tree), compute its root hash, and report the peak resident memory of this process.
-- Prints one line: "OK <root-hex> <VmHWM kB> <cpu s> <phtc entries>" or "LOADFAIL <message>".
local cartesi = require("cartesi")

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local function vmhwm()
    for l in io.lines("/proc/self/status") do
        local v = l:match("^VmHWM:%s+(%d+)")
        if v then return tonumber(v) end
    end
    error("no VmHWM")
end

local t0 = os.clock()
local ok, m = pcall(cartesi.machine, arg[1], { clear_hash_tree = true }, cartesi.SHARING_NONE)
if not ok then
    print("LOADFAIL " .. tostring(m):gsub("\n", " "))
    os.exit(0)
end
local root = m:get_root_hash()
local entries = m:get_initial_config().hash_tree.phtc_size
local cpu = os.clock() - t0
m:destroy()
print(string.format("OK %s %d %.3f %d", hex(root), vmhwm(), cpu, entries))
