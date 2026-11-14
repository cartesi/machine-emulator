-- child.lua <mode> <dir> [<to_dir>]: one machine operation in its own process, so that its peak resident memory
-- (VmHWM) is measured alone.
--   adopt <dir>         load without sharing, rebuilding the cached hash-tree data (O1: clear_hash_tree = true),
--                       compute the root hash. Prints "OK <root-hex> <VmHWM kB> <cpu s>" or "LOADFAIL <message>".
--   clone <dir> <to>    cartesi.machine:clone_stored(dir, to) (what the PRT player does for every snapshot).
--                       Prints "OK - <VmHWM kB> <cpu s>" or "LOADFAIL <message>".
--   store <dir> <to>    load <dir> (no sharing) and store it again into <to> (normalizing config.json).
--                       Prints "OK - <VmHWM kB> <cpu s>" or "LOADFAIL <message>".
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

local mode, dir, to = arg[1], arg[2], arg[3]
local t0 = os.clock()
local ok, res = pcall(function()
    if mode == "adopt" then
        local m = cartesi.machine(dir, { clear_hash_tree = true }, cartesi.SHARING_NONE)
        local root = m:get_root_hash()
        m:destroy()
        return hex(root)
    elseif mode == "clone" then
        cartesi.machine:clone_stored(dir, to)
        return "-"
    elseif mode == "store" then
        local m = cartesi.machine(dir, {}, cartesi.SHARING_NONE)
        m:store(to)
        m:destroy()
        return "-"
    end
    error("unknown mode " .. tostring(mode))
end)
if not ok then
    print("LOADFAIL " .. tostring(res):gsub("\n", " "))
    os.exit(0)
end
print(string.format("OK %s %d %.3f", res, vmhwm(), os.clock() - t0))
