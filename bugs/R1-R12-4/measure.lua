-- Child process: runs ONE collection on a fresh bare-metal machine and prints
--   "<mode> entries=<n> hwm_delta_kib=<k>"
-- where hwm_delta_kib is the growth of the process's peak RSS (VmHWM) caused by that call.
-- Usage: lua5.4 measure.lua <mode> <guest.bin>
local cartesi = require("cartesi")
local mode, guest = arg[1], arg[2]

local function hwm_kib()
    local f = assert(io.open("/proc/self/status"))
    for l in f:lines() do
        local v = l:match("^VmHWM:%s+(%d+)")
        if v then f:close(); return tonumber(v) end
    end
    f:close()
    error("no VmHWM")
end

local m <close> = cartesi.machine({ ram = { length = 64 << 20, backing_store = { data_filename = guest } } })
-- Touch the whole machine once (root hash) so the baseline includes the hash tree.
m:get_root_hash()
collectgarbage(); collectgarbage()
local before = hwm_kib()

-- The revert uarch tail is consumed only when the mcycle rejects an input, which this guest never does;
-- the API requires one whenever the machine is not at a fixed point. Same tail for control and bundle.
local rr = m:read_revert_root_hash()
local tail = { rr, rr }
local n
if mode == "uarch-control" then
    -- The same mcycle without bundling: one hash per uarch cycle executed, then the halted and reset hashes.
    local r = m:collect_uarch_cycle_root_hashes(m:read_reg("mcycle") + 1, 0, tail)
    n = #r.hashes
elseif mode == "uarch-bundle" then
    -- The one bundle that covers the whole mcycle (log2 = ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE).
    local r = m:collect_uarch_cycle_bundle(0, cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE, tail)
    n = #r
elseif mode == "mcycle-control" then
    -- Run the guest to its halt fixed point, collecting one hash per mcycle, no bundling.
    local r = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, 0, 0, 0)
    n = #r.hashes
elseif mode == "mcycle-bundle" then
    -- One bundle of 2^20 mcycles that the halt fixed point pads.
    local r = m:collect_mcycle_bundle(0, 0, 20)
    n = #r
else
    error("unknown mode " .. tostring(mode))
end
local after = hwm_kib()
io.write(string.format("%s entries=%d hwm_delta_kib=%d mcycle=%d\n", mode, n, after - before, m:read_reg("mcycle")))
