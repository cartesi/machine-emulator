local cartesi = require("cartesi")
local enc = require("enc")
local seed = tonumber(arg[1]) or 1
local ncases = tonumber(arg[2]) or 50
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
math.randomseed(seed)
local R = function(n) return math.random(0, (1 << n) - 1) end
local function rnd32() local t = {} for i = 1, 32 do t[i] = string.char(R(8)) end return table.concat(t) end
local zero = {}
zero[5] = cartesi.keccak256(string.rep("\0", 32))
for k = 6, 21 do zero[k] = cartesi.keccak256(zero[k - 1], zero[k - 1]) end
local function merkle(data, k) -- root of data padded to 2^k bytes, 32-byte leaves
    local level = {}
    local nleaves = 1 << (k - 5)
    for i = 0, nleaves - 1 do
        local leaf = data:sub(i * 32 + 1, i * 32 + 32)
        if #leaf == 0 then level[#level + 1] = zero[5] else level[#level + 1] = cartesi.keccak256(leaf .. string.rep("\0", 32 - #leaf)) end
    end
    while #level > 1 do
        local nxt = {}
        for i = 1, #level, 2 do nxt[#nxt + 1] = cartesi.keccak256(level[i], level[i + 1]) end
        level = nxt
    end
    return level[1]
end
local function log2ceil(n) local k = 0 while (1 << k) < n do k = k + 1 end return k end
local id = 0
local lens = { 0, 1, 2, 31, 32, 33, 63, 64, 65, 100, 1000, 4096, 4097, 65535, (1 << 21) - 1, 1 << 21, (1 << 21) + 1 }
for c = 1, ncases do
    local mcycle = ({ 0, R(20), (1 << 63) - 1 + (1 << 63), -1 - R(40), -(1 << 47) - R(3), R(62) })[math.random(6)]
    local m = cartesi.machine({ ram = { length = 1 << 12 }, processor = { registers = { mcycle = mcycle } } })
    local y = math.random(4) ~= 1 and 1 or 0
    m:write_reg("iflags_Y", y)
    local dev = math.random(5) == 1 and R(8) or 2
    local cmd = math.random(5) == 1 and R(8) or 1
    local rs = ({ 1, 1, 2, 4, R(16) })[math.random(5)]
    m:write_reg("htif_tohost", (dev << 56) | (cmd << 48) | (rs << 32) | R(32))
    if math.random(3) == 1 then m:write_reg("htif_fromhost", R(32) | (R(32) << 32)) end
    local reason = ({ 0, 0, 0, 1, R(16) })[math.random(5)]
    local len = lens[math.random(#lens)]
    if math.random(4) == 1 then len = R(12) end
    local t = {}
    for i = 1, math.min(len, 256) do t[i] = string.char(R(8)) end
    local data = (table.concat(t) .. string.rep("\xab", len)):sub(1, len)
    local revert = math.random(2) == 1 and m:get_root_hash() or rnd32()
    local before = m:get_root_hash()
    local log = m:log_send_cmio_response(reason, data, revert)
    local after = m:get_root_hash()
    local v = cartesi.machine:verify_send_cmio_response(reason, data, before, log, revert)
    assert(v == after, "cpp verify mismatch")
    local k = math.max(5, log2ceil(len))
    local dh = (len > 0 and k <= 21) and merkle(data, k) or string.rep("\0", 32)
    id = id + 1
    out:write(enc.req(id, "send", { { "b32", enc.hex(before) }, { "uint", reason }, { "b32", enc.hex(dh) }, { "uint", len }, { "b32", enc.hex(revert) }, { "bytes", enc.proof(log) } }, after,
        string.format("seed=%d c=%d y=%d tohost=%x reason=%d len=%d mcycle=%x", seed, c, y, m:read_reg("htif_tohost"), reason, len, mcycle)))
    -- now uarch step + reset in the resulting state (possibly rejected yield)
    if math.random(2) == 1 then
        m:write_reg("iflags_Y", 1)
        m:write_reg("htif_tohost", (2 << 56) | (1 << 48) | (({ 1, 2, 2, 4 })[math.random(4)] << 32))
    end
    for s = 1, math.random(0, 3) do
        local b = m:get_root_hash(); local l = m:log_step_uarch(); local a = m:get_root_hash()
        id = id + 1
        out:write(enc.req(id, "stepOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, "pre-reset step"))
    end
    local b = m:get_root_hash(); local l = m:log_reset_uarch(); local a = m:get_root_hash()
    local va = cartesi.machine:verify_reset_uarch(b, l)
    if va ~= a then nrev = (nrev or 0) + 1; a = va end
    id = id + 1
    out:write(enc.req(id, "resetOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, string.format("seed=%d c=%d reset Y=%d tohost=%x", seed, c, m:read_reg("iflags_Y"), m:read_reg("htif_tohost"))))
end
out:close()
