-- Differential: random uarch programs and registers (arbitrary uarch states), C++ log vs Solidity verifier.
local cartesi = require("cartesi")
local enc = require("enc")
local seed = tonumber(arg[1]) or 1
local nsteps = tonumber(arg[2]) or 300
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
math.randomseed(seed)
local R = function(n) return math.random(0, (1 << n) - 1) end
local UR = cartesi.UARCH_RAM_START_ADDRESS
-- uarch RV64I encodings
local function rtype(f7, f3, op) return (f7 << 25) | (R(5) << 20) | (R(5) << 15) | (f3 << 12) | (R(5) << 7) | op end
local function itype(f3, op) return (R(12) << 20) | (R(5) << 15) | (f3 << 12) | (R(5) << 7) | op end
local gens = {
    function() return rtype(math.random(0,1) == 0 and 0 or 0x20, R(3), 0x33) end,
    function() return rtype(math.random(0,1) == 0 and 0 or 0x20, R(3), 0x3b) end,
    function() return itype(R(3), 0x13) end,
    function() return itype(R(3), 0x1b) end,
    function() -- shifts with funct6/7 variations
        local f3 = ({1,5})[math.random(2)]
        local hi = ({0, 0x10, 0x20, 0x21, 0x01})[math.random(5)]
        return (hi << 26) | (R(6) << 20) | (R(5) << 15) | (f3 << 12) | (R(5) << 7) | ({0x13,0x1b})[math.random(2)]
    end,
    function() return (R(20) << 12) | (R(5) << 7) | ({0x37,0x17})[math.random(2)] end,
    function() -- loads with base in x1..x4 (prepared addresses)
        local f3 = R(3); local sz = 1 << (f3 & 3)
        local imm = R(6) * 8 + sz * math.random(0, 8 // sz - 1)
        if math.random(10) == 1 then imm = R(9) end
        return (imm << 20) | (math.random(1, 4) << 15) | (f3 << 12) | (R(5) << 7) | 0x03
    end,
    function() -- stores
        local f3 = R(2); local sz = 1 << f3
        local imm = R(6) * 8 + sz * math.random(0, 8 // sz - 1)
        if math.random(10) == 1 then imm = R(9) end
        return ((imm >> 5) << 25) | (R(5) << 20) | (math.random(1, 4) << 15) | (f3 << 12) | ((imm & 31) << 7) | 0x23
    end,
    function() -- branches small forward/back
        local imm = (math.random(-8, 8) * 4) & 0x1fff
        return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) | (R(5) << 20) | (R(5) << 15) | (R(3) << 12) | (((imm >> 1) & 0xf) << 8) | (((imm >> 11) & 1) << 7) | 0x63
    end,
    function() -- jal small
        local imm = (math.random(-8, 8) * 4) & 0x1fffff
        return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3ff) << 21) | (((imm >> 11) & 1) << 20) | (((imm >> 12) & 0xff) << 12) | (R(5) << 7) | 0x6f
    end,
    function() return itype(0, 0x67) end, -- jalr (likely jumps away)
    function() return 0x0000000f end,
}
local N = 256
local words = {}
for i = 1, N do
    local g = gens[math.random(#gens)]
    if math.random(20) == 1 then g = function() return R(32) end end
    local w = g() & 0xffffffff
    local op = w & 0x7f
    if op ~= 0x23 and op ~= 0x63 then
        local rd = (w >> 7) & 31
        if rd >= 1 and rd <= 4 then w = w | (0x10 << 7) end
    end
    words[i] = string.pack("<I4", w)
end
local m = cartesi.machine({ ram = { length = 1 << 16 } })
m:write_memory(UR, table.concat(words))
local bases = { UR + R(10) * 8, 0x80000000 + R(12) * 8, R(9) * 8, cartesi.UARCH_SHADOW_START_ADDRESS + R(5) * 8, UR + (N * 4) }
for i = 1, 31 do
    local v
    if i <= 4 then v = bases[math.random(#bases)]
    else
        local k = math.random(4)
        v = (k == 1) and R(6) or (k == 2) and (R(32) | (R(32) << 32)) or (k == 3) and (-R(12)) or (1 << 63) | R(5)
    end
    m:write_reg("uarch_x" .. i, v)
end
m:write_reg("uarch_pc", UR)
local id, ok_steps, thrown = 0, 0, 0
for s = 1, nsteps do
    local pc = m:read_reg("uarch_pc")
    if pc < UR or pc >= UR + N * 4 then m:write_reg("uarch_pc", UR + 4 * R(8)) end
    local before = m:get_root_hash()
    local ok, log = pcall(m.log_step_uarch, m)
    if not ok then
        thrown = thrown + 1
        m:write_reg("uarch_pc", UR + 4 * R(8))
    else
        local after = m:get_root_hash()
        id = id + 1; ok_steps = ok_steps + 1
        out:write(enc.req(id, "stepOnly", { { "b32", enc.hex(before) }, { "bytes", enc.proof(log) } }, after,
            string.format("seed=%d s=%d pc=%x insn=%08x", seed, s, pc, (string.unpack("<I4", m:read_memory(pc, 4))))))
        if m:read_reg("uarch_halt") ~= 0 then m:write_reg("uarch_halt", 0) end
    end
end
out:close()
io.stderr:write(string.format("seed %d ok %d thrown %d\n", seed, ok_steps, thrown))
