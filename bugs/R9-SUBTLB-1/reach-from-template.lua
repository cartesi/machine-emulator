-- R9-SUBTLB-1, informational (not run by bugs/run.sh): the same deviation from a template at a manual yield.
-- The machine is created with iprv=S, MPRV=1, MPP=U, SPP=S, SUM=0 (Sv39). The guest loads from the U page (fills the
-- read TLB at effective privilege U), then yields manually with the accepted reason through HTIF (mapped U RW).
-- The machine is stored and reloaded, an advance-state input is delivered (send_cmio_response), and the guest runs
-- sret (stays in S, clears MPRV) and loads the U page again. Expected by the spec: stage=2 trap=1 scause=13.
-- Usage: . bugs/env.sh && lua5.4 bugs/R9-SUBTLB-1/reach-from-template.lua
local cartesi = require("cartesi")
local RAM, VA, MARKER = 0x80000000, 0xC0002000, 0x1122334455667788
local function itype(op, f3, rd, rs1, imm) return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op end
local function ld(rd, rs1) return itype(0x03, 3, rd, rs1, 0) end
local function sd(rs2, rs1) return (rs2 << 20) | (rs1 << 15) | (3 << 12) | 0x23 end
local function li(rd, imm) return itype(0x13, 0, rd, 0, imm) end
local function csrr(rd, csr) return (csr << 20) | (2 << 12) | (rd << 7) | 0x73 end
local NOP, SRET, JSELF = 0x13, 0x10200073, 0x6f
local function words(t) local s = {} for _, w in ipairs(t) do s[#s + 1] = string.pack("<I4", w) end return table.concat(s) end
local code = words({ ld(5, 11), sd(12, 13), SRET, NOP, li(8, 2), ld(7, 11), li(8, 3), JSELF })
local handler = words({ csrr(18, 0x142), csrr(19, 0x141), csrr(20, 0x143), li(9, 1), JSELF })
local img = code .. string.rep("\0", 0x100 - #code) .. handler
img = img .. string.rep("\0", 0x1000 - #img)
local pt = {}
for i = 0, 511 do
    local pte = 0
    if i == 1 then pte = (0x40000 << 10) | 0xd7 end -- 0x40000000 gigapage, U RW (HTIF)
    if i == 2 then pte = (0x80000 << 10) | 0xcf end
    if i == 3 then pte = (0x80000 << 10) | 0xd7 end
    pt[#pt + 1] = string.pack("<I8", pte)
end
img = img .. table.concat(pt) .. string.pack("<I8", MARKER)
local dir = arg[1] or (function() local p = io.popen("mktemp -d"); local d = p:read("l"); p:close(); return d end)()
local bin = dir .. "/img.bin"
local f = assert(io.open(bin, "wb")); f:write(img); f:close()
local def = cartesi.machine:get_default_config()
local cfg = {
    ram = { length = 1 << 20, backing_store = { data_filename = bin } },
    processor = { registers = {
        iprv = 1, mstatus = def.processor.registers.mstatus | (1 << 8) | (1 << 17),
        satp = (8 << 60) | ((RAM + 0x1000) >> 12), stvec = RAM + 0x100, sepc = RAM + 0x0C,
        medeleg = (1 << 12) | (1 << 13) | (1 << 15), x11 = VA,
        x12 = (2 << 56) | (1 << 48) | (1 << 32), x13 = 0x40008000,
    } },
}
local m = cartesi.machine(cfg)
local br = m:run(1000)
print("run1 break", br, "iflags_Y", m:read_reg("iflags_Y"), "mcycle", m:read_reg("mcycle"), "iprv", m:read_reg("iprv"),
    "MPRV", (m:read_reg("mstatus") >> 17) & 1, "uarch_cycle", m:read_reg("uarch_cycle"))
os.execute("rm -rf " .. dir .. "/snap")
m:store(dir .. "/snap")
m:destroy()
local t = cartesi.machine(dir .. "/snap")
t:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "hello", t:get_root_hash())
print("after delivery iflags_Y", t:read_reg("iflags_Y"))
t:run(t:read_reg("mcycle") + 100)
print(string.format("stage=%d trap=%d scause=%d t2=0x%x MPRV=%d iprv=%d", t:read_reg("x8"), t:read_reg("x9"),
    t:read_reg("x18"), t:read_reg("x7"), (t:read_reg("mstatus") >> 17) & 1, t:read_reg("iprv")))
os.execute("rm -rf " .. dir .. "/snap " .. dir .. "/img.bin")
if not arg[1] then os.execute("rmdir " .. dir) end
