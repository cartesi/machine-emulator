-- R3-VARSPEC-3: the CLINT implements an msip register at 0x02000000 that the manual does not document.
--
-- doc/README.md, "#### CLINT": "The Core Local Interruptor (or CLINT) controls the timer interrupt. The active
-- addresses are 0x0200bff8 (mtime) and 0x02004000 (mtimecmp)."
-- THREAT_MODEL.md R7: "The emulator implements the RISC-V specification and the devices as the manual documents
-- them, departing only where the manual documents a deviation." (area: Traps and interrupts)
--
-- The test passes (exit 0) if either
--   (a) the manual's CLINT section documents the msip register (mentions "msip" or address 0x02000000), or
--   (b) on every path (native interpreter, uarch + reset), a 32-bit store of 1 to 0x02000000 from M-mode is not
--       an active device access: it raises a store/AMO access fault (mcause 7, mtval 0x02000000) and leaves
--       mip.MSIP clear.
-- Otherwise it exits 1 (the device has an undocumented active address that raises the software interrupt).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    -- (a) does the manual's CLINT section document msip?
    local manual = harness.read_file(harness.REPO .. "/doc/README.md")
    local clint = manual:match("\n#### CLINT\n(.-)\n#### ")
    if not clint then harness.setup_error("cannot find the '#### CLINT' section of doc/README.md") end
    local lc = clint:lower()
    local documented = lc:find("msip", 1, true) ~= nil or lc:find("0x02000000", 1, true) ~= nil
        or lc:find("software interrupt", 1, true) ~= nil
    print("manual CLINT section documents msip: " .. tostring(documented))
    if documented then return true end

    -- (b) behavior
    local function lui(rd, imm20) return (imm20 << 12) | (rd << 7) | 0x37 end
    local function addi(rd, rs1, imm) return ((imm & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | 0x13 end
    local function sw(rs2, rs1, imm)
        return (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | ((imm & 0x1f) << 7) | 0x23
    end
    local JSELF = 0x6f -- jal x0, 0
    local RAM = 0x80000000
    -- 0x80000000: lui t0,0x2000 ; addi t1,x0,1 ; sw t1,0(t0) ; j .     (trap handler at +0x100: j .)
    local code = string.pack("<I4I4I4I4", lui(5, 0x2000), addi(6, 0, 1), sw(6, 5, 0), JSELF)
    local MIP_MSIP = 1 << 3

    -- control: a store to an inactive CLINT offset (0x02000010) faults with mcause 7 (what (b) requires)
    do
        local ctl = string.pack("<I4I4I4I4", lui(5, 0x2000), addi(6, 0, 1), sw(6, 5, 16), JSELF)
        local m <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        m:write_memory(RAM, ctl)
        m:write_memory(RAM + 0x100, string.pack("<I4", JSELF))
        m:write_reg("mtvec", RAM + 0x100)
        m:run(4)
        if m:read_reg("mcause") ~= 7 or m:read_reg("mtval") ~= 0x02000010 or m:read_reg("mip") & MIP_MSIP ~= 0 then
            harness.setup_error("control: store to inactive CLINT offset 0x10 did not fault as expected")
        end
        print("control: store to 0x02000010 -> store access fault (mcause 7), MSIP clear")
    end

    local all_ok = true
    for _, path in ipairs({ "native", "uarch" }) do
        local m <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        m:write_memory(RAM, code)
        m:write_memory(RAM + 0x100, string.pack("<I4", JSELF))
        m:write_reg("mtvec", RAM + 0x100)
        if m:read_reg("mip") & MIP_MSIP ~= 0 then harness.setup_error("MSIP pending at start") end
        if path == "native" then
            m:run(4)
        else
            for _ = 1, 4 do
                m:run_uarch()
                m:reset_uarch()
            end
        end
        if m:read_reg("mcycle") ~= 4 then harness.setup_error(path .. ": did not reach mcycle 4") end
        local mip, mcause, mtval, pc = m:read_reg("mip"), m:read_reg("mcause"), m:read_reg("mtval"), m:read_reg("pc")
        local msip = (mip & MIP_MSIP) ~= 0
        local faulted = mcause == 7 and mtval == 0x02000000
        print(string.format("%-6s: after 'sw 1 -> 0x02000000': mip=0x%x (MSIP=%s) mcause=0x%x mtval=0x%x pc=0x%x",
            path, mip, tostring(msip), mcause, mtval, pc))
        if msip or not faulted then all_ok = false end
    end
    return harness.expect(all_ok,
        "R7 / manual '#### CLINT': the only active CLINT addresses are mtime (0x0200bff8) and mtimecmp "
            .. "(0x02004000); a store to 0x02000000 must fault and must not raise mip.MSIP")
end)
