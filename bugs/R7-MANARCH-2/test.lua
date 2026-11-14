-- R7-MANARCH-2: the manual says the processor shadow (0x0-0xfff) and the shadow TLB (0x1000-0x6fff) are address
-- ranges visible to the main processor, each described by a PMA entry; the emulator gives them no PMA entry and a
-- guest load from them raises a load access fault.
--
-- Required (THREAT_MODEL R7): "The emulator implements the RISC-V specification and the devices as the manual
-- documents them, departing only where the manual documents a deviation." Section 8: "A contradiction between the
-- manual and the behavior on a security-relevant point is a defect in one of the two."
--
-- The test passes (exit 0) if EITHER the emulator behaves as the manual says (a PMA entry covers each of the two
-- ranges and a main-processor load from them returns the shadowed value) OR the manual no longer presents these two
-- ranges as visible to the main processor. It fails (exit 1) when both disagree, as on audit/prt2.
local harness = require("harness")

-- RISC-V encoders (RV64I subset)
local function u_type(op, rd, imm20) return ((imm20 & 0xfffff) << 12) | (rd << 7) | op end
local function i_type(op, f3, rd, rs1, imm12) return ((imm12 & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op end
local T1, A0, A1 = 6, 10, 11
local function li(rd, v) -- v < 0x7ffff800, non-negative
    local hi = (v + 0x800) >> 12
    local lo = v - (hi << 12)
    return { u_type(0x37, rd, hi), i_type(0x13, 0, rd, rd, lo) }
end

local TRAP_OFF = 0x40
local SENTINEL = 0x5a5
local RAM_START = 0x80000000

-- Guest: mtvec = trap loop; a1 = sentinel; a0 = addr; ld a1, 0(a0); ok: j ok ... trap: j trap
local function guest(addr)
    local w = {
        u_type(0x17, T1, 0), -- auipc t1, 0
        i_type(0x13, 0, T1, T1, TRAP_OFF), -- addi t1, t1, TRAP_OFF
        i_type(0x73, 1, 0, T1, 0x305), -- csrrw x0, mtvec, t1
        i_type(0x13, 0, A1, 0, SENTINEL), -- addi a1, x0, SENTINEL
    }
    for _, x in ipairs(li(A0, addr)) do w[#w + 1] = x end
    w[#w + 1] = i_type(0x03, 3, A1, A0, 0) -- ld a1, 0(a0)
    local ok_pc = RAM_START + 4 * #w
    w[#w + 1] = 0x0000006f -- ok: j ok
    while 4 * #w < TRAP_OFF do w[#w + 1] = 0x00000013 end -- nop
    w[#w + 1] = 0x0000006f -- trap: j trap
    local t = {}
    for i, x in ipairs(w) do t[i] = string.pack("<I4", x) end
    return table.concat(t), ok_pc
end

harness.main(function()
    local cartesi = require("cartesi")

    -- 1. Emulator side
    local function pma_entries(m)
        local e = {}
        for i = 0, 255 do
            local istart, ilength = string.unpack("<I8I8", m:read_memory(0x10000 + 16 * i, 16))
            if ilength == 0 then break end
            e[#e + 1] = { start = istart & ~0xfff, length = ilength & ~0xfff, attrs = istart & 0xfff }
        end
        return e
    end
    local function covered(entries, a, len)
        for _, p in ipairs(entries) do
            -- any entry covering the range; readability is checked by the guest loads below, so the test does not
            -- depend on the attribute bit layout
            if p.start <= a and a + len <= p.start + p.length then return true end
        end
        return false
    end

    local probes = {
        { addr = 0x290, what = "processor shadow, marchid (offset 0x290)" },
        { addr = 0x2f8, what = "processor shadow, imcyclemax (offset 0x2f8)" },
        { addr = 0x1000, what = "shadow TLB, first word" },
        { addr = 0x6ff8, what = "shadow TLB, last word" },
    }
    local emulator_ok = true
    local m0 <close> = cartesi.machine({ ram = { length = 4 << 20 } }, {})
    local entries = pma_entries(m0)
    io.write(string.format("PMA array: %d entries\n", #entries))
    for _, p in ipairs(entries) do
        io.write(string.format("  start=0x%x length=0x%x attributes=0x%03x\n", p.start, p.length, p.attrs))
    end
    for _, r in ipairs({ { 0x0, 0x1000, "processor and board shadow 0x0-0xfff" }, { 0x1000, 0x6000, "shadow TLB 0x1000-0x6fff" } }) do
        local c = covered(entries, r[1], r[2])
        io.write(string.format("PMA entry covering %s: %s\n", r[3], c and "yes" or "NO"))
        emulator_ok = emulator_ok and c
    end
    -- control: the same guest loading from the PMA array (a range that has a PMA entry) must succeed
    table.insert(probes, 1, { addr = 0x10008, what = "control: PMA array, a range with a PMA entry", control = true })
    for _, p in ipairs(probes) do
        local img, ok_pc = guest(p.addr)
        local m <close> = cartesi.machine({ ram = { length = 4 << 20 } }, {})
        m:write_memory(RAM_START, img)
        local expected = string.unpack("<I8", m:read_memory(p.addr, 8))
        m:run(64)
        local pc, a1, mcause = m:read_reg("pc"), m:read_reg("x11"), m:read_reg("mcause")
        local loaded = pc == ok_pc and a1 == expected
        if pc == ok_pc then
            io.write(string.format("guest ld 0x%x (%s): value 0x%x, shadowed value 0x%x\n", p.addr, p.what, a1, expected))
        elseif pc == RAM_START + TRAP_OFF then
            io.write(string.format("guest ld 0x%x (%s): TRAP mcause=%d mtval=0x%x\n", p.addr, p.what, mcause,
                m:read_reg("mtval")))
        else
            harness.setup_error(string.format("guest ended at unexpected pc 0x%x", pc))
        end
        if p.control then
            if not loaded then harness.setup_error("control load from the PMA array did not succeed") end
        else
            emulator_ok = emulator_ok and loaded
        end
    end

    -- 2. Manual side (doc/README.md): does it still present 0x0-0xfff and 0x1000-0x6fff as visible to the main
    -- processor? It does while the board mapping table lists them and the "Address ranges" subsection does not name
    -- them among the ranges the main processor cannot access.
    local manual = harness.read_file(os.getenv("REPO") .. "/doc/README.md")
    local board = manual:match("### The board\n(.-)\n###")
    -- "Address ranges" and "PMAs" subsections (up to the next chapter), so a manual fix that names the ranges as
    -- invisible to the main processor in either subsection is recognized (reviewer repair: was Address ranges only)
    local ranges = manual:match("#### Address ranges\n(.-)\n### ")
    if not board or not ranges then harness.setup_error("cannot locate the board / Address ranges / PMAs sections") end
    local function lists(sec, s) return sec:find("`" .. s, 1, true) ~= nil end
    local manual_visible = {}
    for _, s in ipairs({ "0x00000000-0x00000fff", "0x00001000-0x00006fff" }) do
        local vis = lists(board, s) and not lists(ranges, s)
        manual_visible[#manual_visible + 1] = vis
        io.write(string.format("manual presents %s as visible to the main processor: %s\n", s, vis and "yes" or "no"))
    end
    local manual_says_visible = manual_visible[1] or manual_visible[2]
    local claim = manual:find("Each address range visible to the main processor is described by an\nentry", 1, true)
    io.write(string.format("manual: 'Each address range visible to the main processor is described by an entry ...' present: %s\n",
        claim and "yes" or "no"))

    if emulator_ok then
        io.write("emulator matches the manual: shadow ranges have PMA entries and are readable by the guest\n")
        return true
    end
    if not manual_says_visible then
        io.write("manual no longer presents the shadow ranges as visible to the main processor\n")
        return true
    end
    return harness.expect(false, "R7: the manual says the processor shadow and shadow TLB are address ranges visible " ..
        "to the main processor, each described by a PMA entry; the emulator gives them no PMA entry and a guest load faults")
end)
