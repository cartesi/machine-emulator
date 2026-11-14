-- R1-R7-2: the interpreter executes Zcb compressed encodings, which RV64IMAFDC (the ISA the manual documents)
-- reserves, including Zcb encodings whose Zbb/Zba prerequisites the machine does not implement.
--
-- Requirement (THREAT_MODEL.md R7): "The emulator implements the RISC-V specification and the devices as the
-- manual documents them, departing only where the manual documents a deviation."
-- The manual (doc/README.md, "The main processor") documents the ISA as RV64IMAFDCZicsr_Zifencei. In that ISA,
-- the 16-bit encodings that Zcb later assigned (quadrant 0 funct3=100, quadrant 1 funct6=100111 with
-- funct2=10/11) are reserved and must raise an illegal-instruction exception (mcause 2).
-- Independently of documentation, the Zcb specification makes c.sext.b, c.zext.h, c.sext.h depend on Zbb and
-- c.zext.w depend on Zba: when the 32-bit sext.b/zext.h/sext.h/add.uw are illegal, so are their compressed forms.
--
-- Asserted:
--   (A) unless the manual documents Zcb, every probed Zcb encoding traps with mcause 2 and pc = mtvec;
--   (B) each Zbb/Zba-dependent Zcb encoding traps whenever its 32-bit prerequisite traps.
-- Exit 1 if either is violated, 0 if both hold, 2 on setup errors.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local TVEC = RAM + 0x10000
    local DATA = RAM + 0x20000

    local function bits(s)
        s = s:gsub("[%s_]", "")
        assert(#s == 16 or #s == 32, "bad encoding width")
        return tonumber(s, 2), #s // 8
    end

    -- probe one instruction at the start of RAM in M-mode, one mcycle; returns trapped, mcause, pc
    local function probe(insn, len)
        local m <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        local bytes = string.pack(len == 2 and "<I2" or "<I4", insn)
        m:write_memory(RAM, bytes .. string.rep("\x13\x00\x00\x00", 4)) -- followed by nops
        m:write_memory(TVEC, string.rep("\x13\x00\x00\x00", 4))
        for i = 1, 31 do
            m:write_reg("x" .. i, DATA)
        end
        m:write_reg("pc", RAM)
        m:write_reg("iprv", 3)
        m:write_reg("mtvec", TVEC)
        m:write_reg("mcause", 0xdead)
        local mc = m:read_reg("mcycle")
        m:run(mc + 1)
        local pc, cause = m:read_reg("pc"), m:read_reg("mcause")
        return pc == TVEC and cause == 2, cause, pc
    end

    -- rd'/rs1' = 001 (x9), rs2'/rs1' = 000 (x8); all registers point into RAM, so loads/stores succeed if executed
    local zcb = {
        { name = "c.lbu x9,0(x8)", enc = "100000 000 00 001 00" },
        { name = "c.lhu x9,0(x8)", enc = "100001 000 0 0 001 00" },
        { name = "c.lh x9,0(x8)", enc = "100001 000 1 0 001 00" },
        { name = "c.sb x9,0(x8)", enc = "100010 000 00 001 00" },
        { name = "c.sh x9,0(x8)", enc = "100011 000 0 0 001 00" },
        { name = "c.zext.b x9", enc = "100111 001 11 000 01" },
        { name = "c.sext.b x9", enc = "100111 001 11 001 01", needs = "sext.b x5,x6 (Zbb)" },
        { name = "c.zext.h x9", enc = "100111 001 11 010 01", needs = "zext.h x5,x6 (Zbb)" },
        { name = "c.sext.h x9", enc = "100111 001 11 011 01", needs = "sext.h x5,x6 (Zbb)" },
        { name = "c.zext.w x9", enc = "100111 001 11 100 01", needs = "add.uw x5,x6,x0 (Zba)" },
        { name = "c.not x9", enc = "100111 001 11 101 01" },
        { name = "c.mul x9,x8", enc = "100111 001 10 000 01" },
        -- the encoding of all-zero register fields, as the hunter reported it (= c.lbu x8,0(x8))
        { name = "0x8000", enc = "1000000000000000" },
    }
    local base32 = {
        ["sext.b x5,x6 (Zbb)"] = 0x60431293,
        ["zext.h x5,x6 (Zbb)"] = 0x080342bb,
        ["sext.h x5,x6 (Zbb)"] = 0x60531293,
        ["add.uw x5,x6,x0 (Zba)"] = 0x080302bb,
    }

    -- control: a reserved encoding outside Zcb and a plain RV64IMAFDC instruction behave as expected
    do
        local t = probe(0x0000, 2) -- all-zero 16-bit word: defined illegal
        if not t then harness.setup_error("control: 0x0000 did not raise illegal instruction") end
        local t2 = probe(0x00000013, 4) -- nop
        if t2 then harness.setup_error("control: nop trapped") end
    end

    local manual = harness.read_file(os.getenv("REPO") .. "/doc/README.md")
    local manual_documents_zcb = manual:find("Zcb", 1, true) ~= nil
    print(string.format("manual documents Zcb: %s (ISA line: %s)", tostring(manual_documents_zcb),
        manual:match("implements the `([^`]+)` ISA") or "?"))

    local base_traps = {}
    for name, insn in pairs(base32) do
        local t, cause = probe(insn, 4)
        base_traps[name] = t
        print(string.format("  32-bit %-24s 0x%08x  %s", name, insn, t and "illegal (mcause 2)" or
            string.format("executed (mcause=0x%x)", cause)))
    end

    local violations = {}
    for _, z in ipairs(zcb) do
        local insn, len = bits(z.enc)
        local t, cause, pc = probe(insn, len)
        print(string.format("  16-bit %-18s 0x%04x  %s", z.name, insn,
            t and "illegal (mcause 2)" or string.format("EXECUTED (pc=0x%x mcause=0x%x)", pc, cause)))
        if not t then
            if not manual_documents_zcb then
                violations[#violations + 1] = string.format("%s (0x%04x) executes, but RV64IMAFDCZicsr_Zifencei "
                    .. "reserves it and the manual documents no Zcb", z.name, insn)
            end
            if z.needs and base_traps[z.needs] then
                violations[#violations + 1] = string.format("%s (0x%04x) executes although its Zcb prerequisite "
                    .. "%s is illegal on this machine", z.name, insn, z.needs)
            end
        end
    end

    for _, v in ipairs(violations) do
        print("VIOLATION: " .. v)
    end
    return harness.expect(#violations == 0,
        "R7: reserved compressed encodings (Zcb, and Zcb forms of unimplemented Zbb/Zba) must raise "
            .. "illegal instruction unless the manual documents the extension")
end)
