-- R9-SUBCSR-1: M-mode access to the PMP CSRs (pmpcfg0-15 at 0x3A0-0x3AF, pmpaddr0-63 at 0x3B0-0x3EF).
--
-- Claim under test: the emulator deviates from the privileged specification because M-mode CSR instructions on the
-- PMP CSRs raise an illegal-instruction exception instead of reading as WARL read-only zero.
--
-- What this test asserts is the behavior the privileged specification allows (see README.md for the quotes):
--   (a) on RV64 the odd pmpcfg CSRs (pmpcfg1, 3, ..., 15) are illegal, so they must trap;
--   (b) the even pmpcfg CSRs and pmpaddr0-63 either all exist (no trap) or all are non-existent ("zero PMP CSRs"),
--       and an access to a non-existent CSR raises a precise illegal-instruction exception
--       (pc = mtvec, mepc = the instruction, mcause = 2, mtval = the instruction bits, rd not written);
--       a mix of present and absent CSRs that violates "lowest-numbered first" / "all PMP CSRs" is a deviation;
--   (c) the interpreter and the uarch (uarch steps + uarch reset) agree on the root hash after every mcycle (R2).
-- If the claim were true, (b) would only be met by the "all exist" branch; the test reports which branch holds.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local RAM = 0x80000000
    local MTVEC = RAM + 0x100
    local SENTINEL = 0x5a5a5a5a

    local function csrrw(rd, csr, rs1) return (csr << 20) | (rs1 << 15) | (1 << 12) | (rd << 7) | 0x73 end
    local function csrrs(rd, csr, rs1) return (csr << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x73 end
    local JSELF = 0x0000006f -- j .
    local LI_A1_M1 = 0xfff00593 -- addi a1, x0, -1

    local bin = os.tmpname()
    local function cleanup() os.remove(bin) end

    -- Program: li a1,-1; csrrw a0,csr,a1; csrr a2,csr; j .   and at mtvec: j .
    local function make_machine(csr)
        local words = { LI_A1_M1, csrrw(10, csr, 11), csrrs(12, csr, 0), JSELF }
        local img = {}
        for _, w in ipairs(words) do img[#img + 1] = string.pack("<I4", w) end
        local s = table.concat(img)
        s = s .. string.rep("\0", 0x100 - #s) .. string.pack("<I4", JSELF)
        local f = assert(io.open(bin, "wb"))
        f:write(s)
        f:close()
        local m = harness.machine({
            ram = { length = 0x100000, backing_store = { data_filename = bin } },
            processor = { registers = { mtvec = MTVEC, x10 = SENTINEL, x12 = SENTINEL } },
        })
        return m, words[2]
    end

    -- Returns "trap" (precise illegal instruction on the csrrw), "exists" (no trap), or an error string.
    local function probe(csr)
        local m <close>, insn = make_machine(csr)
        m:run(4)
        if m:read_reg("pc") == MTVEC then
            local ok = m:read_reg("mcause") == 2 and m:read_reg("mepc") == RAM + 4 and m:read_reg("mtval") == insn
                and m:read_reg("x10") == SENTINEL and m:read_reg("iprv") == 3
            if ok then return "trap" end
            return string.format("imprecise trap mcause=%x mepc=%x mtval=%x a0=%x", m:read_reg("mcause"),
                m:read_reg("mepc"), m:read_reg("mtval"), m:read_reg("x10"))
        end
        if m:read_reg("pc") == RAM + 12 then return "exists", m:read_reg("x10"), m:read_reg("x12") end
        return string.format("unexpected pc=%x", m:read_reg("pc"))
    end

    local okall = true
    local odd_bad, even = {}, {}
    local counts = { trap = 0, exists = 0 }
    for csr = 0x3a0, 0x3ef do
        local r, a0, a2 = probe(csr)
        local name = csr < 0x3b0 and string.format("pmpcfg%d", csr - 0x3a0) or string.format("pmpaddr%d", csr - 0x3b0)
        if r ~= "trap" and r ~= "exists" then
            okall = harness.expect(false, name .. ": " .. r) and okall
        elseif csr < 0x3b0 and (csr & 1) == 1 then
            if r ~= "trap" then odd_bad[#odd_bad + 1] = name end
        else
            even[#even + 1] = { name = name, r = r, a0 = a0, a2 = a2 }
            counts[r] = counts[r] + 1
        end
    end
    cleanup()
    print(string.format("pmpcfg(even)+pmpaddr: %d trap with a precise illegal-instruction exception, %d exist",
        counts.trap, counts.exists))
    for _, e in ipairs(even) do
        if e.r == "exists" then print(string.format("  %s exists: old=%x readback=%x", e.name, e.a0, e.a2)) end
    end

    okall = harness.expect(#odd_bad == 0,
        "RV64: odd pmpcfg CSRs are illegal and must trap" ..
        (#odd_bad > 0 and (" (did not: " .. table.concat(odd_bad, ",") .. ")") or "")) and okall
    -- "zero PMP CSRs" (all trap) or the CSRs exist; the lowest-numbered must be implemented first.
    local function exists(name)
        for _, e in ipairs(even) do if e.name == name then return e.r == "exists" end end
    end
    local consistent = counts.exists == 0 or (exists("pmpcfg0") and exists("pmpaddr0"))
    okall = harness.expect(consistent,
        "PMP CSRs: zero implemented (all non-existent, illegal instruction) or the lowest-numbered implemented first")
    and okall
    if counts.exists == 0 then
        print("observed: the machine implements zero PMP CSRs (every access is a precise illegal-instruction trap),"
            .. " which the privileged specification permits")
    end

    -- (c) R2: interpreter vs uarch + reset on the pmpcfg0 program.
    local mi <close> = make_machine(0x3a0)
    local mu <close> = make_machine(0x3a0)
    cleanup()
    for k = 1, 4 do
        mi:run(k)
        local br = mu:run_uarch()
        if br ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED then harness.setup_error("uarch did not halt") end
        mu:reset_uarch()
        okall = harness.expect(mi:get_root_hash() == mu:get_root_hash(),
            "R2: interpreter and uarch agree after mcycle " .. k) and okall
    end
    return okall
end)
