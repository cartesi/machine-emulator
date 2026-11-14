-- R3-VARSPEC-2: a guest write to mcycle (CSR 0xB00) in M-mode raises an illegal-instruction exception, a
-- deviation from the RISC-V privileged specification (mcycle is an MRW counter) that the manual does not document.
--
-- Required (THREAT_MODEL.md R7, area "Traps and interrupts"): "The emulator implements the RISC-V specification and
-- the devices as the manual documents them, departing only where the manual documents a deviation."
-- R8 also requires that the guest "can never change the cycle counter", so the only behavior consistent with both
-- rules is a deviation (trap or ignored write) that doc/README.md documents.
--
-- The test runs, in M-mode on a bare 1 MiB machine, natively (machine:run) and on the uarch path
-- (run_uarch + reset_uarch), each of:
--   csrrw x0,mcycle,x6 / csrrs x0,mcycle,x6 / csrrc x0,mcycle,x6 / csrrwi x0,mcycle,5   (writes, x6 = 0x12345)
-- and controls that must retire:
--   csrrw x0,minstret,x6 (writable sibling counter)  /  csrrs x7,mcycle,x0 (plain read of mcycle)
-- Both paths must agree (a disagreement is a harness error: it would be a different defect).
--
-- Verdict:
--   exit 0  if doc/README.md has a sentence that names `mcycle` together with a statement that it is not writable
--           (read-only / not writable / cannot be written / writes trap / raise an illegal-instruction exception /
--           writes are ignored), and the observed write behavior does not change mcycle;
--   exit 1  if a write traps (or is ignored) and the manual documents nothing, or if a write changes mcycle (R8).

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local HANDLER = RAM + 0x100
    local VAL = 0x12345
    local J_SELF = 0x0000006f -- jal x0,0

    local function csr_insn(csr, funct3, rs1, rd) return (csr << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | 0x73 end
    local MCYCLE, MINSTRET = 0xB00, 0xB02

    local cases = {
        { name = "csrrw x0,mcycle,x6", insn = csr_insn(MCYCLE, 1, 6, 0), write = true },
        { name = "csrrs x0,mcycle,x6", insn = csr_insn(MCYCLE, 2, 6, 0), write = true },
        { name = "csrrc x0,mcycle,x6", insn = csr_insn(MCYCLE, 3, 6, 0), write = true },
        { name = "csrrwi x0,mcycle,5", insn = csr_insn(MCYCLE, 5, 5, 0), write = true },
        { name = "csrrw x0,minstret,x6 (control)", insn = csr_insn(MINSTRET, 1, 6, 0), control = true },
        { name = "csrrs x7,mcycle,x0 (control)", insn = csr_insn(MCYCLE, 2, 0, 7), control = true },
    }

    local function run_case(c, uarch)
        local m <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        m:write_memory(RAM, string.pack("<I4I4", c.insn, J_SELF))
        m:write_memory(HANDLER, string.pack("<I4", J_SELF))
        m:write_reg("mtvec", HANDLER)
        m:write_reg("x6", VAL)
        assert(m:read_reg("iprv") == 3, "machine must start in M-mode")
        local mcycle0 = m:read_reg("mcycle")
        if uarch then
            m:run_uarch()
            m:reset_uarch()
        else
            m:run(mcycle0 + 1)
        end
        local r = {
            pc = m:read_reg("pc"),
            mcause = m:read_reg("mcause"),
            mtval = m:read_reg("mtval"),
            mcycle = m:read_reg("mcycle"),
            mcycle0 = mcycle0,
            root = m:get_root_hash(),
        }
        r.trapped = r.pc == HANDLER
        r.retired = r.pc == RAM + 4
        -- a write to mcycle that takes effect is judged below (R8); anything else must take exactly one cycle
        if r.mcycle ~= mcycle0 + 1 and not (c.write and r.retired) then
            error(string.format("%s (%s): mcycle advanced from %d to %d, expected exactly one cycle", c.name,
                uarch and "uarch" or "native", mcycle0, r.mcycle))
        end
        return r
    end

    local trapped, ignored, changed = 0, 0, 0
    for _, c in ipairs(cases) do
        local n = run_case(c, false)
        local u = run_case(c, true)
        if n.root ~= u.root or n.pc ~= u.pc then
            harness.setup_error(c.name .. ": native and uarch paths disagree (different defect)")
        end
        print(string.format("%-34s native+uarch: pc=0x%x mcause=%d mtval=0x%x mcycle %d->%d  %s", c.name, n.pc,
            n.mcause, n.mtval, n.mcycle0, n.mcycle,
            n.trapped and "TRAPPED (illegal instruction)" or (n.retired and "retired" or "?")))
        if not n.trapped and not n.retired then harness.setup_error(c.name .. ": neither trapped nor retired") end
        if c.control then
            if not n.retired then harness.setup_error(c.name .. ": control instruction did not retire") end
        else
            if n.trapped then
                if n.mcause ~= 2 or n.mtval ~= c.insn then
                    harness.setup_error(c.name .. ": unexpected trap cause")
                end
                trapped = trapped + 1
            elseif n.mcycle ~= n.mcycle0 + 1 then
                changed = changed + 1 -- the write took effect: the guest changed the cycle counter
            else
                -- retired: mcycle advanced by one, so the written value did not take effect
                ignored = ignored + 1
            end
        end
    end

    -- Does the manual document that mcycle is not writable by the guest?
    -- MANUAL_OVERRIDE (optional) points at another copy of the manual, to check the test against a documented fix
    local manual = harness.read_file(os.getenv("MANUAL_OVERRIDE") or (os.getenv("REPO") .. "/doc/README.md"))
    -- prose only: drop fenced code blocks, join lines, then look at each sentence that names `mcycle`
    local prose = manual:gsub("\r", ""):gsub("\n```.-\n```", "\n"):gsub("\n", " ")
    local function says_not_writable(lower)
        if lower:find("read%-only") or lower:find("read only") then return true end
        if not (lower:find("writ") or lower:find("modif") or lower:find("csrw")) then return false end
        for _, k in ipairs({ "illegal", "trap", "exception", "cannot", "can't", "can not", "not ", "ignored", "raise",
            "fault", "never" }) do
            if lower:find(k, 1, true) then return true end
        end
        return false
    end
    local documented = nil
    for sentence in (prose .. " "):gmatch("(.-[%.%?!])%s") do
        if sentence:find("%f[%w_]mcycle%f[^%w_]") and says_not_writable(sentence:lower()) then
            documented = sentence
            break
        end
    end
    if documented then
        print("manual documents it: " .. documented:sub(1, 300))
    else
        print("manual: no sentence naming `mcycle` says it is read-only, not writable, or that writes trap")
    end

    print(string.format("writes to mcycle: %d trapped, %d retired without effect, %d changed mcycle", trapped,
        ignored, changed))

    if changed > 0 then
        return harness.expect(false, "R8: the guest can never change the cycle counter")
    end
    return harness.expect(documented ~= nil,
        "R7 (Traps and interrupts): a guest write to mcycle in M-mode departs from the RISC-V privileged spec "
            .. "(mcycle is MRW) and the manual must document that deviation")
end)
