-- R2-DFGUESTSTATE-1: the manual documents Sv39 as the address-translation mode of the main processor, but the
-- interpreter also accepts satp.MODE = 9 (Sv48) and walks four-level page tables.
--
-- Requirement (THREAT_MODEL.md R7): "The emulator implements the RISC-V specification and the devices as the
-- manual documents them, departing only where the manual documents a deviation. [...] Address translation and
-- memory permissions."
-- The manual (doc/README.md, "The main processor"): "Cartesi Machines support the Sv39 mode of address
-- translation and memory protection. Sv39 provides a 39-bit protected virtual address space, divided into 4KiB
-- pages, organized by a three-level page table." The device tree the emulator generates advertises
-- mmu-type = "riscv,sv39".
-- RISC-V privileged specification, satp: "Implementations are not required to support all MODE settings, and if
-- satp is written with an unsupported MODE, the entire write has no effect; no fields in satp are modified."
--
-- Asserted: unless the manual's "The main processor" section documents Sv48, a guest write of satp with
-- MODE = 9 has no effect (satp keeps its previous value, here 0 = Bare).
-- Controls (setup errors if they fail): MODE = 8 (Sv39) is accepted, MODE = 10 (Sv57, compiled out) is ignored.
-- Informational: after the MODE = 9 write, an M-mode load with MPRV=1/MPP=S from a virtual address that only
-- Sv48 can translate (0x80_8000_0000, non-canonical under Sv39, beyond every PMA in Bare mode) succeeds through
-- a root-level 512 GiB terapage, showing that four-level walks are performed; and the uarch path agrees.
-- Exit 1 if the assertion is violated, 0 if it holds, 2 on setup errors.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local TVEC = RAM + 0x1000
    local ROOT = RAM + 0x10000 -- page-table root (4 KiB aligned)
    local DATA = RAM + 0x20000
    local MAGIC = 0x5356343821212121 -- "!!!!8VS" little endian, any recognizable value
    local SATP_SHIFT = 60
    local NOP = 0x00000013
    local CSRW_SATP_X5 = 0x18029073 -- csrrw x0, satp, x5
    local CSRR_X6_SATP = 0x18002373 -- csrrs x6, satp, x0
    local LD_X7_0_X8 = 0x00043383 -- ld x7, 0(x8)
    local MSTATUS_MPP_S = 1 << 11
    local MSTATUS_MPRV = 1 << 17
    -- leaf PTE: V R W X A D, ppn 0 => a 512 GiB terapage at the root of an Sv48 table maps VA [i*2^39, ...) to PA 0
    local PTE_LEAF_PPN0 = 0x1 | 0x2 | 0x4 | 0x8 | 0x40 | 0x80
    local VA_SV48_ONLY = (1 << 39) + DATA -- root index 1 under Sv48; bits 63..39 not a sign extension of bit 38

    -- Runs, in M-mode: csrw satp, x5 ; csrr x6, satp ; ld x7, 0(x8) (with MPRV=1, MPP=S when probing loads)
    -- Returns satp, x6 (read back by the guest), x7, mcause, pc
    local function probe(satp_val, use_uarch, with_load)
        local m <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        local prog = string.pack("<I4I4I4I4I4I4", CSRW_SATP_X5, CSRR_X6_SATP, with_load and LD_X7_0_X8 or NOP,
            NOP, NOP, NOP)
        m:write_memory(RAM, prog)
        m:write_memory(TVEC, string.pack("<I4I4I4I4", NOP, NOP, NOP, NOP))
        -- Sv48 root: entries 0 and 1 are terapages to PA 0 (identity for the first 512 GiB, and VA 2^39+x -> x)
        m:write_memory(ROOT, string.pack("<I8I8", PTE_LEAF_PPN0, PTE_LEAF_PPN0))
        m:write_memory(DATA, string.pack("<I8", MAGIC))
        m:write_reg("pc", RAM)
        m:write_reg("iprv", 3)
        m:write_reg("mtvec", TVEC)
        m:write_reg("mcause", 0xdead)
        if m:read_reg("satp") ~= 0 then harness.setup_error("fresh machine has satp ~= 0") end
        if with_load then m:write_reg("mstatus", m:read_reg("mstatus") | MSTATUS_MPRV | MSTATUS_MPP_S) end
        m:write_reg("x5", satp_val)
        m:write_reg("x6", 0xdeadbeef)
        m:write_reg("x7", 0)
        m:write_reg("x8", VA_SV48_ONLY)
        local mc = m:read_reg("mcycle")
        local n = 3
        if use_uarch then
            for _ = 1, n do
                if m:run_uarch() ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
                    harness.setup_error("uarch did not halt")
                end
                m:reset_uarch()
            end
        else
            m:run(mc + n)
        end
        if m:read_reg("mcycle") ~= mc + n then harness.setup_error("did not complete " .. n .. " mcycles") end
        return m:read_reg("satp"), m:read_reg("x6"), m:read_reg("x7"), m:read_reg("mcause"), m:read_reg("pc")
    end

    local ppn = ROOT >> 12
    local function satp_of(mode) return (mode << SATP_SHIFT) | ppn end

    -- controls: Sv39 accepted, Sv57 (compiled out) ignored as the WARL rule requires
    do
        local s8, r8 = probe(satp_of(8))
        if s8 ~= satp_of(8) or r8 ~= satp_of(8) then
            harness.setup_error(string.format("control: Sv39 write not accepted (satp=0x%x)", s8))
        end
        local s10, r10 = probe(satp_of(10))
        if s10 ~= 0 or r10 ~= 0 then
            harness.setup_error(string.format("control: Sv57 write took effect (satp=0x%x)", s10))
        end
        print(string.format("control: write 0x%016x (Sv39) -> satp 0x%016x (accepted)", satp_of(8), s8))
        print(string.format("control: write 0x%016x (Sv57) -> satp 0x%016x (ignored, WARL)", satp_of(10), s10))
    end

    -- the probe
    local s9, r9 = probe(satp_of(9))
    print(string.format("probe:   write 0x%016x (Sv48) -> satp 0x%016x, guest read-back 0x%016x (MODE %d)",
        satp_of(9), s9, r9, r9 >> SATP_SHIFT))

    -- informational: four-level translation in effect, and the uarch agrees
    do
        local _, _, x7, cause, pc = probe(satp_of(9), false, true)
        local translated = (x7 == MAGIC and cause == 0xdead)
        print(string.format("info:    MPRV load from VA 0x%x (translatable only by Sv48): %s", VA_SV48_ONLY,
            translated and string.format("loaded 0x%x from PA 0x%x via a root-level terapage", x7, DATA)
                or string.format("faulted (mcause=0x%x pc=0x%x)", cause, pc)))
        local _, _, c7, ccause = probe(satp_of(8), false, true)
        print(string.format("info:    same load with the same table under Sv39: %s", (c7 == MAGIC)
            and "loaded" or string.format("faulted (mcause=0x%x, 13 = load page fault)", ccause)))
        local us9, ur9 = probe(satp_of(9), true)
        local _, _, ux7 = probe(satp_of(9), true, true)
        print(string.format("info:    uarch path: satp 0x%016x, read-back 0x%016x, Sv48-only load %s", us9, ur9,
            ux7 == MAGIC and "translated" or "faulted"))
    end

    local manual = harness.read_file(os.getenv("REPO") .. "/doc/README.md")
    local section = manual:match("\n### The main processor\n(.-)\n###? ") or ""
    if section == "" then harness.setup_error("cannot find the manual section 'The main processor'") end
    local documents_sv48 = section:find("Sv48", 1, true) ~= nil
    print(string.format("manual, 'The main processor': documents Sv39 = %s, documents Sv48 = %s",
        tostring(section:find("Sv39", 1, true) ~= nil), tostring(documents_sv48)))

    local ok = documents_sv48 or (s9 == 0 and r9 == 0)
    if not ok then
        print(string.format("VIOLATION: satp.MODE=9 (Sv48) write took effect (satp=0x%x), but the manual documents "
            .. "only Sv39 (three-level page tables) and the WARL rule requires the write to have no effect", s9))
    end
    return harness.expect(ok, "R7: address translation as the manual documents it: a write of satp with an "
        .. "undocumented MODE (Sv48) must have no effect unless the manual documents Sv48")
end)
