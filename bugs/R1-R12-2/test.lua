-- R1-R12-2: every TLB flush writes all 768 slots, each through a non-inlined write_tlb ecall wrapper (22 uarch
-- instructions per slot), so one sfence.vma (or satp write, or privilege change) costs about 17,500 uarch cycles
-- whatever the TLB holds, including in the worst case, a full TLB.
--
-- Requirement (THREAT_MODEL.md):
--   R12 "Each of the following operations has a worst case in host time and memory that is bounded ... They are an
--        mcycle, a uarch cycle, ..., a uarch-level claim, ..."
--   section 8, High: "A defect that lets the guest ... multiply the worst-case cost of an operation listed in R12 by a
--        constant factor, compared with the same operation without the defect ... A cost that the specified
--        semantics require is not a defect."
--
-- With every one of the 768 TLB slots valid, the semantics of sfence.vma x0, x0 require 768 slot writes, and in the
-- uarch each slot write is one write_tlb ecall. Issuing them from an inlined loop costs about 3 to 4 uarch cycles per
-- slot (set the slot index, ecall, increment, branch). The test asserts that a flush of a FULL TLB (the worst case of
-- the flush) costs at most 8 uarch cycles per slot beyond a control mcycle (an addi that misses the code TLB).
--
-- Part 1 (decisive, worst case): a guest touches 256 code pages, reads 256 pages and writes 256 pages, so all 768
-- slots are valid, then executes sfence.vma. The test counts the exact uarch cycles of that mcycle (deterministic
-- counts, no timing) and of the addi that follows it (code TLB miss, the larger control).
-- Part 2 (diagnostic only, not asserted): a guest alternates sfence.vma and addi with an almost empty TLB; the test
-- single-steps one flush and counts the write_tlb ecalls and how many of them target a slot already invalid. Skipping
-- those would only help the average case, which section 8 puts out of scope, so it is not asserted.
--
-- On audit/prt2 a flush costs 17,492 uarch cycles in both parts (21.96 per slot), so the test exits 1.
-- (Test revised by the reviewer: the original asserted only the almost-empty case of part 2.)

local harness = require("harness")

local MAX_PER_SLOT = 8

-- RV64 encoders
local function jal(rd, off)
    local imm = off & 0x1fffff
    return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3ff) << 21) | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12) | (rd << 7) | 0x6f
end
local function itype(op, f3, rd, rs1, imm)
    return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
end
local function addi(rd, rs1, imm) return itype(0x13, 0, rd, rs1, imm) end
local function ld(rd, rs1, imm) return itype(0x03, 3, rd, rs1, imm) end
local function sd(rs2, rs1, imm)
    imm = imm & 0xfff
    return ((imm >> 5) << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | ((imm & 31) << 7) | 0x23
end
local function add(rd, rs1, rs2) return (rs2 << 20) | (rs1 << 15) | (rd << 7) | 0x33 end
local function lui(rd, imm20) return (imm20 << 12) | (rd << 7) | 0x37 end
local function auipc(rd, imm20) return (imm20 << 12) | (rd << 7) | 0x17 end
local function bne(rs1, rs2, off)
    local imm = off & 0x1fff
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) | (rs2 << 20) | (rs1 << 15) | (1 << 12)
        | (((imm >> 1) & 0xf) << 8) | (((imm >> 11) & 1) << 7) | 0x63
end
local SFENCE, NOP = 0x12000073, 0x00000013
local T0, T1, T2, T3, T4, T5 = 5, 6, 7, 28, 29, 30
local PAGE = 4096
local RAM_START = 0x80000000

-- Full-TLB guest. Pages 0..254 each start with "j next page" (fills the 256 code slots); page 255 reads pages
-- 256..511 and writes pages 512..767 (fills the 256 read and 256 write slots), then sfence.vma; addi; j .
local function full_tlb_image()
    local words = {}
    for k = 0, 254 do words[k * PAGE // 4] = jal(0, PAGE) end
    local main = {
        auipc(T0, 0), lui(T5, 1), add(T0, T0, T5), lui(T4, 0x100), add(T3, T0, T4), addi(T1, 0, 256),
        ld(T2, T0, 0), sd(T2, T3, 0), add(T0, T0, T5), add(T3, T3, T5), addi(T1, T1, -1), bne(T1, 0, -20),
        SFENCE, NOP, jal(0, 0),
    }
    for i, w in ipairs(main) do words[(255 * PAGE) // 4 + i - 1] = w end
    local parts = {}
    for i = 0, 256 * PAGE // 4 - 1 do parts[#parts + 1] = string.pack("<I4", words[i] or 0) end
    return table.concat(parts), RAM_START + 255 * PAGE + 12 * 4
end

-- Almost-empty-TLB guest: loop: .rept 32 ; sfence.vma ; addi x0, x0, 0 ; .endr ; j loop
local function alternating_image()
    local parts = {}
    for _ = 1, 32 do
        parts[#parts + 1] = string.pack("<I4", SFENCE)
        parts[#parts + 1] = string.pack("<I4", NOP)
    end
    parts[#parts + 1] = string.pack("<I4", jal(0, -4 * 64))
    return table.concat(parts)
end

harness.main(function()
    local cartesi = require("cartesi")
    local NSLOTS = cartesi.TLB_NUM_SETS * cartesi.TLB_SET_SIZE
    local SLOT = cartesi.SHADOW_TLB_SLOT_SIZE
    local TLB0 = cartesi.AR_SHADOW_TLB_START
    local INVALID = -1 -- TLB_INVALID_PAGE = UINT64_C(-1)

    local tmp = io.popen("mktemp -d"):read("l")
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function new_machine(image)
        local bin = tmp .. "/guest.bin"
        local f = assert(io.open(bin, "wb"))
        f:write(image)
        f:close()
        local m = cartesi.machine({ ram = { length = 64 << 20, backing_store = { data_filename = bin } } })
        os.remove(bin)
        return m
    end

    local ok, res = pcall(function()
        local function valid_slots(m)
            local tlb = m:read_memory(TLB0, NSLOTS * SLOT)
            local n = 0
            for i = 0, NSLOTS - 1 do
                if string.unpack("<i8", tlb, i * SLOT + 1) ~= INVALID then n = n + 1 end
            end
            return n
        end
        local function uarch_cycles_of_mcycle(m)
            local br = m:run_uarch(cartesi.UARCH_CYCLE_MAX)
            if br ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED then error("uarch did not halt") end
            local c = m:read_reg("uarch_cycle")
            m:reset_uarch()
            return c
        end
        local function cur_insn(m) return string.unpack("<I4", m:read_memory(m:read_reg("pc"), 4)) end

        -- Part 1: worst case, full TLB
        local image, sfpc = full_tlb_image()
        local m1 <close> = new_machine(image)
        while m1:read_reg("pc") ~= sfpc do
            m1:run(m1:read_reg("mcycle") + 1)
            if m1:read_reg("mcycle") > 100000 or m1:read_reg("iflags_H") ~= 0 then error("guest did not reach sfence") end
        end
        local full_valid = valid_slots(m1)
        if full_valid ~= NSLOTS then error("TLB not full before the sfence.vma: " .. full_valid) end
        local full_sf = uarch_cycles_of_mcycle(m1)
        local after_valid = valid_slots(m1)
        if cur_insn(m1) ~= NOP then error("expected the addi after the sfence.vma") end
        local full_nop = uarch_cycles_of_mcycle(m1)
        local per_slot = (full_sf - full_nop) / NSLOTS
        print(string.format("full TLB: %d of %d slots valid before sfence.vma, %d after; sfence.vma %d uarch cycles, "
            .. "following addi %d", full_valid, NSLOTS, after_valid, full_sf, full_nop))

        -- Part 2: diagnostic, almost empty TLB
        local m2 <close> = new_machine(alternating_image())
        m2:run(100)
        local diag
        for _ = 1, 4 do
            local insn, valid = cur_insn(m2), valid_slots(m2)
            if insn == SFENCE then
                local ecalls, to_invalid = 0, 0
                while true do
                    local uinsn = string.unpack("<I4", m2:read_memory(m2:read_reg("uarch_pc"), 4))
                    if uinsn == 0x00000073 and m2:read_reg("uarch_x17") == cartesi.UARCH_ECALL_FN_WRITE_TLB then
                        ecalls = ecalls + 1
                        local set, slot = m2:read_reg("uarch_x10"), m2:read_reg("uarch_x11")
                        local addr = TLB0 + (set * cartesi.TLB_SET_SIZE + slot) * SLOT
                        if string.unpack("<i8", m2:read_memory(addr, 8)) == INVALID then to_invalid = to_invalid + 1 end
                    end
                    local br = m2:run_uarch(m2:read_reg("uarch_cycle") + 1)
                    if br == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then break end
                    if m2:read_reg("uarch_cycle") >= cartesi.UARCH_CYCLE_MAX then error("uarch did not halt") end
                end
                diag = { valid = valid, ecalls = ecalls, to_invalid = to_invalid, cycles = m2:read_reg("uarch_cycle") }
                m2:reset_uarch()
                break
            end
            uarch_cycles_of_mcycle(m2)
        end
        if not diag then error("no sfence.vma in the alternating guest") end
        print(string.format("almost empty TLB (diagnostic): %d slots valid before, %d write_tlb ecalls, %d of them to "
            .. "slots already invalid, %d uarch cycles", diag.valid, diag.ecalls, diag.to_invalid, diag.cycles))
        print(string.format("full-TLB flush cost over the control: %.2f uarch cycles per slot (bound %d)", per_slot,
            MAX_PER_SLOT))
        return per_slot
    end)
    os.execute("rm -rf '" .. tmp .. "'")
    if not ok then error(res, 0) end
    return harness.expect(res <= MAX_PER_SLOT, string.format("R12 / section 8 High: flushing a full TLB costs %.2f "
        .. "uarch cycles per slot (more than %d) beyond an addi; the 768 required write_tlb ecalls are each issued "
        .. "through a non-inlined 14-instruction wrapper from an 8-instruction loop body, multiplying the worst-case "
        .. "cost of the flush mcycle, and of a uarch-level claim, by a constant factor the semantics do not require",
        res, MAX_PER_SLOT))
end)
