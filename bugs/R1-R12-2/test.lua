-- R1-R12-2: a TLB flush rewrites all 768 slots, already-invalid ones included, each through a non-inlined
-- write_tlb ecall wrapper, so one sfence.vma (or satp write, or privilege change) costs about 17,300 uarch cycles.
--
-- Requirement (THREAT_MODEL.md):
--   R12 "Each of the following operations has a worst case in host time and memory that is bounded ... They are an
--        mcycle, a uarch cycle, ..., a uarch-level claim, ..."
--   section 8, High: "A defect that lets the guest ... multiply the worst-case cost of an operation listed in R12 by a
--        constant factor, compared with the same operation without the defect ... A cost that the specified
--        semantics require is not a defect."
--
-- The specified semantics of sfence.vma x0, x0 only require that every TLB slot be invalid afterwards. The uarch-level
-- claim hashes the state after every uarch cycle, so the uarch cycles one mcycle executes are its cost unit.
--
-- The test runs a bare-metal guest whose loop alternates `sfence.vma x0, x0` and `addi x0, x0, 0` (control) and, for
-- each mcycle, counts the uarch cycles the pristine uarch program executes (deterministic counts, no timing) and the
-- TLB slots that are valid before it. For sfence.vma mcycles that start with at most 3 of the 768 slots valid, it
-- computes the uarch cycles the flush adds per slot over the control mcycle:
--     per_slot = (uarch_cycles(sfence) - uarch_cycles(addi)) / 768
-- and asserts per_slot <= 8. That bound is twice what an inlined loop that still writes every slot needs (move the
-- slot index, ecall, increment, branch: 4 uarch cycles per slot), and a loop that skips already-invalid slots needs
-- about as much (load, compare, branch, increment). On audit/prt2 per_slot is about 21.8 (about 17,300 uarch cycles
-- per sfence.vma against about 540 for the addi), so the test exits 1. Diagnostics: it single-steps one flush and
-- counts the write_tlb ecalls and how many of them target a slot that was already invalid.

local harness = require("harness")

local MAX_PER_SLOT = 8
local MAX_VALID_BEFORE = 3

-- RISC-V encodings of the guest (loaded at 0x80000000, runs in M-mode with bare translation):
--   loop: .rept 32 ; sfence.vma x0, x0 ; addi x0, x0, 0 ; .endr ; j loop
local SFENCE = 0x12000073
local NOP = 0x00000013
local function jal_x0(off)
    local imm = off & 0x1fffff
    local b20 = (imm >> 20) & 1
    local b10_1 = (imm >> 1) & 0x3ff
    local b11 = (imm >> 11) & 1
    local b19_12 = (imm >> 12) & 0xff
    return (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | 0x6f
end

harness.main(function()
    local cartesi = require("cartesi")
    local NSLOTS = cartesi.TLB_NUM_SETS * cartesi.TLB_SET_SIZE
    local SLOT = cartesi.SHADOW_TLB_SLOT_SIZE
    local TLB0 = cartesi.AR_SHADOW_TLB_START
    local INVALID = -1 -- TLB_INVALID_PAGE = UINT64_C(-1)

    local words = {}
    for _ = 1, 32 do
        words[#words + 1] = SFENCE
        words[#words + 1] = NOP
    end
    words[#words + 1] = jal_x0(-4 * #words)
    local parts = {}
    for i, w in ipairs(words) do parts[i] = string.pack("<I4", w) end
    local image = table.concat(parts)

    local tmp = io.popen("mktemp -d"):read("l")
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local bin = tmp .. "/guest.bin"
    local f = assert(io.open(bin, "wb"))
    f:write(image)
    f:close()
    local ok, err = pcall(function()
        local m <close> = cartesi.machine({ ram = { length = 64 << 20, backing_store = { data_filename = bin } } })
        os.remove(bin)

        local function valid_slots()
            local tlb = m:read_memory(TLB0, NSLOTS * SLOT)
            local n = 0
            for i = 0, NSLOTS - 1 do
                if string.unpack("<i8", tlb, i * SLOT + 1) ~= INVALID then n = n + 1 end
            end
            return n
        end
        local function slot_valid(set, slot)
            local v = string.unpack("<i8", m:read_memory(TLB0 + (set * cartesi.TLB_SET_SIZE + slot) * SLOT, 8))
            return v ~= INVALID
        end
        local function cur_insn() return string.unpack("<I4", m:read_memory(m:read_reg("pc"), 4)) end

        m:run(100) -- inside the loop
        if m:read_reg("iflags_H") ~= 0 or m:read_reg("mcycle") ~= 100 then error("guest did not reach its loop") end

        -- 1. Deterministic per-mcycle uarch cycle counts
        local sf, nop = {}, {}
        local diag_done = false
        local diag = nil
        for _ = 1, 40 do
            local insn = cur_insn()
            local valid = valid_slots()
            if insn == SFENCE and valid <= MAX_VALID_BEFORE and not diag_done then
                -- Diagnostics: single-step this flush, counting write_tlb ecalls and their targets
                diag_done = true
                local ecalls, to_invalid = 0, 0
                while true do
                    local upc = m:read_reg("uarch_pc")
                    local uinsn = string.unpack("<I4", m:read_memory(upc, 4))
                    if uinsn == 0x00000073 and m:read_reg("uarch_x17") == cartesi.UARCH_ECALL_FN_WRITE_TLB then
                        ecalls = ecalls + 1
                        if not slot_valid(m:read_reg("uarch_x10"), m:read_reg("uarch_x11")) then
                            to_invalid = to_invalid + 1
                        end
                    end
                    local br = m:run_uarch(m:read_reg("uarch_cycle") + 1)
                    if br == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then break end
                    if m:read_reg("uarch_cycle") >= cartesi.UARCH_CYCLE_MAX then error("uarch did not halt") end
                end
                diag = { valid = valid, ecalls = ecalls, to_invalid = to_invalid, cycles = m:read_reg("uarch_cycle") }
                sf[#sf + 1] = diag.cycles
            else
                local br = m:run_uarch(cartesi.UARCH_CYCLE_MAX)
                if br ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED then error("uarch did not halt") end
                local c = m:read_reg("uarch_cycle")
                if insn == SFENCE and valid <= MAX_VALID_BEFORE then
                    sf[#sf + 1] = c
                elseif insn == NOP then
                    nop[#nop + 1] = c
                end
            end
            m:reset_uarch()
        end
        if #sf < 8 or #nop < 8 or not diag then error("too few classified mcycles") end

        local function max(t)
            local r = t[1]
            for _, v in ipairs(t) do if v > r then r = v end end
            return r
        end
        local function min(t)
            local r = t[1]
            for _, v in ipairs(t) do if v < r then r = v end end
            return r
        end
        local sf_min, sf_max, nop_max = min(sf), max(sf), max(nop)
        local per_slot = (sf_min - nop_max) / NSLOTS
        print(string.format("addi mcycles: %d, uarch cycles max %d", #nop, nop_max))
        print(string.format("sfence.vma mcycles (<= %d of %d slots valid before): %d, uarch cycles min %d max %d",
            MAX_VALID_BEFORE, NSLOTS, #sf, sf_min, sf_max))
        print(string.format("single-stepped flush: %d slots valid before, %d write_tlb ecalls, %d of them to slots "
            .. "already invalid, %d uarch cycles", diag.valid, diag.ecalls, diag.to_invalid, diag.cycles))
        print(string.format("flush cost over the control: %.2f uarch cycles per slot (bound %d)", per_slot,
            MAX_PER_SLOT))
        return per_slot
    end)
    os.execute("rm -rf '" .. tmp .. "'")
    if not ok then error(err, 0) end
    return harness.expect(err <= MAX_PER_SLOT, string.format("R12 / section 8 High: an sfence.vma over an almost "
        .. "empty TLB costs %.2f uarch cycles per slot (more than %d) beyond an addi; rewriting already-invalid slots "
        .. "through a non-inlined ecall wrapper multiplies the worst-case cost of an mcycle and of a uarch-level "
        .. "claim by a constant factor the semantics do not require", err, MAX_PER_SLOT))
end)
