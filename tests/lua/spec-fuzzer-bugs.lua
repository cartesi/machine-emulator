--[[
Regression tests for bugs found by the fuzzer.

Each test sets up a minimal machine state that would have triggered a crash
or incorrect behavior before the corresponding fix was applied.
]]

local lester = require("cartesi.third-party.lester")
local cartesi = require("cartesi")
local describe, it, expect = lester.describe, lester.it, lester.expect

-- RISC-V constants
local RAM_START = cartesi.AR_RAM_START
local MSTATUS_SIE = 1 << 1
local MSTATUS_MIE = 1 << 3
local MSTATUS_MPP_S = 1 << 11
local MSTATUS_FS_DIRTY = 3 << 13
local MIP_SSIP = 1 << 1
local MIP_MTIP = 1 << 7
local MIP_MEIP = 1 << 11

-- CSR numbers (RISC-V privileged spec)
local CSR = {
    fcsr = 0x003,
    stvec = 0x105,
    scounteren = 0x106,
    senvcfg = 0x10A,
    satp = 0x180,
    mstatus = 0x300,
    medeleg = 0x302,
    mideleg = 0x303,
    mie = 0x304,
    mtvec = 0x305,
    mcounteren = 0x306,
    menvcfg = 0x30A,
    mepc = 0x341,
    sepc = 0x141,
    mip = 0x344,
}

-- Expected WARL masks (from riscv-warl.h / riscv-constants.h)
-- MIP_RW_MASK: bits 1,3,5,7,9,11
local MIP_RW_MASK = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 7) | (1 << 9) | (1 << 11)
-- MIP_S_RW_MASK: bits 1,5,9
local MIP_S_RW_MASK = (1 << 1) | (1 << 5) | (1 << 9)
-- MEDELEG_W_MASK: exception causes 0-9, 12-13, 15
local MEDELEG_W_MASK = (1 << 0)
    | (1 << 1)
    | (1 << 2)
    | (1 << 3)
    | (1 << 4)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (1 << 9)
    | (1 << 12)
    | (1 << 13)
    | (1 << 15)
-- MCOUNTEREN/SCOUNTEREN: bits 0,1,2 (CY, TM, IR)
local COUNTEREN_RW_MASK = (1 << 0) | (1 << 1) | (1 << 2)
-- MENVCFG/SENVCFG: only FIOM (bit 0)
local ENVCFG_R_MASK = 1 << 0
-- FCSR: bits 0-7 (fflags + frm)
local FCSR_RW_MASK = 0xFF
-- MSTATUS_R_MASK: all readable bits
local MSTATUS_R_MASK = (1 << 1)
    | (1 << 3)
    | (1 << 5)
    | (1 << 6)
    | (1 << 7)
    | (1 << 8)
    | (3 << 9)
    | (3 << 11)
    | (3 << 13)
    | (1 << 17)
    | (1 << 18)
    | (1 << 19)
    | (1 << 20)
    | (1 << 21)
    | (1 << 22)
    | (3 << 32)
    | (3 << 34)
    | (1 << 36)
    | (1 << 37)
    | (1 << 63)

-- Encode csrrs rd, csr, x0 (read CSR into rd without modifying it)
local function encode_csrrs(rd, csr_number)
    return string.pack("<I4", (csr_number << 20) | (0x2 << 12) | (rd << 7) | 0x73)
end

-- NOP: addi x0, x0, 0
local NOP = "\x13\x00\x00\x00"

-- Helper: create a machine, write an illegal value to a CSR via write_reg,
-- then execute csrrs x1, csr, x0 to read the value as seen by the interpreter.
local function read_csr_via_interpret(csr_name, illegal_value)
    local machine <close> = cartesi.machine({
        ram = { length = 1 << 20 },
        processor = { registers = { mstatus = MSTATUS_FS_DIRTY } },
    })
    machine:write_memory(RAM_START, encode_csrrs(1, CSR[csr_name]))
    machine:write_reg(csr_name, illegal_value)
    machine:write_reg("pc", RAM_START)
    machine:run(1)
    return machine:read_reg("x1")
end

describe("fuzzer bugs", function()
    -- Bug 1: misaligned PC at startup (commit 111687e5)
    --
    -- The interpreter assumed PC is always 2-byte aligned, but the external API
    -- allowed setting PC to an odd value. The fetch logic used a 2-byte-aligned
    -- pointer derived from PC, causing undefined behavior.
    --
    -- Fix: check PC alignment at interpreter entry and raise
    -- MCAUSE_INSN_ADDRESS_MISALIGNED if bit 0 is set.
    it("should handle misaligned PC without crashing", function()
        local machine <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        machine:write_memory(RAM_START, NOP)
        machine:write_reg("pc", RAM_START + 1)
        -- Before the fix, this would crash or produce undefined behavior.
        local br = machine:run(1)
        expect.equal(br, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        expect.not_equal(machine:read_reg("pc"), RAM_START + 1)
    end)

    -- Bug 2: WARL registers not legalized through state access layer (commit 20f11c4e)
    --
    -- WARL bit-masking was only applied inside CSR instruction handlers, so
    -- external writes via write_reg could store illegal bit patterns that the
    -- interpreter would consume raw when reading the CSR.
    --
    -- Fix: centralized legalization in the i-state-access layer (riscv-warl.h).
    --
    -- To test: write all-ones via write_reg, then execute csrrs x1, csr, x0
    -- and check x1 has the legalized value.
    describe("WARL register legalization", function()
        it("should mask mtvec low 2 bits", function()
            local val = read_csr_via_interpret("mtvec", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, 0xFFFFFFFFFFFFFFFF & ~3)
        end)

        it("should mask stvec low 2 bits", function()
            local val = read_csr_via_interpret("stvec", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, 0xFFFFFFFFFFFFFFFF & ~3)
        end)

        it("should mask mepc low bit", function()
            local val = read_csr_via_interpret("mepc", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, 0xFFFFFFFFFFFFFFFF & ~1)
        end)

        it("should mask sepc low bit", function()
            local val = read_csr_via_interpret("sepc", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, 0xFFFFFFFFFFFFFFFF & ~1)
        end)

        it("should mask fcsr to valid bits", function()
            local val = read_csr_via_interpret("fcsr", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, FCSR_RW_MASK)
        end)

        it("should mask mie to valid interrupt bits", function()
            local val = read_csr_via_interpret("mie", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, MIP_RW_MASK)
        end)

        it("should mask mip to valid interrupt bits", function()
            local val = read_csr_via_interpret("mip", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, MIP_RW_MASK)
        end)

        it("should mask mideleg to supervisor-delegatable bits", function()
            local val = read_csr_via_interpret("mideleg", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, MIP_S_RW_MASK)
        end)

        it("should mask medeleg to valid exception causes", function()
            local val = read_csr_via_interpret("medeleg", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, MEDELEG_W_MASK)
        end)

        it("should mask mcounteren to valid bits", function()
            local val = read_csr_via_interpret("mcounteren", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, COUNTEREN_RW_MASK)
        end)

        it("should mask scounteren to valid bits", function()
            local val = read_csr_via_interpret("scounteren", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, COUNTEREN_RW_MASK)
        end)

        it("should mask menvcfg to FIOM bit only", function()
            local val = read_csr_via_interpret("menvcfg", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, ENVCFG_R_MASK)
        end)

        it("should mask senvcfg to FIOM bit only", function()
            local val = read_csr_via_interpret("senvcfg", 0xFFFFFFFFFFFFFFFF)
            expect.equal(val, ENVCFG_R_MASK)
        end)

        it("should reject invalid satp modes", function()
            -- Mode field [63:60] = 5 is not a valid SV mode; should read back as 0
            local val = read_csr_via_interpret("satp", 5 << 60 | 0xDEADBEEF)
            expect.equal(val, 0)
        end)

        it("should accept valid satp SV39 mode", function()
            local val = read_csr_via_interpret("satp", 8 << 60 | 0x12345)
            expect.equal(val, 8 << 60 | 0x12345)
        end)

        it("should mask mstatus to readable bits", function()
            local val = read_csr_via_interpret("mstatus", 0xFFFFFFFFFFFFFFFF)
            -- All-ones with FS != off means FS gets forced to dirty + SD set.
            -- MPP=2 (HS mode) is invalid and gets cleared.
            -- The result is MSTATUS_R_MASK with MPP cleared (HS) and SD+FS forced.
            -- Since we wrote all-ones, FS=0b11 (dirty) which is valid, MPP=0b11 (M)
            -- which is valid, so the result should be just R_MASK with SD set.
            expect.equal(val, MSTATUS_R_MASK)
        end)

        it("should clear mstatus MPP when set to reserved HS mode", function()
            -- MPP = 2 (bits [12:11] = 0b10) is the reserved HS mode
            local mpp_hs = 2 << 11
            local val = read_csr_via_interpret("mstatus", mpp_hs)
            -- MPP should be cleared to 0 (U-mode)
            expect.equal(val & (3 << 11), 0)
        end)
    end)

    -- Bug 3: fetch cache not properly invalidated (commit 52f1a5db)
    --
    -- The fetch cache used TLB_INVALID_PAGE (0xFFFFFFFFFFFFFFFF) as its miss
    -- sentinel. The XOR-based hit test could produce false hits for certain PC
    -- values. Also, the cache wasn't invalidated after fetch exceptions or
    -- after raise_interrupt_if_any (which can change privilege level and PC).
    --
    -- Fix: use ~pc as the sentinel (guaranteed miss) and invalidate after
    -- fetch exceptions and raise_interrupt_if_any.
    --
    -- We test the interrupt-driven invalidation: set up S-mode with a pending
    -- M-mode interrupt. When the interrupt fires, PC jumps to mtvec and
    -- privilege changes to M-mode. The fetch cache must be invalidated or it
    -- would fetch from the old (stale) code address.
    it("should invalidate fetch cache on interrupt-driven privilege change", function()
        local machine <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        machine:write_memory(RAM_START, string.rep(NOP, 16))
        local mtvec_addr = RAM_START + 0x100
        machine:write_memory(mtvec_addr, string.rep(NOP, 16))
        machine:write_reg("mtvec", mtvec_addr)
        machine:write_reg("iprv", 1) -- S-mode
        machine:write_reg("pc", RAM_START)
        machine:write_reg("mie", MIP_MTIP)
        machine:write_reg("mstatus", MSTATUS_MIE | MSTATUS_FS_DIRTY | MSTATUS_MPP_S)
        machine:write_reg("mip", MIP_MTIP)
        machine:write_reg("mideleg", 0)
        machine:run(1)
        expect.equal(machine:read_reg("iprv"), 3) -- should be in M-mode
    end)

    -- Bug 4: assert_no_brk too strict with multiple pending interrupts (commit 3eefda30)
    --
    -- The debug assertion required ALL pending interrupts to be zero after
    -- executing an instruction. But in S/U-mode, non-delegated M-mode
    -- interrupts can legitimately remain pending — they are serviced by the
    -- outer interpreter loop, not by the current instruction.
    --
    -- Fix: in S/U-mode, only assert that delegated interrupts (bits in mideleg)
    -- are zero; non-delegated interrupts may remain pending.
    --
    -- Note: this test only catches the bug in debug builds (NDEBUG not defined).
    it("should not assert with non-delegated interrupts pending in S-mode", function()
        local machine <close> = cartesi.machine({ ram = { length = 1 << 20 } })
        machine:write_memory(RAM_START, string.rep(NOP, 64))
        machine:write_reg("mtvec", RAM_START)
        machine:write_reg("stvec", RAM_START + 0x100)
        machine:write_memory(RAM_START + 0x100, string.rep(NOP, 16))
        machine:write_reg("iprv", 1) -- S-mode
        machine:write_reg("pc", RAM_START)
        -- SSIP: delegated to S-mode, enabled, pending
        -- MEIP: NOT delegated, enabled, pending
        machine:write_reg("mideleg", MIP_SSIP)
        machine:write_reg("mie", MIP_SSIP | MIP_MEIP)
        machine:write_reg("mip", MIP_SSIP | MIP_MEIP)
        machine:write_reg("mstatus", MSTATUS_SIE | MSTATUS_MIE | MSTATUS_FS_DIRTY | MSTATUS_MPP_S)
        -- Before the fix, the debug assertion would fire because MEIP remains
        -- pending after the SSIP interrupt is handled.
        local br = machine:run(4)
        expect.equal(br, cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    end)
end)
