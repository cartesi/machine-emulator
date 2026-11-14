-- Bare-metal guest for bugs/R1-O2-3, assembled here (no toolchain needed). Returns the raw image (loaded at
-- 0x80000000, entry at its first byte) and the addresses the test needs.
--
-- M-mode: writes one Sv39 leaf PTE (a 1 GiB identity gigapage over 0x80000000, V|R|W|X, A=0, D=0) into the
-- root page table at 0x80010000, sets satp, sfence.vma (which evicts the page-table page from the write TLB,
-- marking it dirty), and mrets to S-mode.
-- S-mode: spins SPIN iterations (instruction fetches only: the walk sets the PTE's A bit), then stores to
-- NPAGES distinct 4 KiB pages starting at 0x80400000 (the first store makes the walk set the PTE's D bit with
-- a physical write to the page-table page that does not go through the write TLB), then loops forever.
local M = {}

M.RAM_START = 0x80000000
M.PT = 0x80010000 -- root page table (Sv39), zero-filled RAM
M.PTE_ADDR = M.PT + 2 * 8 -- VPN[2] = 2 covers 0x80000000..0xbfffffff
M.PTE = (0x80000 << 10) | 0xf -- PPN 0x80000, V|R|W|X, A=0 D=0
M.PTE_A, M.PTE_D = 0x40, 0x80
M.DBASE = 0x80400000
M.NPAGES = 8000
M.SPIN = 0x100000

local X = { zero = 0, t0 = 5, t1 = 6, t2 = 7, s0 = 8, t3 = 28 }

local function I(imm, rs1, f3, rd, op)
    return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
end
local function S(imm, rs2, rs1, f3, op)
    return (((imm >> 5) & 0x7f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | ((imm & 0x1f) << 7) | op
end
local function R(f7, rs2, rs1, f3, rd, op)
    return (f7 << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op
end
local function B(imm, rs2, rs1, f3)
    return (((imm >> 12) & 1) << 31) | (((imm >> 5) & 0x3f) << 25) | (rs2 << 20) | (rs1 << 15) | (f3 << 12)
        | (((imm >> 1) & 0xf) << 8) | (((imm >> 11) & 1) << 7) | 0x63
end
local function J(imm, rd)
    return (((imm >> 20) & 1) << 31) | (((imm >> 1) & 0x3ff) << 21) | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12) | (rd << 7) | 0x6f
end

local CSR = { satp = 0x180, mstatus = 0x300, mepc = 0x341 }
local DATA = 0x100 -- data words start here (offsets from s0 = 0x80000000)
local data_names = { "PTE", "PTOFF", "SATP", "MPPMASK", "MPPS", "SENTRY", "SPIN", "DBASE", "NPAGES", "PAGESZ" }
local D = {}
for i, n in ipairs(data_names) do D[n] = DATA + 8 * (i - 1) end

function M.image()
    local code = {}
    local labels = {}
    local fix = {}
    local function emit(w) code[#code + 1] = w end
    local function label(n) labels[n] = #code * 4 end
    local function branch_to(f, n) fix[#code + 1] = { f, n }; emit(0) end
    local ld = function(rd, off) emit(I(off, X.s0, 3, rd, 0x03)) end
    local add = function(rd, a, b) emit(R(0, b, a, 0, rd, 0x33)) end
    local addi = function(rd, a, imm) emit(I(imm, a, 0, rd, 0x13)) end
    local sd = function(rs2, off, rs1) emit(S(off, rs2, rs1, 3, 0x23)) end
    local csrw = function(csr, rs) emit(I(csr, rs, 1, 0, 0x73)) end
    local csrs = function(csr, rs) emit(I(csr, rs, 2, 0, 0x73)) end
    local csrc = function(csr, rs) emit(I(csr, rs, 3, 0, 0x73)) end

    -- M-mode
    emit((X.s0 << 7) | 0x17) -- auipc s0, 0  -> s0 = 0x80000000
    ld(X.t1, D.PTE)
    ld(X.t0, D.PTOFF)
    add(X.t0, X.s0, X.t0) -- t0 = PT
    sd(X.t1, 16, X.t0) -- PT[2] = PTE
    ld(X.t1, D.SATP)
    csrw(CSR.satp, X.t1)
    emit(0x12000073) -- sfence.vma
    ld(X.t1, D.MPPMASK)
    csrc(CSR.mstatus, X.t1)
    ld(X.t1, D.MPPS)
    csrs(CSR.mstatus, X.t1) -- MPP = S
    ld(X.t1, D.SENTRY)
    add(X.t1, X.s0, X.t1)
    csrw(CSR.mepc, X.t1)
    emit(0x30200073) -- mret
    -- S-mode
    label("sentry")
    ld(X.t0, D.SPIN)
    label("spin")
    addi(X.t0, X.t0, -1)
    branch_to(function(off) return B(off, X.zero, X.t0, 1) end, "spin") -- bne t0, zero
    ld(X.t1, D.DBASE)
    ld(X.t2, D.NPAGES)
    ld(X.t3, D.PAGESZ)
    label("dirty")
    sd(X.t2, 0, X.t1)
    add(X.t1, X.t1, X.t3)
    addi(X.t2, X.t2, -1)
    branch_to(function(off) return B(off, X.zero, X.t2, 1) end, "dirty")
    label("forever")
    branch_to(function(off) return J(off, 0) end, "forever")
    assert(#code * 4 <= DATA)

    for idx, f in pairs(fix) do
        code[idx] = f[1](labels[f[2]] - (idx - 1) * 4)
    end
    local values = {
        PTE = M.PTE,
        PTOFF = M.PT - M.RAM_START,
        SATP = (8 << 60) | (M.PT >> 12),
        MPPMASK = 0x1800,
        MPPS = 0x800,
        SENTRY = labels.sentry,
        SPIN = M.SPIN,
        DBASE = M.DBASE,
        NPAGES = M.NPAGES,
        PAGESZ = 4096,
    }
    local parts = {}
    for i = 1, #code do parts[i] = string.pack("<I4", code[i]) end
    local img = table.concat(parts)
    img = img .. string.rep("\0", DATA - #img)
    for _, n in ipairs(data_names) do img = img .. string.pack("<i8", values[n]) end
    return img
end

return M
