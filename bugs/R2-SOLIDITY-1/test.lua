-- R2-SOLIDITY-1: TLB-write ECALL indices are unchecked in both uarch verifiers.
--
-- What it checks (correct behavior required by THREAT_MODEL.md R2, R3, R10, A6):
--   On a fabricated before-state where the uarch is at an ECALL with a7 = UARCH_ECALL_FN_WRITE_TLB (4) and
--   an out-of-range set index (a0) or slot index (a1), native interpretation (run_uarch) and the log producer
--   (log_step_uarch) have no successor: machine::write_unverified_tlb throws "TLB set/slot index out of bounds".
--   A verifier must then accept no log at all (or, if the native semantics were changed to define a successor,
--   only that successor). The test hand-builds a uarch step log that writes the 32-byte TLB slot image
--   [vaddr_page, vp_offset, pma_index, 0] at the leaf shadow_tlb_get_abs_addr(set, slot) and asks
--   cartesi.machine:verify_step_uarch (the C++ replay, used by the referee model) to verify it.
--     case A: set = 0,     slot = 0x3FFFF80 -> leaf 0x1000 + slot*32 = 0x80000000 (guest RAM)
--     case B: set = 2^51,  slot = 0x3FFFF80 -> 0x1000 + 2^51*0x2000 + slot*32 wraps mod 2^64 to 0x80000000
--   On feature/prt-audit the C++ verifier accepts both logs (an arbitrary RAM write) although native throws.
--
-- Solidity (machine-solidity-step, NOT executable here: no EVM). Differential trace of
-- EmulatorCompat.writeTlbECALL (pragma ^0.8.30, checked uint64 arithmetic, no range check):
--     paddress = AR_SHADOW_TLB_START(0x1000) + setIndex*TLB_SET_LENGTH(8192) + slotIndex*TLB_SLOT_LENGTH(32)
--   case A: paddress = 0x80000000, strideFromLeafAddress passes (aligned), write4Words writes
--           keccak(LE(w0)||LE(w1)||LE(w2)||LE(0)) = the C++ get_write_tlb_slot_hash -> accepts the same after-hash.
--   case B: 2^51 * 8192 = 2^64 overflows uint64 -> Panic(0x11) revert, while the C++ replay accepts the wrapped
--           address. The test models this arithmetic in Lua and checks the Solidity source has no index check.
--
-- Severity per section 8: High (verifier accepting a successor / paths diverging only at unreachable
-- before-states: indices are produced by the pristine uarch program, set in {0,1,2}, slot = (vaddr>>12)&255).
local cartesi = require("cartesi")

local K = 0x3FFFF80
local UARCH_RAM = cartesi.UARCH_RAM_START_ADDRESS
local VPAGE, VPOFF, PMAI = 0x1111000, 0x2222, 0x3333

local function make_machine(set)
    local m = cartesi.machine({ ram = { length = 0x10000 }, uarch = {} })
    m:write_memory(UARCH_RAM, string.pack("<I4", 0x73)) -- ecall
    m:write_reg("uarch_pc", UARCH_RAM)
    m:write_reg("uarch_x17", 4) -- a7 = UARCH_ECALL_FN_WRITE_TLB
    m:write_reg("uarch_x10", set) -- a0 = set index
    m:write_reg("uarch_x11", K) -- a1 = slot index
    m:write_reg("uarch_x12", VPAGE)
    m:write_reg("uarch_x13", VPOFF)
    m:write_reg("uarch_x14", PMAI)
    return m
end

-- Solidity model: checked uint64 arithmetic of EmulatorCompat.writeTlbECALL. Returns address or nil (Panic 0x11).
local function sol_paddress(set, slot)
    -- x * 2^k overflows uint64 iff x >> (64 - k) ~= 0; x + y overflows iff the unsigned sum is below x
    if (set >> (64 - 13)) ~= 0 or (slot >> (64 - 5)) ~= 0 then return nil end
    local s1 = 0x1000 + (set << 13)
    if math.ult(s1, 0x1000) then return nil end
    local s2 = s1 + (slot << 5)
    if math.ult(s2, s1) then return nil end
    if s2 & 31 ~= 0 then return nil end -- strideFromPhysicalAddress alignment assert
    return s2
end

local function cpp_paddress(set, slot)
    return (0x1000 + set * 0x2000 + slot * 32) -- wraps mod 2^64 like shadow_tlb_get_abs_addr
end

-- Builds the 14-access log that a "write TLB slot at an arbitrary leaf" step would produce.
local function build_log(set)
    local m = make_machine(set)
    local target = cpp_paddress(set, K)
    assert(target == 0x80000000, "harness: target address")
    local before = m:get_root_hash()
    local accesses = {}
    local function leafof(addr) return addr & ~31 end
    local function rd(addr)
        local p = m:get_proof(leafof(addr), 5)
        local data = m:read_memory(leafof(addr), 32)
        accesses[#accesses + 1] = { type = "read", address = addr, log2_size = 3, read = data,
            read_hash = p.target_hash, sibling_hashes = p.sibling_hashes }
    end
    local function wr_word(addr, writer)
        local p = m:get_proof(leafof(addr), 5)
        local data = m:read_memory(leafof(addr), 32)
        writer()
        local after = m:read_memory(leafof(addr), 32)
        accesses[#accesses + 1] = { type = "write", address = addr, log2_size = 3, read = data,
            read_hash = p.target_hash, written = after, written_hash = cartesi.keccak256(after),
            sibling_hashes = p.sibling_hashes }
    end
    local A = function(n) return m:get_reg_address(n) end
    rd(A("uarch_cycle")); rd(A("uarch_halt")); rd(A("uarch_pc")); rd(UARCH_RAM)
    for _, r in ipairs({ 17, 10, 11, 12, 13, 14 }) do rd(A("uarch_x" .. r)) end
    local slot = string.pack("<I8I8I8I8", VPAGE, VPOFF, PMAI, 0)
    local p = m:get_proof(target, 5)
    m:write_memory(target, slot)
    accesses[#accesses + 1] = { type = "write", address = target, log2_size = 5, read_hash = p.target_hash,
        written_hash = cartesi.keccak256(slot), sibling_hashes = p.sibling_hashes }
    wr_word(A("uarch_pc"), function() m:write_reg("uarch_pc", UARCH_RAM + 4) end)
    wr_word(A("uarch_cycle"), function() m:write_reg("uarch_cycle", 1) end)
    rd(A("uarch_halt"))
    local after = m:get_root_hash()
    local ram_changed = m:read_memory(0x80000000, 32) == slot
    return before, { accesses = accesses, log_type = { has_annotations = false, has_large_data = false } }, after,
        ram_changed
end

local failures = {}
local function fail(msg) failures[#failures + 1] = msg end

local cases = { { name = "A (set=0, slot=0x3FFFF80)", set = 0 }, { name = "B (set=2^51, slot=0x3FFFF80)", set = 1 << 51 } }
local cpp_accepts = {}
for i, c in ipairs(cases) do
    local before, log, after, ram_changed = build_log(c.set)
    assert(ram_changed, "harness: crafted after-state does not change guest RAM")
    -- native semantics on the identical before-state
    local m2 = make_machine(c.set)
    assert(m2:get_root_hash() == before, "harness: before-state mismatch")
    local nok, nerr = pcall(m2.run_uarch, m2, 1)
    local native_after = nok and m2:get_root_hash() or nil
    local m3 = make_machine(c.set)
    local lok, lerr = pcall(m3.log_step_uarch, m3)
    io.write(string.format("case %s: native run_uarch: %s; log_step_uarch: %s\n", c.name,
        nok and "ok" or tostring(nerr), lok and "ok" or tostring(lerr)))
    local vok, vres = pcall(function() return cartesi.machine:verify_step_uarch(before, log) end)
    local accepted = vok and vres == after
    cpp_accepts[i] = accepted
    io.write(string.format("case %s: C++ verify_step_uarch on crafted RAM-write log: %s\n", c.name,
        accepted and "ACCEPTED" or ("rejected: " .. tostring(vres))))
    if accepted and native_after ~= after then
        fail(string.format("case %s: C++ uarch verifier accepts a TLB-format write to guest RAM 0x80000000 that native "
            .. "interpretation does not produce (%s)", c.name, nok and "different successor" or tostring(nerr)))
    end
end

-- Solidity part (modeled, not executed on-chain).
local sol_dir = os.getenv("MACHINE_SOLIDITY_STEP_DIR") or "/home/user/ext/machine-solidity-step"
local f = assert(io.open(sol_dir .. "/src/EmulatorCompat.sol", "r"), "harness: cannot open EmulatorCompat.sol")
local src = f:read("a")
f:close()
local body = src:match("function writeTlbECALL%(.-%)%s*internal%s*pure%s*(%b{})")
assert(body, "harness: writeTlbECALL not found")
local has_check = body:find("setIndex%s*[<>]=?") or body:find("slotIndex%s*[<>]=?") or body:find("TLB_SET_SIZE")
    or body:find("TLB_LAST")
if not has_check then
    local pa = sol_paddress(0, K)
    local pb = sol_paddress(1 << 51, K)
    io.write(string.format("Solidity writeTlbECALL (modeled): case A paddress=%s -> accepts same arbitrary-leaf write; "
        .. "case B %s\n", pa and string.format("0x%x", pa) or "revert",
        pb and string.format("paddress=0x%x", pb) or "Panic(0x11) overflow revert"))
    if pa == 0x80000000 then
        fail("Solidity EmulatorCompat.writeTlbECALL has no index range check: (modeled) accepts the same TLB-format "
            .. "write to guest RAM 0x80000000")
    end
    if (pb == nil) ~= (not cpp_accepts[2]) then
        fail("C++ replay and Solidity writeTlbECALL disagree on set=2^51: C++ "
            .. (cpp_accepts[2] and "accepts the wrapped address" or "rejects") .. ", Solidity "
            .. (pb and "accepts" or "reverts (Panic 0x11)"))
    end
end

if #failures > 0 then
    print("FAIL: uarch verifiers accept out-of-range WRITE_TLB ECALL indices where native throws (R2/R3/R10, High):")
    for _, m in ipairs(failures) do print("  - " .. m) end
    os.exit(1)
end
print("OK: verifiers reject out-of-range WRITE_TLB ECALL indices, consistent with native interpretation")
os.exit(0)
