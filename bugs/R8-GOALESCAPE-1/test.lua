-- R8-GOALESCAPE-1: AMOs translate their address twice (a read walk, then a write walk).
--
-- src/interpret.cpp execute_AMO performs an AMO as
--     read_virtual_memory<T, STATE_ACCESS, true>(vaddr)   -- read-TLB set, read-type page walk
--   followed by
--     write_virtual_memory<T>(vaddr, result)              -- write-TLB set, store-type page walk
-- Each half consults its own TLB set and, on a miss, runs its own translate_virtual_address walk
-- (src/translate-virtual-address.hpp), each updating the leaf PTE's A/D after its own permission check.
-- The RISC-V A extension defines an AMO as ONE atomic access that loads and stores back to the SAME
-- address, translated once as a store/AMO access. Two consequences, both asserted here:
--
--   (A) Split translation (atomicity / address translation).
--       A stale read-TLB entry V->P1 and a fresh write-TLB entry V->P2 (PTE changed without sfence.vma,
--       the write TLB refilled by an earlier store) make one `amoadd.d rd, 1, (V)` LOAD from P1 and
--       STORE to P2. The AMO is not atomic on any single physical location: rd is taken from P1 while
--       P2 is overwritten with rd+1 without ever being read, and P1 is left unchanged.
--       A spec-correct AMO uses ONE translation, so some location L has rd == pre(L) and
--       post(L) == rd+1 and the other location is unchanged.
--
--   (C) Lost dirty bit (memory permissions / A-D semantics).
--       An AMO on the PTE word that maps its own page (A=0, D=0, W=1): the read walk sets only A, the
--       AMO reads the half-updated PTE, the write walk sets A and D, and then the AMO's store writes the
--       half-updated value back, clearing D although the page was just written. A single store/AMO
--       translation sets A and D before the access, so after the AMO the PTE's D bit must be set.
--
-- THREAT_MODEL.md R7 (Faithful architecture): "The emulator implements the RISC-V specification ...
-- departing only where the manual documents a deviation. ... In these areas, any deviation lets an input
-- subvert a correct guest, even a deviation that is consistent across all paths." Listed areas include
-- "Address translation and memory permissions." and "Atomics and fences." The manual documents no
-- deviation here, so both (A) and (C) are R7 violations. The deviation is in the state transition
-- function itself: native interpretation and the uarch program agree (printed below).
--
-- Exit: 0 if both requirements hold (fixed), 1 if either is violated (bug present), 2 on setup error.

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    -- Build the bare-metal guest (amo.c, in this directory) into a fresh temp dir.
    local tmp = os.tmpname()
    os.remove(tmp)
    if not os.execute("mkdir -p '" .. tmp .. "'") then
        harness.setup_error("cannot create temp dir " .. tmp)
    end
    local bin = tmp .. "/amo.bin"
    local build = assert(os.getenv("HARNESS"), "HARNESS unset (source bugs/env.sh)") .. "/baremetal/build.sh"
    local ok = os.execute("'" .. build .. "' -o '" .. bin .. "' amo.c > '" .. tmp .. "/build.log' 2>&1")
    if not ok then
        local f = io.open(tmp .. "/build.log", "rb")
        local log = f and f:read("a") or "(no log)"
        if f then f:close() end
        harness.setup_error("bare-metal build of amo.c failed:\n" .. log)
    end

    local cfg = { ram = { length = 64 << 20, backing_store = { data_filename = bin } } }
    local m = harness.machine(cfg)

    -- Run to halt (the guest records results and halts via HTIF; ~4.7k mcycles).
    m:run(1000000)
    if m:read_reg("iflags_H") == 0 then
        harness.setup_error("guest did not halt within the mcycle budget (mcycle=" ..
            tostring(m:read_reg("mcycle")) .. ")")
    end

    local R = 0x80920000 -- fixed physical RESULT array in RAM, written by the guest
    local old = m:read_word(R + 0 * 8)  -- amoadd.d return value (value it loaded)
    local p1 = m:read_word(R + 1 * 8)   -- P1 after the AMO (pre-value 100)
    local p2 = m:read_word(R + 2 * 8)   -- P2 after the AMO (pre-value 200)
    local pte_c = m:read_word(R + 3 * 8) -- self-mapping PTE after the AMO on itself
    local ctl_old = m:read_word(R + 7 * 8) -- control AMO (consistent translation): value loaded
    local ctl_pc = m:read_word(R + 8 * 8)  -- control page after the AMO (pre-value 300)

    -- Sanity on the setup (not the assertion): the split-TLB precondition must have held, i.e. the
    -- earlier store to V+8 refilled the write TLB to P2 (P2+8 == 0x77). If not, the split scenario was
    -- not produced -> setup error, not a verdict.
    local p2_8 = m:read_word(0x80911008)
    if p2_8 ~= 0x77 then
        harness.setup_error("split-TLB precondition not established (P2+8=" ..
            string.format("0x%x", p2_8) .. ", expected 0x77)")
    end

    -- Control: a normal AMO with a consistent translation (never remapped) must be atomic on its single
    -- page. This emulator handles it correctly (old==300, PC==301), which both confirms the setup is sane
    -- and shows that the SAME atomicity predicate used below returns true for correct behavior -- i.e. a
    -- spec-conformant AMO makes assertion (A) pass, so the fixed emulator exits 0. If the control itself
    -- is not atomic, the scenario is broken -> setup error, not a verdict.
    if not (ctl_old == 300 and ctl_pc == 301) then
        harness.setup_error(string.format(
            "control AMO (consistent translation) is not atomic: old=%d PC=%d (expected 300, 301)",
            ctl_old, ctl_pc))
    end

    -- uarch cross-check (informational): confirms the deviation is in the state transition function.
    local u = harness.machine(cfg)
    while u:read_reg("iflags_H") == 0 and u:read_reg("mcycle") < 1000000 do
        u:run_uarch(cartesi.UARCH_CYCLE_MAX or ((1 << 20) - 1))
        u:reset_uarch()
    end
    io.stderr:write(string.format("native/uarch final root hashes equal: %s\n",
        tostring(u:get_root_hash() == m:get_root_hash())))
    io.stderr:write(string.format("scenario A: amo old=%d  P1=%d (pre 100)  P2=%d (pre 200)\n", old, p1, p2))
    io.stderr:write(string.format("scenario C: self-mapping PTE after AMO = 0x%x  (D bit 0x80 = %d)\n",
        pte_c, pte_c & 0x80))
    io.stderr:write(string.format("control  : consistent-translation AMO old=%d  PC=%d (pre 300) -> atomic\n",
        ctl_old, ctl_pc))

    -- (A) The AMO must be atomic on a single physical location: one correct translation.
    --     pre(P1)=100, pre(P2)=200. Either the AMO used P1 throughout (old=100, P1=101, P2=200)
    --     or P2 throughout (old=200, P2=201, P1=100). The bug produces old=100, P1=100, P2=101: neither.
    local atomic_on_P1 = (old == 100 and p1 == 101 and p2 == 200)
    local atomic_on_P2 = (old == 200 and p2 == 201 and p1 == 100)
    local atomic_ok = atomic_on_P1 or atomic_on_P2

    -- (C) After the AMO stores to its own page, the dirty bit must be set.
    local dirty_ok = (pte_c & 0x80) ~= 0

    local a = harness.expect(atomic_ok,
        "R7 (Atomics and fences; Address translation): an AMO is one atomic access on a single address " ..
        "-- it must load and store the same physical location")
    local c = harness.expect(dirty_ok,
        "R7 (Address translation and memory permissions): an AMO that stores to the page its own PTE maps " ..
        "must leave that PTE's dirty bit set")

    os.execute("rm -rf '" .. tmp .. "'")
    return a and c
end)
