#!/usr/bin/env lua5.4
-- R4-VARSPEC-1: the Sv39 page walk follows non-leaf PTEs that have the reserved A, D or U bits set, instead of
-- raising a page fault (src/translate-virtual-address.hpp: the reserved-bit check covers bits 63-54 only; the
-- xwr == 0 branch follows the pointer without checking A/D/U).
--
-- RISC-V privileged spec (Sv32/Sv39 "Virtual Address Translation Process", step 3, and the PTE format): for
-- non-leaf PTEs the D, A and U bits are reserved for future standard use, and if any bits or encodings that are
-- reserved for future standard use are set within a PTE, the walk stops with a page fault for the original access
-- type. The emulator already applies that rule to bits 60-54, PBMT and N; the manual documents no deviation.
-- Area: address translation and memory permissions (R7).
--
-- The bare-metal guest (pte.S, built at test time) sets up an Sv39 identity map whose root PTE is a non-leaf
-- pointer OR-ed with a host-chosen bit, then performs an instruction fetch (S-mode ecall), a load or a store
-- (M-mode with MPRV=1, MPP=S) through it. The M-mode trap handler halts with exit code = mcause.
-- Expected: control (no extra bit) -> 9 (fetch) / 11 (load, store); A, D or U -> 12 / 13 / 15 (page faults).
-- It also replays the A-bit fetch case through the uarch (run_uarch + reset_uarch per mcycle) to show the
-- deviation is consistent across native and uarch (hence Medium, not Critical). Exits nonzero while present.

local cartesi = require("cartesi")

local PARAM = 0x80004000
local BITS = { { "none", 0 }, { "A", 0x40 }, { "D", 0x80 }, { "U", 0x10 } }
local KINDS = { [0] = "fetch", [1] = "load", [2] = "store" }
local OK_CAUSE = { [0] = 9, [1] = 11, [2] = 11 }
local FAULT_CAUSE = { [0] = 12, [1] = 13, [2] = 15 }

local outdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
assert(os.execute("bash ./build.sh " .. outdir), "harness error: failed to build guest pte.bin")
local bin = outdir .. "/pte.bin"

local function make_machine(bits, kind)
    local m = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
    })
    m:write_memory(PARAM, string.pack("<I8I8", bits, kind))
    return m
end

local function run_case(bits, kind)
    local m <close> = make_machine(bits, kind)
    m:run(100000)
    assert(m:read_reg("iflags_H") ~= 0, "harness error: guest did not halt")
    local cause = m:read_reg("htif_tohost_data") >> 1
    assert(cause == m:read_reg("mcause"), "harness error: exit code does not match mcause")
    return cause
end

local failures = {}
for kind = 0, 2 do
    for _, b in ipairs(BITS) do
        local name, bits = b[1], b[2]
        local cause = run_case(bits, kind)
        local expected = bits == 0 and OK_CAUSE[kind] or FAULT_CAUSE[kind]
        print(string.format("%-5s non-leaf root PTE extra bits=%-4s (0x%02x): mcause=%d expected=%d", KINDS[kind],
            name, bits, cause, expected))
        if bits == 0 then
            assert(cause == expected, "harness error: control case did not complete the " .. KINDS[kind])
        elseif cause ~= expected then
            failures[#failures + 1] = string.format("%s through a non-leaf PTE with reserved bit %s set completed "
                .. "(mcause=%d) instead of raising a page fault (mcause=%d)", KINDS[kind], name, cause, expected)
        end
    end
end

-- Consistency across paths for the A-bit fetch case.
do
    local native <close> = make_machine(0x40, 0)
    local uarch <close> = make_machine(0x40, 0)
    while native:read_reg("iflags_H") == 0 do
        local target = native:read_reg("mcycle") + 1
        native:run(target)
        uarch:run_uarch(cartesi.UARCH_CYCLE_MAX)
        assert(uarch:read_reg("uarch_halt") ~= 0, "harness error: uarch did not halt within the mcycle")
        uarch:reset_uarch()
        assert(uarch:read_reg("mcycle") == target, "harness error: uarch mcycle mismatch")
        if native:get_root_hash() ~= uarch:get_root_hash() then
            error("uarch and native diverge at mcycle " .. target .. " (unexpected: this would be Critical)")
        end
    end
    print(string.format("uarch replay (A, fetch): agrees with native through halt at mcycle %d (mcause=%d)",
        native:read_reg("mcycle"), uarch:read_reg("mcause")))
end

os.execute("rm -rf " .. outdir)

if #failures > 0 then
    for _, f in ipairs(failures) do
        print("FAIL R4-VARSPEC-1: " .. f)
    end
    os.exit(1)
end
print("OK: non-leaf PTEs with reserved A/D/U bits raise page faults")
os.exit(0)
