#!/usr/bin/env lua5.4
-- R1-ARCH-1: CLINT mtimecmp-to-cycle conversion overflows (src/rtc.hpp rtc_time_to_cycle, used by
-- src/interpret.cpp set_rtc_interrupt and execute_WFI).
--
-- RISC-V privileged spec (and R7, "traps and interrupts"): mip.MTIP is pending iff mtime >= mtimecmp.
-- In the Cartesi Machine mtime = mcycle / 8192, so mtime < 2^51 always.
-- The emulator instead tests mtimecmp * 8192 (computed modulo 2^64) <= mcycle, and excludes the product 0.
--
-- This test boots a bare-metal M-mode guest (timer.S, built at test time) that writes a deadline to mtimecmp,
-- enables MTIE/MIE, busy-loops past three RTC ticks, and halts with exit 0. Its trap handler halts with exit 1
-- and records mcause/mcycle. It checks:
--   case A: mtimecmp = 2^51 + 1 (mtime can never reach it)  -> no interrupt may be taken (expect exit 0)
--   case B: mtimecmp = 0        (mtime >= 0 always holds)   -> a machine timer interrupt must be taken (exit 1)
-- It also replays case A through the uarch (run_uarch + reset_uarch per mcycle) across the first RTC tick and
-- checks that the uarch agrees with the native interpreter, i.e. the deviation is consistent across paths (Medium).
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local PARAM = 0x80001000
local RESULT = 0x80001008
local MCAUSE_MTI = 0x8000000000000007

local outdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
assert(os.execute("bash ./build.sh " .. outdir), "harness error: failed to build guest timer.bin")
local bin = outdir .. "/timer.bin"

local function make_machine(mtimecmp)
    local m = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
    })
    m:write_memory(PARAM, string.pack("<I8", mtimecmp))
    return m
end

local function run_case(mtimecmp)
    local m <close> = make_machine(mtimecmp)
    m:run(1000000)
    assert(m:read_reg("iflags_H") ~= 0, "harness error: guest did not halt")
    local exit = m:read_reg("htif_tohost_data") >> 1
    local mcause, mcycle = string.unpack("<I8I8", m:read_memory(RESULT, 16))
    return exit, mcause, mcycle
end

local failures = {}

-- Case A: far-future deadline that wraps to 8192 when multiplied by 8192.
local a_cmp = (1 << 51) + 1
local exit, mcause, mcycle = run_case(a_cmp)
print(string.format("case A: mtimecmp=0x%x exit=%d mcause=0x%x mcycle=%d", a_cmp, exit, mcause, mcycle))
if exit ~= 0 then
    failures[#failures + 1] = string.format(
        "spurious machine timer interrupt (mcause=0x%x) at mcycle %d (mtime=%d) with mtimecmp=2^51+1: "
            .. "mtimecmp*8192 wraps to 8192, but mtime < 2^51 can never reach mtimecmp",
        mcause,
        mcycle,
        mcycle // 8192
    )
end
if exit == 1 then assert(mcause == MCAUSE_MTI, "harness error: unexpected trap cause") end

-- Case B: mtimecmp == 0, timer must be pending immediately (mtime >= 0).
exit, mcause, mcycle = run_case(0)
print(string.format("case B: mtimecmp=0x0 exit=%d mcause=0x%x mcycle=%d", exit, mcause, mcycle))
if exit ~= 1 then
    failures[#failures + 1] = "no machine timer interrupt with mtimecmp=0 although mtime >= mtimecmp always holds "
        .. "(set_rtc_interrupt excludes timecmp_cycle == 0)"
elseif mcause ~= MCAUSE_MTI then
    error("harness error: unexpected trap cause in case B")
end

-- Consistency across paths for case A: run native and uarch side by side across the first tick (mcycle 8192).
do
    local native <close> = make_machine(a_cmp)
    local uarch <close> = make_machine(a_cmp)
    local start = 8190
    native:run(start)
    uarch:run(start)
    assert(native:get_root_hash() == uarch:get_root_hash(), "harness error: hashes differ before replay")
    for target = start + 1, start + 10 do
        native:run(target)
        uarch:run_uarch(cartesi.UARCH_CYCLE_MAX)
        assert(uarch:read_reg("uarch_halt") ~= 0, "harness error: uarch did not halt within the mcycle")
        uarch:reset_uarch()
        assert(uarch:read_reg("mcycle") == target, "harness error: uarch mcycle mismatch")
        if native:get_root_hash() ~= uarch:get_root_hash() then
            error("uarch and native diverge at mcycle " .. target .. " (unexpected: this would be Critical)")
        end
    end
    local mip = uarch:read_reg("mip")
    print(string.format("uarch replay: agrees with native through mcycle %d (MTIP raised there too: mip=0x%x, mcause=0x%x)", start + 10, mip,
        uarch:read_reg("mcause")))
end

os.execute("rm -rf " .. outdir)

if #failures > 0 then
    for _, f in ipairs(failures) do
        print("FAIL R1-ARCH-1: " .. f)
    end
    os.exit(1)
end
print("OK: mtimecmp semantics follow mtime >= mtimecmp")
os.exit(0)
