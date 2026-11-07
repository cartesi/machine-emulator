#!/usr/bin/env lua5.4
-- R4-VARSPEC-2: taking an interrupt decrements the architectural instruction count (minstret/instret).
--
-- The emulator derives minstret = mcycle - icycleinstret, and the manual defines icycleinstret as the difference
-- between mcycle and the architectural instruction count. raise_exception (src/interpret.cpp) increments
-- icycleinstret for every trap cause. That is right for synchronous exceptions (the faulting instruction consumes an
-- mcycle without retiring), but interrupts are raised by raise_interrupt_if_any in the outer interpreter loop,
-- before the next fetch, without consuming an mcycle. Each interrupt taken therefore subtracts one from minstret,
-- although Zicntr/privileged spec define minstret as the number of instructions retired (R7, Medium per section 8).
--
-- The bare-metal M-mode guest (instret.S, built at test time) retires exactly three instructions between two
-- minstret reads: csrr minstret, csrr mcycle, sw. Case 0 stores to RAM; case 1 stores to CLINT msip, which raises a
-- machine software interrupt taken before the next instruction, landing on the same code (mtvec == fall-through).
-- The test asserts dinstret == 3 in both cases (and dmcycle == 3, mcause as expected), and that the uarch replay
-- (run_uarch + reset_uarch per mcycle) reaches the same root hash as native interpretation.
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local PARAM = 0x80001000
local RESULT = 0x80001010
local SCRATCH = 0x80002000
local CLINT_MSIP = 0x02000000
local MCAUSE_MSI = 0x8000000000000003

local outdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
assert(os.execute("bash ./build.sh " .. outdir), "harness error: failed to build guest instret.bin")
local bin = outdir .. "/instret.bin"

local function make_machine(target)
    local m = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
    })
    m:write_memory(PARAM, string.pack("<I8", target))
    return m
end

local function results(m, what)
    assert(m:read_reg("iflags_H") ~= 0, "harness error: guest did not halt (" .. what .. ")")
    assert(m:read_reg("htif_tohost_data") >> 1 == 0, "harness error: unexpected exit code (" .. what .. ")")
    return string.unpack("<I8I8I8", m:read_memory(RESULT, 24))
end

local function run_case(target)
    local native <close> = make_machine(target)
    native:run(10000)
    local dinstret, dmcycle, mcause = results(native, "native")
    -- Replay through the uarch, one mcycle at a time, and compare with native.
    local uarch <close> = make_machine(target)
    local steps = 0
    while uarch:read_reg("iflags_H") == 0 do
        uarch:run_uarch(cartesi.UARCH_CYCLE_MAX)
        assert(uarch:read_reg("uarch_halt") ~= 0, "harness error: uarch did not halt within the mcycle")
        uarch:reset_uarch()
        steps = steps + 1
        assert(steps < 1000, "harness error: uarch replay did not halt")
    end
    local u_dinstret, u_dmcycle, u_mcause = results(uarch, "uarch")
    assert(uarch:read_reg("mcycle") == native:read_reg("mcycle"), "harness error: mcycle differs native/uarch")
    local same = uarch:get_root_hash() == native:get_root_hash()
        and u_dinstret == dinstret and u_dmcycle == dmcycle and u_mcause == mcause
    return dinstret, dmcycle, mcause, same
end

local failures = {}

local r0 = table.pack(run_case(SCRATCH))
print(string.format("case 0 (sw to RAM):       dinstret=%d dmcycle=%d mcause=0x%x uarch==native:%s", r0[1], r0[2],
    r0[3], tostring(r0[4])))
local r1 = table.pack(run_case(CLINT_MSIP))
print(string.format("case 1 (sw to CLINT msip): dinstret=%d dmcycle=%d mcause=0x%x uarch==native:%s", r1[1], r1[2],
    r1[3], tostring(r1[4])))

os.execute("rm -rf " .. outdir)

-- Harness sanity: the scenario must be the one described.
assert(r0[3] == 0, "harness error: case 0 unexpectedly trapped")
assert(r1[3] == MCAUSE_MSI, "harness error: case 1 did not take a machine software interrupt")
assert(r0[2] == 3 and r1[2] == 3, "harness error: unexpected mcycle delta")
if not (r0[4] and r1[4]) then
    print("FAIL R4-VARSPEC-2: uarch and native disagree (unexpected; this would be Critical)")
    os.exit(2)
end

if r0[1] ~= 3 then
    failures[#failures + 1] = string.format("minstret advanced by %d (expected 3) over three retired instructions", r0[1])
end
if r1[1] ~= r0[1] then
    failures[#failures + 1] = string.format(
        "taking a machine software interrupt changed the minstret delta from %d to %d over the same three retired "
            .. "instructions (mcycle advanced by %d in both): raise_exception bumps icycleinstret for interrupts, "
            .. "which consume no mcycle, so each interrupt decrements instret",
        r0[1], r1[1], r1[2])
end

if #failures > 0 then
    for _, f in ipairs(failures) do
        print("FAIL R4-VARSPEC-2: " .. f)
    end
    os.exit(1)
end
print("OK: interrupts do not change the retired-instruction count")
os.exit(0)
