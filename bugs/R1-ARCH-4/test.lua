#!/usr/bin/env lua5.4
-- R1-ARCH-4: writes to sip let S-mode set and clear sip.STIP and sip.SEIP (src/interpret.cpp write_csr_sip).
--
-- RISC-V privileged spec (sip/sie, "Supervisor Interrupt Registers"): in sip only SSIP is writable; STIP and SEIP
-- are read-only in sip, set and cleared by the execution environment (M-mode firmware via mip, or the platform).
-- The emulator uses mask = mideleg in write_csr_sip, so every delegated pending bit, including STIP and SEIP,
-- becomes writable from S-mode. The manual documents no deviation here. Area: traps and interrupts (R7).
--
-- This test boots a bare-metal guest (sipw.S, built at test time) that delegates SSI/STI/SEI in mideleg (as OpenSBI
-- does), keeps interrupts disabled, drops to S-mode and:
--   case 0: csrs sip,(STIP|SEIP)  -> spec: sip.STIP/SEIP stay 0                    (guest exit 0 = correct)
--   case 1: M sets mip.STIP|SEIP, then S does csrc sip,(STIP|SEIP) -> spec: they stay 1 (guest exit 0 = correct)
--   case 2: control, csrs sip,SSIP -> SSIP is set (writable per spec)               (guest exit 0 = correct)
-- It also replays case 0 through the uarch (run_uarch + reset_uarch per mcycle), and logs and verifies every
-- uarch step of the mcycle that executes the sip write, to show the deviation is consistent across native, uarch
-- and the step verifier (hence Medium, not Critical). Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local PARAM = 0x80001000
local STIP, SEIP, SSIP = 1 << 5, 1 << 9, 1 << 1

local outdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
assert(os.execute("bash ./build.sh " .. outdir), "harness error: failed to build guest sipw.bin")
local bin = outdir .. "/sipw.bin"

local function make_machine(case)
    local m = cartesi.machine({
        ram = { backing_store = { data_filename = bin }, length = 1 << 20 },
    })
    m:write_memory(PARAM, string.pack("<I8", case))
    return m
end

local function run_case(case)
    local m <close> = make_machine(case)
    m:run(100000)
    assert(m:read_reg("iflags_H") ~= 0, "harness error: guest did not halt in case " .. case)
    assert(m:read_reg("mcause") == 9, "harness error: guest did not reach M via ecall from S in case " .. case)
    return m:read_reg("htif_tohost_data") >> 1, m:read_reg("mip")
end

local failures = {}

local exit0, mip0 = run_case(0)
print(string.format("case 0 (S: csrs sip,STIP|SEIP): exit=%d mip=0x%x", exit0, mip0))
if exit0 ~= 0 then
    failures[#failures + 1] = string.format(
        "S-mode csrs sip,(STIP|SEIP) set read-only sip bits (mip=0x%x); only SSIP is writable in sip", mip0)
end

local exit1, mip1 = run_case(1)
print(string.format("case 1 (M: mip|=STIP|SEIP, S: csrc sip,STIP|SEIP): exit=%d mip=0x%x", exit1, mip1))
if exit1 ~= 0 then
    failures[#failures + 1] = string.format(
        "S-mode csrc sip,(STIP|SEIP) cleared timer/external interrupts raised by M-mode (mip=0x%x)", mip1)
end

local exit2, mip2 = run_case(2)
print(string.format("case 2 (control, S: csrs sip,SSIP): exit=%d mip=0x%x", exit2, mip2))
assert(exit2 == 0 and mip2 & SSIP ~= 0, "harness error: control case failed, SSIP must be writable from sip")

-- Consistency across paths for case 0.
do
    local native <close> = make_machine(0)
    local uarch <close> = make_machine(0)
    local logged = false
    while native:read_reg("iflags_H") == 0 do
        local target = native:read_reg("mcycle") + 1
        local before_mip = native:read_reg("mip")
        native:run(target)
        local wrote_sip = before_mip & (STIP | SEIP) == 0 and native:read_reg("mip") & (STIP | SEIP) ~= 0
        if wrote_sip and not logged then
            -- Log and verify every uarch step of the mcycle that executes csrs sip.
            local steps = 0
            while uarch:read_reg("uarch_halt") == 0 do
                local h = uarch:get_root_hash()
                local log = uarch:log_step_uarch()
                local after = uarch:get_root_hash()
                assert(cartesi.machine:verify_step_uarch(h, log) == after, "uarch step log does not verify")
                steps = steps + 1
            end
            local h = uarch:get_root_hash()
            local log = uarch:log_reset_uarch()
            assert(cartesi.machine:verify_reset_uarch(h, log) == uarch:get_root_hash(), "uarch reset log does not verify")
            print(string.format("verifier: %d logged uarch steps + reset of the csrs sip mcycle verify", steps))
            logged = true
        else
            uarch:run_uarch(cartesi.UARCH_CYCLE_MAX)
            assert(uarch:read_reg("uarch_halt") ~= 0, "harness error: uarch did not halt within the mcycle")
            uarch:reset_uarch()
        end
        assert(uarch:read_reg("mcycle") == target, "harness error: uarch mcycle mismatch")
        if native:get_root_hash() ~= uarch:get_root_hash() then
            error("uarch and native diverge at mcycle " .. target .. " (unexpected: this would be Critical)")
        end
    end
    print(string.format("uarch replay: agrees with native through halt at mcycle %d (uarch mip=0x%x)",
        native:read_reg("mcycle"), uarch:read_reg("mip")))
end

os.execute("rm -rf " .. outdir)

if #failures > 0 then
    for _, f in ipairs(failures) do
        print("FAIL R1-ARCH-4: " .. f)
    end
    os.exit(1)
end
print("OK: sip.STIP and sip.SEIP are read-only from S-mode")
os.exit(0)
