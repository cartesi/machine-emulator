#!/usr/bin/env lua5.4
-- R7-FPMEM-1: a PLIC claim/complete write clears the software-written mip.SEIP bit
-- (src/plic-address-range.cpp plic_write_claim_complete: reset_mip(MIP_MEIP_MASK | MIP_SEIP_MASK) when the
-- PLIC has nothing pending; the emulator stores M-mode's software SEIP and the PLIC signal in one bit).
--
-- RISC-V privileged spec (R7, "traps and interrupts"): mip.SEIP is writable by M-mode, and the pending
-- supervisor external interrupt is the logical OR of that software bit and the interrupt controller's signal.
-- A PLIC claim/complete only affects the controller's signal, so it can never clear the software bit.
--
-- This test boots a bare-metal guest (seip.S, built at test time) and checks:
--   case M: M-mode sets mip.SEIP, stores 1 to PLIC claim/complete -> mip.SEIP must still read 1;
--   case S: M-mode injects SEIP, delegates SEI to S, enters S with SIE=0; S-mode stores 1 to claim/complete
--           and then sets SIE=1 -> the injected supervisor external interrupt must be taken (scause = 0x8..09).
-- A control run skips the S-mode store and must take the SEI (shows the harness itself is sound).
-- It also replays the whole run through the uarch (run_uarch + reset_uarch per mcycle), logging and verifying
-- every uarch step and the reset of each mcycle in which native mip changes (the claim/complete stores), and
-- checks it agrees with native interpretation at every mcycle: the deviation is consistent across paths
-- (Medium, not a divergence).
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local RESULT = 0x80001000
local SEIP = 1 << 9
local SCAUSE_SEI = 0x8000000000000009
local MCAUSE_ECALL_S = 9

local outdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
assert(os.execute("bash ./build.sh " .. outdir), "harness error: failed to build guest seip.bin")
local bin = outdir .. "/seip.bin"

local SKIP = 0x80001100

local function make_machine(skip)
    local m = cartesi.machine({ ram = { backing_store = { data_filename = bin }, length = 1 << 20 } })
    m:write_memory(SKIP, string.pack("<I4", skip and 1 or 0))
    return m
end

-- Control run: without the S-mode claim/complete store, the injected SEI is taken.
do
    local c <close> = make_machine(true)
    c:run(100000)
    assert(c:read_reg("iflags_H") ~= 0, "harness error: control guest did not halt")
    local cs = string.unpack("<I8", c:read_memory(RESULT + 16, 8))
    print(string.format("control (no S-mode store): scause=0x%x", cs))
    assert(cs == SCAUSE_SEI, "harness error: control run did not take the injected SEI")
end

-- Native run
local m <close> = make_machine()
m:run(100000)
assert(m:read_reg("iflags_H") ~= 0, "harness error: guest did not halt")
local final_mcycle = m:read_reg("mcycle")
local mip_set, mip_after, scause, mcause = string.unpack("<I8I8I8I8", m:read_memory(RESULT, 32))
print(string.format("case M: mip_after_csrs=0x%x mip_after_claim_complete_write=0x%x", mip_set, mip_after))
print(string.format("case S: scause=0x%x (0 = no supervisor interrupt taken), final mcause=%d, halted at mcycle %d",
    scause, mcause, final_mcycle))
assert(mip_set & SEIP ~= 0, "harness error: csrs mip did not set SEIP")
assert(mcause == MCAUSE_ECALL_S, "harness error: guest did not end with an ecall from S-mode")
assert(scause == 0 or scause == SCAUSE_SEI, "harness error: unexpected supervisor trap cause")

-- Uarch replay with logged and verified steps and resets, compared with native at every mcycle.
do
    local native <close> = make_machine()
    local uarch <close> = make_machine()
    local nsteps, nlogged = 0, 0
    for target = 1, final_mcycle do
        local mip_before = native:read_reg("mip")
        native:run(target)
        if native:read_reg("mip") ~= mip_before then
            nlogged = nlogged + 1
            while uarch:read_reg("uarch_halt") == 0 do
                local before = uarch:get_root_hash()
                local log = uarch:log_step_uarch()
                assert(cartesi.machine:verify_step_uarch(before, log) == uarch:get_root_hash(),
                    "uarch step log does not verify (unexpected)")
                nsteps = nsteps + 1
            end
            local before = uarch:get_root_hash()
            local log = uarch:log_reset_uarch()
            assert(cartesi.machine:verify_reset_uarch(before, log) == uarch:get_root_hash(),
                "uarch reset log does not verify (unexpected)")
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
    local um = string.unpack("<I8", uarch:read_memory(RESULT + 8, 8))
    print(string.format("uarch replay: agrees with native at all %d mcycles; %d logged+verified uarch steps in the "
        .. "%d mcycles where mip changes (uarch also sees mip_after=0x%x)", final_mcycle, nsteps, nlogged, um))
end

os.execute("rm -rf " .. outdir)

local failures = {}
if mip_after & SEIP == 0 then
    failures[#failures + 1] = string.format("M-mode software-written mip.SEIP was cleared by a PLIC claim/complete "
        .. "write (mip 0x%x -> 0x%x); SEIP must be the OR of the software bit and the PLIC signal", mip_set, mip_after)
end
if scause ~= SCAUSE_SEI then
    failures[#failures + 1] = "an S-mode store to PLIC claim/complete discarded the supervisor external interrupt "
        .. "injected by M-mode (no SEI taken after sstatus.SIE=1)"
end
if #failures > 0 then
    for _, f in ipairs(failures) do
        print("FAIL R7-FPMEM-1: " .. f)
    end
    os.exit(1)
end
print("OK: PLIC claim/complete does not clear the software-written mip.SEIP")
os.exit(0)
