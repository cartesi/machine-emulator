-- R1-R7-4: the PLIC claim register returns the HIGHEST pending source ID, while the RISC-V PLIC specification
-- breaks ties between sources of equal priority in favour of the LOWEST ID.
--
-- Requirement (THREAT_MODEL.md R7): "The emulator implements the RISC-V specification and the devices as the
-- manual documents them, departing only where the manual documents a deviation." The manual lists the PLIC
-- (0x40100000) among the board devices and documents no claim ordering. The emulator hardwires every source
-- priority to the same level (reads of priority1..31 return 1). The RISC-V PLIC specification (riscv-plic-spec,
-- "Interrupt Priorities"): "Ties between global interrupts of the same priority are broken by the Interrupt ID;
-- interrupts with the lowest ID have the highest effective priority." and ("Interrupt Claim Process") a claim
-- returns "the ID of the highest-priority pending interrupt for the target".
--
-- Setup: a minimal reproducible machine (4 KiB RAM) whose PLIC has sources 1 and 2 pending (girqpend = 0b110,
-- set through the config, as only VirtIO devices, which need an unreproducible machine, raise PLIC sources).
-- The M-mode guest reads the priority of sources 1 and 2, then performs two 32-bit claims, then spins.
--
-- Passes (exit 0) if both priorities are equal and the first claim returns 1 and the second 2.
-- Fails (exit 1) if the first claim returns 2 (the emulator's ilog2 of the pending mask).
-- The same program run through the uarch (run_uarch + reset_uarch) must agree with native interpretation; a
-- disagreement there would be a different bug and is reported as a setup error (exit 2).

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local RAM_START = 0x80000000
    local PLIC_START = 0x40100000
    if cartesi.AR_PLIC_START and cartesi.AR_PLIC_START ~= PLIC_START then
        harness.setup_error(string.format("unexpected PLIC start 0x%x", cartesi.AR_PLIC_START))
    end

    -- t0 = PLIC base + 0x200000 (threshold/claim page of context 0)
    -- a2 = priority1 (base+4), a3 = priority2 (base+8)
    -- a0 = first claim, a1 = second claim (base+0x200004)
    local program = {
        0x401002b7, -- lui  t0, 0x40100        t0 = 0x40100000
        0x0042a603, -- lw   a2, 4(t0)          priority1
        0x0082a683, -- lw   a3, 8(t0)          priority2
        0x403002b7, -- lui  t0, 0x40300        t0 = 0x40300000
        0x0042a503, -- lw   a0, 4(t0)          claim #1
        0x0042a583, -- lw   a1, 4(t0)          claim #2
        0x0000006f, -- jal  x0, 0              spin
    }
    local code = {}
    for _, insn in ipairs(program) do
        code[#code + 1] = string.pack("<I4", insn)
    end
    code = table.concat(code)

    local function new_machine()
        local config = {
            ram = { length = 0x1000 },
            processor = {
                registers = {
                    pc = RAM_START,
                    plic = { girqpend = 0x6, girqsrvd = 0 }, -- sources 1 and 2 pending
                },
            },
        }
        local m = harness.machine(config)
        if m:read_reg("iunrep") ~= 0 then harness.setup_error("machine is unreproducible") end
        if m:read_reg("plic_girqpend") ~= 0x6 then
            harness.setup_error(string.format("girqpend = 0x%x", m:read_reg("plic_girqpend")))
        end
        m:write_memory(RAM_START, code)
        return m
    end

    -- native interpretation
    local m <close> = new_machine()
    local start = m:read_reg("mcycle")
    m:run(start + #program + 4)
    local native = {
        prio1 = m:read_reg("x12"),
        prio2 = m:read_reg("x13"),
        claim1 = m:read_reg("x10"),
        claim2 = m:read_reg("x11"),
        pc = m:read_reg("pc"),
    }
    if native.pc ~= RAM_START + 4 * (#program - 1) then
        harness.setup_error(string.format("guest did not reach the spin loop: pc=0x%x", native.pc))
    end

    -- the same program through the uarch (consistency across paths; not the claim under test)
    local u <close> = new_machine()
    for _ = 1, #program + 4 do
        u:run_uarch(cartesi.UARCH_CYCLE_MAX or (1 << 64) - 1)
        u:reset_uarch()
    end
    local uarch = {
        prio1 = u:read_reg("x12"),
        prio2 = u:read_reg("x13"),
        claim1 = u:read_reg("x10"),
        claim2 = u:read_reg("x11"),
    }

    print(string.format("native: priority1=%d priority2=%d claim#1=%d claim#2=%d", native.prio1, native.prio2,
        native.claim1, native.claim2))
    print(string.format("uarch:  priority1=%d priority2=%d claim#1=%d claim#2=%d", uarch.prio1, uarch.prio2,
        uarch.claim1, uarch.claim2))
    for k, v in pairs(uarch) do
        if native[k] ~= v then harness.setup_error("native and uarch disagree on " .. k) end
    end
    if native.prio1 ~= native.prio2 or native.prio1 == 0 then
        harness.setup_error("sources 1 and 2 do not have the same non-zero priority")
    end

    return harness.expect(native.claim1 == 1 and native.claim2 == 2,
        string.format("R7 / PLIC spec: with sources 1 and 2 pending at equal priority, claims must return 1 then 2 "
            .. "(lowest ID first); the emulator returned %d then %d", native.claim1, native.claim2))
end)
