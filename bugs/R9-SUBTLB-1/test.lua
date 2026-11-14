-- R9-SUBTLB-1: SRET from S-mode to S-mode clears mstatus.MPRV but does not flush the read/write TLB.
--
-- Machine created from a configuration: iprv = S, mstatus.MPRV = 1, MPP = U, SPP = S, SUM = 0, satp = Sv39.
-- The guest (hand-encoded below, no toolchain needed) runs in S-mode:
--
--   0x80000000  ld   t0, 0(a1)     a1 = 0xC0002000, a U page. With MPRV=1 and MPP=U the emulator performs this
--                                  load at effective privilege U: it succeeds and fills the read TLB.
--   0x80000004  addi s0, x0, 1
--   0x80000008  sret               sepc = 0x8000000C, SPP = S: stays in S and clears MPRV (privileged spec).
--   0x8000000C  nop | sfence.vma   (the control variant flushes the TLB here)
--   0x80000010  addi s0, x0, 2
--   0x80000014  ld   t2, 0(a1)     S-mode, MPRV = 0, SUM = 0, U page: must raise a load page fault (cause 13).
--   0x80000018  addi s0, x0, 3     reached only if the second load completed
--   0x8000001C  j .
--   0x80000100  S handler (medeleg delegates page faults): s1 = 1, s2 = scause, s3 = sepc, s4 = stval; j .
--
-- Required (THREAT_MODEL R7, area "Address translation and memory permissions"; RISC-V privileged spec, SUM: "When
-- SUM=0, S-mode memory accesses to pages that are accessible by U-mode will fault"): the second load must not
-- complete; it must raise a load page fault with sepc = 0x80000014 and stval = 0xC0002000.
-- A fix that instead refuses to create a machine outside M-mode with MPRV=1 also passes (the state is then not
-- producible), and so does a fix that ignores MPRV outside M-mode (the first load then faults).
--
-- The control (sfence.vma before the second load) shows that a page walk refuses the access, so the bug is the
-- stale TLB entry. The uarch path is also run on the bug variant, to report whether the deviation is consistent
-- across paths (informational).
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local RAM = 0x80000000
    local ROOT = RAM + 0x1000 -- Sv39 root page table
    local DATA_PA = RAM + 0x2000
    local VA = 0xC0002000 -- gigapage 3 -> PA 0x80000000, U RW
    local HANDLER = RAM + 0x100
    local MTRAP = RAM + 0x200
    local MARKER = 0x1122334455667788

    local function itype(op, f3, rd, rs1, imm) return ((imm & 0xfff) << 20) | (rs1 << 15) | (f3 << 12) | (rd << 7) | op end
    local function ld(rd, rs1) return itype(0x03, 3, rd, rs1, 0) end
    local function li(rd, imm) return itype(0x13, 0, rd, 0, imm) end
    local function csrr(rd, csr) return (csr << 20) | (2 << 12) | (rd << 7) | 0x73 end
    local NOP, SFENCE, SRET, JSELF = 0x00000013, 0x12000073, 0x10200073, 0x0000006f
    local T0, T2, S0, S1, S2, S3, S4, A1 = 5, 7, 8, 9, 18, 19, 20, 11

    local bin = os.tmpname()

    local function image(flush)
        local function words(t)
            local s = {}
            for _, w in ipairs(t) do s[#s + 1] = string.pack("<I4", w) end
            return table.concat(s)
        end
        local code = words({ ld(T0, A1), li(S0, 1), SRET, flush and SFENCE or NOP, li(S0, 2), ld(T2, A1), li(S0, 3),
            JSELF })
        local handler = words({ csrr(S2, 0x142), csrr(S3, 0x141), csrr(S4, 0x143), li(S1, 1), JSELF })
        local mtrap = words({ li(S1, 2), JSELF })
        local img = code .. string.rep("\0", 0x100 - #code) .. handler
        img = img .. string.rep("\0", 0x200 - #img) .. mtrap
        img = img .. string.rep("\0", 0x1000 - #img)
        -- Sv39 root: [2] 0x80000000 -> 0x80000000 S RWX A D V; [3] 0xC0000000 -> 0x80000000 U RW A D V
        local pt = {}
        for i = 0, 511 do
            local pte = 0
            if i == 2 then pte = (0x80000 << 10) | 0xcf end
            if i == 3 then pte = (0x80000 << 10) | 0xd7 end
            pt[#pt + 1] = string.pack("<I8", pte)
        end
        img = img .. table.concat(pt) .. string.pack("<I8", MARKER)
        local f = assert(io.open(bin, "wb"))
        f:write(img)
        f:close()
    end

    local def = cartesi.machine:get_default_config()
    local function config(flush)
        image(flush)
        local mstatus = def.processor.registers.mstatus | (1 << 8) | (1 << 17) -- SPP = S, MPRV = 1, MPP = U, SUM = 0
        return {
            ram = { length = 1 << 20, backing_store = { data_filename = bin } },
            processor = {
                registers = {
                    iprv = 1,
                    mstatus = mstatus,
                    satp = (8 << 60) | (ROOT >> 12),
                    stvec = HANDLER,
                    mtvec = MTRAP,
                    sepc = RAM + 0x0C,
                    medeleg = (1 << 12) | (1 << 13) | (1 << 15),
                    x11 = VA,
                },
            },
        }
    end

    local function state(m)
        return {
            stage = m:read_reg("x8"),
            trap = m:read_reg("x9"),
            scause = m:read_reg("x18"),
            sepc = m:read_reg("x19"),
            stval = m:read_reg("x20"),
            t0 = m:read_reg("x5"),
            t2 = m:read_reg("x7"),
            mprv = (m:read_reg("mstatus") >> 17) & 1,
            iprv = m:read_reg("iprv"),
        }
    end
    local function show(name, s)
        print(string.format("%-28s stage=%d trap=%d scause=%d sepc=0x%x stval=0x%x t0(1st ld)=0x%x t2(2nd ld)=0x%x "
            .. "MPRV=%d iprv=%d", name, s.stage, s.trap, s.scause, s.sepc, s.stval, s.t0, s.t2, s.mprv, s.iprv))
    end
    local function faulted_at_second_load(s)
        return s.stage == 2 and s.trap == 1 and s.scause == 13 and s.sepc == RAM + 0x14 and s.stval == VA
            and s.t2 ~= MARKER
    end
    local function faulted_at_first_load(s) -- a fix that ignores MPRV outside M-mode
        return s.stage == 0 and s.trap == 1 and s.scause == 13 and s.sepc == RAM and s.stval == VA
    end

    -- Bug variant (no flush between SRET and the second load)
    local ok, m = pcall(cartesi.machine, config(false))
    if not ok then
        os.remove(bin)
        print("machine creation refused the configuration (iprv=S with MPRV=1): " .. tostring(m))
        return harness.expect(true, "the state (S-mode with MPRV=1) cannot be produced")
    end
    m:run(100)
    local bug = state(m)
    show("native, no flush:", bug)
    m:destroy()

    -- Control: sfence.vma before the second load
    local c <close> = harness.machine(config(true))
    c:run(100)
    local ctl = state(c)
    show("native, sfence.vma (control):", ctl)

    -- uarch path on the bug variant (informational: consistency across paths)
    local u <close> = harness.machine(config(false))
    while u:read_reg("mcycle") < 100 do
        u:run_uarch(cartesi.UARCH_CYCLE_MAX or (1 << 20))
        u:reset_uarch()
    end
    local ust = state(u)
    show("uarch, no flush:", ust)
    os.remove(bin)

    if not faulted_at_second_load(ctl) and not faulted_at_first_load(ctl) then
        harness.setup_error("control did not fault on the U page: the page tables/encoding are wrong")
    end
    print(string.format("uarch and native %s on the bug variant", (ust.stage == bug.stage and ust.t2 == bug.t2
        and ust.trap == bug.trap) and "agree" or "DIFFER"))

    if faulted_at_first_load(bug) then
        return harness.expect(true, "MPRV ignored outside M-mode: the U page is never accessible from S-mode")
    end
    if bug.stage == 3 and bug.t2 == MARKER then
        print("the second load completed in S-mode with SUM=0 on a U page (stale read-TLB entry filled at effective "
            .. "privilege U before SRET cleared MPRV); with sfence.vma it faults")
    end
    return harness.expect(faulted_at_second_load(bug),
        "R7 (address translation and memory permissions): after SRET clears MPRV, an S-mode load with SUM=0 from a U "
            .. "page must raise a load page fault (scause 13, stval = VA)")
end)
