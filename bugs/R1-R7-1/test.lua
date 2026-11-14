-- R1-R7-1: an SC after a remap of the reserved virtual address succeeds on a physical word in another
-- 4 KiB physical page, which no LR/SC reservation set of the earlier LR may contain.
--
-- Guest (S-mode, Sv39, no interrupts, no trap between LR and SC):
--   VA 0x1000 maps to P1 (page A) and later to P2 (another 4 KiB physical page)
--   lr.d  x6, (x5)        ; x5 = 0x1000 -> reserves (a set within) P1's physical page
--   <remap VA 0x1000 to P2>  (variant "satp": csrw satp to a second root; variant "pte": sd new leaf PTE)
--   sfence.vma
--   sc.d  x9, x8, (x5)    ; would write P2
--
-- Required (RISC-V privileged spec, Sv32/Sv39 section: "For implementations with both page-based virtual
-- memory and the A standard extension, the LR/SC reservation set must lie completely within a single base
-- physical page (i.e., a naturally aligned 4 KiB physical-memory region)"; Zalrsc: "The SC must fail if the
-- address is not within the reservation set of the most recent LR in program order", "If the SC fails, the
-- instruction does not write to memory, and it writes a nonzero value to rd"), as THREAT_MODEL.md R7
-- ("Atomics and fences") asks: the SC must fail (x9 ~= 0) and P2 must keep its value.
--
-- Control: the same program with a "remap" that keeps VA 0x1000 on P1 must succeed (x9 == 0, P1 written),
-- so a failure of the assertion cannot come from a broken setup.
--
-- The uarch path (run_uarch + reset_uarch per mcycle) is run too and must agree with native interpretation;
-- it is reported, and a disagreement is a harness error (it would be a different defect).

local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local V, R, W, X, A, D = 1, 2, 4, 8, 64, 128
    local P1, P2 = RAM + 0x20000, RAM + 0x21000 -- distinct 4 KiB physical pages
    local CODE = RAM + 0x5000 -- mapped at VA 0x5000
    local TRAP = RAM + 0x4000
    local ROOT_A, ROOT_B = RAM + 0x10000, RAM + 0x30000
    local OLD, NEW = 0x1111, 0x9999

    local function pte(pa, flags) return ((pa >> 12) << 10) | flags end

    -- program variants (VA 0x5000 ...)
    local programs = {
        satp = {
            0x1002b32f, -- lr.d x6,(x5)
            0x18039073, -- csrw satp,x7
            0x12000073, -- sfence.vma
            0x1882b4af, -- sc.d x9,x8,(x5)
            0x0000006f, -- j .
        },
        pte = {
            0x1002b32f, -- lr.d x6,(x5)
            0x00a5b023, -- sd x10,0(x11)   (overwrite the leaf PTE of VA 0x1000)
            0x12000073, -- sfence.vma
            0x1882b4af, -- sc.d x9,x8,(x5)
            0x0000006f, -- j .
        },
    }

    local function build(variant, remap)
        local m = cartesi.machine({ ram = { length = 1 << 20 } })
        local function w64(a, v) m:write_memory(a, string.pack("<I8", v)) end
        local function w32(a, v) m:write_memory(a, string.pack("<I4", v)) end
        local function mkpt(root, target)
            local l1, l0 = root + 0x1000, root + 0x2000
            m:write_memory(root, string.rep("\0", 0x3000))
            w64(root, pte(l1, V))
            w64(l1, pte(l0, V))
            w64(l0 + 8 * 5, pte(CODE, V | X | A)) -- VA 0x5000 -> code
            w64(l0 + 8 * 1, pte(target, V | R | W | A | D)) -- VA 0x1000 -> target
            w64(l0 + 8 * 2, pte(l0, V | R | W | A | D)) -- VA 0x2000 -> this leaf table
        end
        mkpt(ROOT_A, P1)
        mkpt(ROOT_B, remap and P2 or P1)
        w64(P1, OLD)
        w64(P2, OLD)
        for i, c in ipairs(programs[variant]) do
            w32(CODE + 4 * (i - 1), c)
        end
        w32(TRAP, 0x0000006f)
        local sv39 = 8 << 60
        m:write_reg("x5", 0x1000)
        m:write_reg("x7", sv39 | (ROOT_B >> 12))
        m:write_reg("x8", NEW)
        m:write_reg("x9", 77)
        m:write_reg("x10", pte(remap and P2 or P1, V | R | W | A | D))
        m:write_reg("x11", 0x2000 + 8 * 1)
        m:write_reg("satp", sv39 | (ROOT_A >> 12))
        m:write_reg("mstatus", (2 << 32) | (2 << 34)) -- UXL = SXL = 64, MIE = 0
        m:write_reg("mie", 0)
        m:write_reg("mtvec", TRAP)
        m:write_reg("iprv", 1) -- S-mode
        m:write_reg("pc", 0x5000)
        return m
    end

    local function observe(m)
        local function r64(a) return (string.unpack("<I8", m:read_memory(a, 8))) end
        return {
            pc = m:read_reg("pc"),
            iprv = m:read_reg("iprv"),
            x9 = m:read_reg("x9"),
            p1 = r64(P1),
            p2 = r64(P2),
            root = m:get_root_hash(),
        }
    end

    local NINSN = 4 -- lr, remap, sfence, sc; then j .
    local function run_native(variant, remap)
        local m <close> = build(variant, remap)
        m:run(m:read_reg("mcycle") + NINSN + 2)
        return observe(m)
    end
    local function run_uarch(variant, remap)
        local m <close> = build(variant, remap)
        for _ = 1, NINSN + 2 do
            m:run_uarch(cartesi.UARCH_CYCLE_MAX)
            m:reset_uarch()
        end
        return observe(m)
    end

    local function show(tag, o)
        print(string.format("%-28s pc=0x%x prv=%d x9(sc rd)=%d P1=0x%x P2=0x%x", tag, o.pc, o.iprv, o.x9, o.p1,
            o.p2))
    end

    local ok = true
    for _, variant in ipairs({ "satp", "pte" }) do
        local ctl = run_native(variant, false)
        local ctlu = run_uarch(variant, false)
        local got = run_native(variant, true)
        local gotu = run_uarch(variant, true)
        show(variant .. " control (native)", ctl)
        show(variant .. " control (uarch)", ctlu)
        show(variant .. " remap   (native)", got)
        show(variant .. " remap   (uarch)", gotu)
        local endpc = 0x5000 + 4 * NINSN
        for _, o in ipairs({ ctl, ctlu, got, gotu }) do
            if o.pc ~= endpc or o.iprv ~= 1 then
                harness.setup_error(variant .. ": the program did not reach the end in S-mode without a trap")
            end
        end
        if ctl.root ~= ctlu.root or got.root ~= gotu.root then
            harness.setup_error(variant .. ": native and uarch paths disagree (a different defect)")
        end
        if not (ctl.x9 == 0 and ctl.p1 == NEW and ctl.p2 == OLD) then
            harness.setup_error(variant .. ": control LR/SC on an unchanged mapping did not succeed")
        end
        ok = harness.expect(got.x9 ~= 0 and got.p2 == OLD and got.p1 == OLD,
            variant .. ": R7 (Atomics; Address translation): after LR at VA 0x1000 (P1) and a remap of VA 0x1000 "
                .. "to P2 in another 4 KiB physical page, the SC lies outside every legal reservation set and must "
                .. "fail (rd != 0) without writing memory") and ok
    end
    return ok
end)
