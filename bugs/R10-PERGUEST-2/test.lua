-- R10-PERGUEST-2: collect_mcycle_root_hashes updates the hash tree over the whole shadow state (registers, TLB,
-- uarch state) twice per automatic yield, although no hash is needed at a yield that is not a sampling point.
--
-- A guest that loops on an automatic yield ('sd t1,0(tohost); j .') makes the honest builder call
-- collect_mcycle_root_hashes once every 2 mcycles. Each call (1) runs update_hash_tree() on entry, which marks
-- the shadow uarch state, the shadow registers and the 6 shadow TLB pages dirty and updates the tree, and
-- (2) after interpret returns at the yield, updates the tree again over the 8 shadow-state pages that
-- do_write_mcycle marked dirty, before even testing whether the reached mcycle is a sampling point.
--
-- Asserted (deterministic, hash-tree statistics, no timing): over a span of mcycles that contains no sampling
-- point, the hash-tree pages looked up by the builder may exceed those of the same span without yields (control:
-- one call over a guest that spins without yielding) by at most 2 pages per automatic yield (the shadow-registers
-- page the yield actually writes: mcycle and the HTIF registers, plus one page of margin).
-- The guest writes no RAM, so the write TLB holds no valid slot and R1-R8-3 does not contribute.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local HTIF_TOHOST = 0x40008000
    local HTIF_DEV_YIELD = 2
    local HTIF_YIELD_CMD_AUTOMATIC = 0
    local HTIF_YIELD_AUTOMATIC_REASON_PROGRESS = 1
    local LOG2_PERIOD = 30 -- large sampling period: no sampling point is reached in the measured span
    local YIELDS = 256 -- collect calls measured, one automatic yield each
    local MARGIN_PER_YIELD = 2 -- pages per yield allowed above the no-yield control
    local TIMED_CALLS = 2000

    local YIELD_LOOP = {
        0x006EB023, -- yld: sd t1, 0(t4)   (automatic yield, progress)
        0xFFDFF06F, --      j  yld
    }
    local SPIN_LOOP = {
        0x00128293, -- spn: addi t0, t0, 1
        0xFFDFF06F, --      j  spn
    }

    local function build(code)
        local m = cartesi.machine({ ram = { length = 4 << 20 } })
        m:write_memory(RAM, string.pack("<" .. string.rep("I4", #code), table.unpack(code)))
        m:write_reg("x29", HTIF_TOHOST)
        m:write_reg("x6", (HTIF_DEV_YIELD << 56) | (HTIF_YIELD_CMD_AUTOMATIC << 48)
            | (HTIF_YIELD_AUTOMATIC_REASON_PROGRESS << 32))
        return m
    end

    local function work(stats)
        local hashes = stats.sparse_node_hashes + stats.phtc.inner_page_hashes
        for _, v in ipairs(stats.dense_node_hashes) do
            hashes = hashes + v
        end
        return stats.phtc.page_hits + stats.phtc.page_misses, hashes
    end

    -- Subject: the automatic-yield loop, one collect call per yield, as the honest builder re-enters.
    local m <close> = build(YIELD_LOOP)
    local phase = 0
    local res = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, LOG2_PERIOD, phase, 0) -- warm-up
    if res.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
        error("guest did not reach its automatic yield: " .. tostring(res.break_reason))
    end
    phase = res.mcycle_phase
    m:get_hash_tree_stats(true)
    local mcycle0 = m:read_reg("mcycle")
    local samples = 0
    for _ = 1, YIELDS do
        res = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, LOG2_PERIOD, phase, 0)
        if res.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            error("unexpected break reason " .. tostring(res.break_reason))
        end
        phase = res.mcycle_phase
        samples = samples + #res.hashes
    end
    local sub_pages, sub_hashes = work(m:get_hash_tree_stats(true))
    local span = m:read_reg("mcycle") - mcycle0
    if samples ~= 0 then
        error("the measured span unexpectedly contains a sampling point")
    end

    -- Control: the same number of mcycles, same period, no yields (one call).
    local c <close> = build(SPIN_LOOP)
    res = c:collect_mcycle_root_hashes(c:read_reg("mcycle") + 2, LOG2_PERIOD, 0, 0) -- warm-up, same as above
    c:get_hash_tree_stats(true)
    res = c:collect_mcycle_root_hashes(c:read_reg("mcycle") + span, LOG2_PERIOD, res.mcycle_phase, 0)
    if res.break_reason ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE or #res.hashes ~= 0 then
        error("control did not run its span without sampling")
    end
    local ctl_pages, ctl_hashes = work(c:get_hash_tree_stats(true))

    -- Information only: the cost of an actual sample (period 1 mcycle, spin guest).
    local s <close> = build(SPIN_LOOP)
    s:collect_mcycle_root_hashes(s:read_reg("mcycle") + 2, 0, 0, 0)
    s:get_hash_tree_stats(true)
    res = s:collect_mcycle_root_hashes(s:read_reg("mcycle") + YIELDS, 0, 0, 0)
    local smp_pages, smp_hashes = work(s:get_hash_tree_stats(true))
    local nsamples = #res.hashes

    -- Information only (not asserted): CPU time per collect call at a yield, and per run() to the same yield.
    local t0 = os.clock()
    for _ = 1, TIMED_CALLS do
        res = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, LOG2_PERIOD, res.mcycle_phase, 0)
    end
    local collect_us = (os.clock() - t0) / TIMED_CALLS * 1e6
    t0 = os.clock()
    for _ = 1, TIMED_CALLS do
        m:run(cartesi.MCYCLE_MAX)
    end
    local run_us = (os.clock() - t0) / TIMED_CALLS * 1e6

    print(string.format("subject (automatic yield every 2 mcycles): %d mcycles, %d collect calls, 0 samples: "
        .. "%d pages, %d hashes (%.1f pages, %.1f hashes per yield)", span, YIELDS, sub_pages, sub_hashes,
        sub_pages / YIELDS, sub_hashes / YIELDS))
    print(string.format("control (no yields, same span, 1 call):     %d mcycles, 0 samples: %d pages, %d hashes",
        span, ctl_pages, ctl_hashes))
    print(string.format("info: one real sample (log2 period 0):      %.1f pages, %.1f hashes per sample",
        smp_pages / nsamples, smp_hashes / nsamples))
    print(string.format("info: CPU per collect call at a yield %.1f us, per run() to the same yield %.2f us",
        collect_us, run_us))
    local extra = (sub_pages - ctl_pages) / YIELDS
    print(string.format("extra hash-tree pages per automatic yield: %.1f (allowed %d)", extra, MARGIN_PER_YIELD))
    return harness.expect(sub_pages <= ctl_pages + MARGIN_PER_YIELD * YIELDS,
        "R12 / section 8 High: an automatic yield that is not a sampling point must not make "
            .. "collect_mcycle_root_hashes update the hash tree over the always-dirty shadow pages (per-yield "
            .. "hash-tree work above the no-yield control must stay within the pages the yield writes)")
end)
