-- R1-R8-3: collect_mcycle_root_hashes rehashes every page mapped by the write TLB on entry, even when
-- nothing was written since the previous call. A guest that fills the write TLB and then loops on an
-- automatic yield makes every 2-mcycle collect call re-visit ~256 unchanged pages.
--
-- Asserted (deterministic, hash-tree statistics, no timing): a collect_mcycle_root_hashes call that resumes
-- at an automatic yield, with no memory written since the previous call, visits a number of hash-tree pages
-- that does not depend on how many write-TLB slots are valid. Control: the same guest with one valid
-- write-TLB slot. Required: pages(full TLB) <= pages(one slot) + MARGIN per call.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local RAM = 0x80000000
    local CALLS = 64
    local TIMED_CALLS = 1000
    local MARGIN = 16 -- pages per call allowed above the control (the guest writes no memory at all)

    local HTIF_TOHOST = 0x40008000
    local HTIF_DEV_YIELD = 2
    local HTIF_YIELD_CMD_AUTOMATIC = 0
    local HTIF_YIELD_AUTOMATIC_REASON_PROGRESS = 1

    -- t0 = fill base, t3 = stride (4 KiB), t2 = number of pages to store to, t4 = tohost, t1 = yield command
    local code = {
        0x0052B023, -- loop: sd   t0, 0(t0)    (non-zero data: the page is not pristine)
        0x01C282B3, --       add  t0, t0, t3
        0xFFF38393, --       addi t2, t2, -1
        0xFE039AE3, --       bnez t2, loop
        0x006EB023, -- yld:  sd   t1, 0(t4)      (automatic yield)
        0xFFDFF06F, --       j    yld
    }

    local function build(pages)
        local m = cartesi.machine({ ram = { length = 4 << 20 } })
        m:write_memory(RAM, string.pack("<" .. string.rep("I4", #code), table.unpack(code)))
        m:write_reg("x5", RAM + 0x100000)
        m:write_reg("x28", 4096)
        m:write_reg("x7", pages)
        m:write_reg("x29", HTIF_TOHOST)
        m:write_reg("x6", (HTIF_DEV_YIELD << 56) | (HTIF_YIELD_CMD_AUTOMATIC << 48)
            | (HTIF_YIELD_AUTOMATIC_REASON_PROGRESS << 32))
        return m
    end

    local function pages_visited(stats)
        return stats.phtc.page_hits + stats.phtc.page_misses
    end

    local function measure(pages)
        local m <close> = build(pages)
        -- reach the yield loop: the fill loop is 4 instructions per page
        local r = m:run(4 * pages + 16)
        if r ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            error("guest did not reach its automatic yield: " .. tostring(r))
        end
        -- one warm-up collect call: it may legitimately hash the pages the fill loop wrote
        local res = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, 10, 0, 0)
        if res.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
            error("unexpected break reason " .. tostring(res.break_reason))
        end
        m:get_hash_tree_stats(true)
        local mcycle0 = m:read_reg("mcycle")
        for _ = 1, CALLS do
            res = m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, 10, 0, 0)
            if res.break_reason ~= cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY then
                error("unexpected break reason " .. tostring(res.break_reason))
            end
        end
        local stats = m:get_hash_tree_stats(true)
        local mcycles = m:read_reg("mcycle") - mcycle0
        -- informative only (not asserted): CPU time per collect call, and the hash computations, which
        -- are the same in both runs (the extra work is marking and comparing unchanged pages)
        local t0 = os.clock()
        for _ = 1, TIMED_CALLS do
            m:collect_mcycle_root_hashes(cartesi.MCYCLE_MAX, 10, 0, 0)
        end
        local us = (os.clock() - t0) / TIMED_CALLS * 1e6
        local node_hashes = stats.sparse_node_hashes + stats.phtc.inner_page_hashes
        for _, v in ipairs(stats.dense_node_hashes) do
            node_hashes = node_hashes + v
        end
        return pages_visited(stats) / CALLS, (stats.phtc.word_hits + stats.phtc.word_misses) / CALLS,
            mcycles / CALLS, node_hashes / CALLS, us
    end

    local ctl_pages, ctl_words, ctl_mcycles, ctl_hashes, ctl_us = measure(1)
    local full_pages, full_words, full_mcycles, full_hashes, full_us = measure(256)
    local fmt = "%-31s %.1f pages, %.1f words compared, %.1f hashes, %.1f mcycles per collect call (%.1f us, info)"
    print(string.format(fmt, "control  (1 write-TLB slot):", ctl_pages, ctl_words, ctl_hashes, ctl_mcycles, ctl_us))
    print(string.format(fmt, "full TLB (256 write-TLB slots):", full_pages, full_words, full_hashes, full_mcycles,
        full_us))
    if full_mcycles ~= ctl_mcycles then
        error("control and full runs execute different mcycles per call")
    end
    print(string.format("ratio of hash-tree pages visited per call: %.1fx", full_pages / ctl_pages))
    return harness.expect(full_pages <= ctl_pages + MARGIN,
        "R12 / section 8 High: a collect_mcycle_root_hashes call that resumes at an automatic yield with no "
            .. "memory written must not re-visit every page mapped by the write TLB (per-call hash-tree work "
            .. "must not grow with valid write-TLB slots)")
end)
