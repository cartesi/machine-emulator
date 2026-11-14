-- R1-R12-4: collect_uarch_cycle_bundle / collect_mcycle_bundle cost per repeated fixed-point leaf.
--
-- THREAT_MODEL.md R12: "Where a computation hash repeats the hash of a fixed point, the repetitions cost a
-- bounded amount per run of them, not per cycle."
--
-- Each measurement runs in its own child process (measure.lua) on a fresh machine with the harness's
-- bare-metal `halt` guest (114 mcycles, then halts with 42), and records the growth of the child's peak RSS
-- (VmHWM) caused by the one API call. The control is the same work without the repeated tail:
--   uarch: collect_uarch_cycle_root_hashes(mcycle+1, 0)  vs  collect_uarch_cycle_bundle(0, 20)   (same mcycle)
--   mcycle: collect_mcycle_root_hashes(MCYCLE_MAX, 0, 0, 0) vs collect_mcycle_bundle(0, 0, 20)  (to the halt)
-- Required: the bundle call costs at most a bounded amount more than its control, i.e. its peak-RSS growth
-- is at most max(16 MiB, 32 x control growth). The repetitions (the halted uarch tail of the mcycle, and the
-- halt fixed point padding 2^20 mcycle positions) must not be paid per position.
local harness = require("harness")

harness.main(function()
    local guest = harness.baremetal("halt")
    local function measure(mode)
        local ok, out = harness.sh(string.format("lua5.4 measure.lua %s %q 2>&1", mode, guest))
        local n, kib, mcycle = out:match("entries=(%d+) hwm_delta_kib=(%d+) mcycle=(%d+)")
        if not ok or not n then harness.setup_error("measure " .. mode .. " failed:\n" .. out) end
        io.stderr:write(string.format("  %-15s entries=%-8s peak RSS growth=%8.1f MiB  (mcycle after: %s)\n",
            mode, n, tonumber(kib) / 1024, mcycle))
        return tonumber(n), tonumber(kib)
    end

    local LIMIT_FLOOR_KIB = 16 * 1024
    local RATIO = 32
    local all_ok = true
    for _, kind in ipairs({ "uarch", "mcycle" }) do
        local cn, ckib = measure(kind .. "-control")
        local bn, bkib = measure(kind .. "-bundle")
        local limit = math.max(LIMIT_FLOOR_KIB, RATIO * ckib)
        local ok = bkib <= limit
        io.stderr:write(string.format("  %s: control %d entries / %.1f MiB, bundle %d entries / %.1f MiB, limit %.1f MiB"
            .. " (%.0fx the control)\n", kind, cn, ckib / 1024, bn, bkib / 1024, limit / 1024, bkib / math.max(ckib, 1)))
        all_ok = harness.expect(ok, string.format(
            "R12: collect_%s_bundle must cost a bounded amount per run of repeated fixed-point hashes "
            .. "(peak RSS growth %.1f MiB <= %.1f MiB)", kind == "uarch" and "uarch_cycle" or "mcycle",
            bkib / 1024, limit / 1024)) and all_ok
    end
    return all_ok
end)
