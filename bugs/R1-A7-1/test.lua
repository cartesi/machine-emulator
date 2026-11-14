-- R1-A7-1: the released Dave clocks size the honest uarch-level (leaf) commitment build for AVERAGE uarch density.
--
-- Requirement (THREAT_MODEL.md):
--   A7  "The dispute constants and clocks leave room for the honest claim to play the logarithmic number of matches
--        that a tournament forces on it, at the worst-case costs of R12 ..."
--   section 8, Critical: "An operation listed in R12 whose worst-case cost a guest can make unbounded, super-linear,
--        or larger than what the deployment was sized for."  (R12 lists "a uarch-level claim".)
--
-- What the deployment was sized for (Dave v3.0.0-alpha.7, released, read from bugs/harness/work/dave/released):
--   * ArbitrationConstants.sol: COMMITMENT_BUDGET (120 min) is the wall-clock time granted to build one inner
--     tournament's commitment; log2step = [38, 0], so one level-0 leaf, which the level-1 (uarch-level) claim spans
--     with one hash per uarch cycle, covers 2^(38-20) = 2^18 mcycles.
--   * ClockBudgets.sol: "joining an inner tournament first takes `commitment` seconds to build the commitment".
--   * docs/measurements/constants.md: the reference leaf build rate, 173 mcycles/s, measured on a workload of
--     566 executed uarch cycles per mcycle (the "density label"); the docs state that clocks are dimensioned to
--     the average density, not the worst instruction.
--
-- The test measures, with the emulator's honest uarch-level claim builder (collect_uarch_cycle_root_hashes):
--   * the exact number of uarch cycles per mcycle (deterministic counts) of a control guest (cheapest instructions,
--     about Dave's average density) and of dense guests (sfence.vma in S-mode; fdiv.d in U-mode);
--   * the host cost ratio R = (build cost per mcycle of the dense guest) / (same for the control), both measured in
--     the same run, interleaved, so that the host speed cancels out.
-- It projects the build of one 2^18-mcycle leaf of the dense guest on Dave's own reference host:
--     projected = R * (D_ctrl / D_ref) * 2^18 / rate_ref        (no hardware slack at all: most lenient)
-- and asserts projected <= COMMITMENT_BUDGET for both dense guests. On audit/prt2 the sfence.vma (S-mode) leaf
-- projects to about 12 h (6x the budget) and the fdiv.d (U-mode) leaf to about 3 h, with zero hardware slack (twice
-- that with the deployment's own slack 2), so the test exits 1. It exits 0 once the clocks (or strides) are sized
-- for the worst-case density.

local harness = require("harness")

local function sh_ok(cmd)
    local ok = os.execute(cmd)
    return ok == true or ok == 0
end

local function read(path)
    local f = io.open(path, "rb")
    if not f then harness.setup_error("cannot read " .. path) end
    local s = f:read("a")
    f:close()
    return s
end

harness.main(function()
    local cartesi = require("cartesi")
    local HARNESS = os.getenv("HARNESS") or harness.setup_error("HARNESS not set (run through bugs/run.sh)")
    local DAVE = (os.getenv("HARNESS_WORK") or (HARNESS .. "/work")) .. "/dave/released"

    -- 1. Released deployment constants
    local consts = read(DAVE .. "/prt/contracts/src/arbitration-config/ArbitrationConstants.sol")
    local budget_min = tonumber(consts:match("COMMITMENT_BUDGET%s*=%s*(%d+)%s*minutes"))
    local s0, s1 = consts:match("function log2step.-%[%s*uint64%((%d+)%)%s*,%s*uint64%((%d+)%)%s*%]")
    local clocks = read(DAVE .. "/prt/contracts/src/arbitration-config/ClockBudgets.sol")
    local cmd_md = read(DAVE .. "/docs/measurements/constants.md")
    local rate_ref = tonumber(cmd_md:match("leaf build rate%)%s*|%s*(%d+)/s"))
    local dens_ref = tonumber(cmd_md:match("density label%)%s*|%s*([%d%.]+)"))
    local hw_slack = tonumber(cmd_md:match("hardware slack (%d+)"))
    if not (budget_min and s0 and s1 and rate_ref and dens_ref and hw_slack) then
        harness.setup_error("cannot parse the released Dave constants")
    end
    if not clocks:find("joining an inner tournament first takes `commitment` seconds", 1, true) then
        harness.setup_error("ClockBudgets.sol no longer states the commitment-build model this test relies on")
    end
    local budget_s = budget_min * 60
    local log2_u = cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE
    local leaf_mcycles = 1 << (tonumber(s0) - tonumber(s1) - log2_u)
    local ref_avg_build_s = leaf_mcycles / rate_ref
    print(string.format("Dave released: COMMITMENT_BUDGET %d min, log2step [%s, %s] -> one leaf = 2^%d mcycles",
        budget_min, s0, s1, tonumber(s0) - tonumber(s1) - log2_u))
    print(string.format("Dave reference: %d mcycles/s at %.1f usteps/mcycle (hardware slack %d) -> average-density "
        .. "leaf build %.0f s (%.2f h), %.0f s with slack", rate_ref, dens_ref, hw_slack, ref_avg_build_s,
        ref_avg_build_s / 3600, ref_avg_build_s * hw_slack))

    -- 2. Build the guests
    local tmp = io.popen("mktemp -d"):read("l")
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local guests = { "ctrl", "sfence", "fdiv" }
    for _, g in ipairs(guests) do
        if not sh_ok(string.format("'%s/baremetal/build.sh' -o '%s/%s.bin' guests/%s.S > '%s/build.log' 2>&1",
                HARNESS, tmp, g, g, tmp)) then
            local log = read(tmp .. "/build.log")
            cleanup()
            harness.setup_error("guest build failed: " .. g .. "\n" .. log)
        end
    end

    local START = 200 -- past the M-mode prologue, inside the loop
    local expected_prv = { ctrl = 0, fdiv = 0, sfence = 1 }
    local function new_machine(g)
        local m = cartesi.machine({ ram = { length = 64 << 20,
            backing_store = { data_filename = tmp .. "/" .. g .. ".bin" } } })
        m:run(START)
        if m:read_reg("mcycle") ~= START or m:read_reg("iprv") ~= expected_prv[g] or m:read_reg("iflags_H") ~= 0 then
            error("guest " .. g .. " did not reach its loop in the expected privilege level")
        end
        return m
    end

    -- 3. Deterministic density: uarch cycles executed per mcycle (what the uarch-level claim hashes)
    local N = 64
    local dens = {}
    for _, g in ipairs(guests) do
        local m <close> = new_machine(g)
        local tot = 0
        for _ = 1, N do
            local br = m:run_uarch(cartesi.UARCH_CYCLE_MAX)
            if br ~= cartesi.UARCH_BREAK_REASON_UARCH_HALTED then error("uarch did not halt in guest " .. g) end
            tot = tot + m:read_reg("uarch_cycle")
            m:reset_uarch()
        end
        dens[g] = tot / N
    end

    -- 4. Host cost of the honest uarch-level claim builder, interleaved rounds (host speed cancels in the ratio)
    local per_round = { ctrl = 64, sfence = 6, fdiv = 16 }
    local cpu, mc = {}, {}
    local machines = {}
    for _, g in ipairs(guests) do
        machines[g] = new_machine(g)
        cpu[g], mc[g] = 0, 0
    end
    local zero = string.rep("\0", 32)
    for _ = 1, 5 do
        for _, g in ipairs(guests) do
            local m = machines[g]
            local target = m:read_reg("mcycle") + per_round[g]
            local t0 = os.clock()
            local r = m:collect_uarch_cycle_root_hashes(target, log2_u, { zero, m:read_revert_root_hash() })
            cpu[g] = cpu[g] + (os.clock() - t0)
            if #r.hashes == 0 or m:read_reg("mcycle") ~= target then error("collect did not run for " .. g) end
            mc[g] = mc[g] + per_round[g]
        end
    end
    machines = nil
    collectgarbage()
    cleanup()

    local cost = {}
    for _, g in ipairs(guests) do cost[g] = cpu[g] / mc[g] end
    local function project(g)
        local R = cost[g] / cost.ctrl
        -- the control is slightly cheaper than Dave's 566-density workload; scale R down by the density ratio
        local adj = math.min(1, dens.ctrl / dens_ref)
        return R, R * adj * ref_avg_build_s
    end
    print(string.format("%-7s %10s %10s %12s %14s %14s %14s", "guest", "usteps/mc", "ratio(cnt)", "ms/mc(host)",
        "ratio(host)", "leaf h slack1", "leaf h slack" .. hw_slack))
    for _, g in ipairs(guests) do
        local R, p = project(g)
        print(string.format("%-7s %10.0f %10.2f %12.2f %14.2f %14.2f %14.2f", g, dens[g], dens[g] / dens_ref,
            cost[g] * 1000, R, p / 3600, p * hw_slack / 3600))
    end
    print(string.format("budget: %.2f h (COMMITMENT_BUDGET)", budget_s / 3600))

    if dens.sfence < 4 * dens_ref or dens.fdiv < 4 * dens_ref then
        error("dense guests are not dense; harness changed?")
    end
    local function check(g, what)
        local R, p = project(g)
        return harness.expect(p <= budget_s, string.format(
            "A7/R12: honest uarch-level claim over one 2^%d-mcycle leaf of a guest running %s (%.0f usteps/mcycle, "
                .. "host cost x%.1f the control) projects to %.2f h on Dave's own reference host with NO hardware "
                .. "slack (%.2f h with its slack %d); the deployment sized the build for COMMITMENT_BUDGET = %.2f h "
                .. "at average density %.0f usteps/mcycle",
            tonumber(s0) - tonumber(s1) - log2_u, what, dens[g], R, p / 3600, p * hw_slack / 3600, hw_slack,
            budget_s / 3600, dens_ref))
    end
    -- The S-mode sfence.vma guest decides the verdict with a wide margin (about 6x over budget on audit/prt2);
    -- the U-mode fdiv guest (no privilege needed) is checked too (about 1.5x over budget with no slack).
    local ok_sfence = check("sfence", "sfence.vma in S-mode")
    local ok_fdiv = check("fdiv", "fdiv.d in U-mode")
    return ok_sfence and ok_fdiv
end)
