#!/usr/bin/env lua5.4
-- R14-INVLOGS-1: the uarch-cycle computation-hash builder throws when the uarch halts on the very step that brings
-- its cycle count to UARCH_CYCLE_MAX (2^20-1), although R4 allows exactly that ("halts no later than the uarch step
-- that brings its cycle count to the last uarch position of the mcycle") and every verifier accepts the mcycle.
--
-- uarch_step (src/uarch-step.cpp) checks `cycle >= UARCH_CYCLE_MAX` before the halt check after executing an
-- instruction, so the halting ECALL executed at cycle MAX-1 is reported as UArchCycleOverflow. uarch_interpret
-- forwards it as uarch_cycle_overflow, and collect_uarch_cycle_root_hashes (src/machine.cpp) throws "uarch reached its
-- maximum cycle ..." without looking at uarch_halt. collect_uarch_cycle_bundle, which the honest player
-- (doc/recipes/prt.lua) uses to answer uarch bisections, calls it and fails too.
--
-- The uarch program halt.S (built at test time) increments mcycle, as one interpreted main-processor step would, and
-- runs exactly 2^20-1 instructions, halting on the last one. It is loaded through the uarch RAM config, a deliberate
-- host change used only to reach the code path (the pristine uarch is not known to have a main-processor instruction
-- that takes 2^20-1 uarch cycles; see the finding for reachability).
--
-- The test checks:
--   (1) harness sanity: the uarch halts exactly on the step to cycle MAX; that step's log verifies (R2/R3), the next
--       step is a verified no-op (R5), and the closing reset verifies. So the mcycle is fully defined for the referee.
--   (2) correct behavior: on a fresh identical machine, collect_uarch_cycle_bundle for the last bundle of the mcycle
--       succeeds and holds, at its last leaves, the state after cycle MAX-1 and the halted state after cycle MAX, i.e.
--       the builder agrees with the step verifier (R2, R4). The reset leaf is not compared: with a non-pristine uarch
--       RAM, reset_uarch rewrites the embedded pristine image while the builder only restores the words the uarch
--       dirtied, so those differ by construction of the host change, not because of this defect.
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local MAX = cartesi.UARCH_CYCLE_MAX
assert(MAX == (1 << 20) - 1, "harness error: unexpected UARCH_CYCLE_MAX")
local LOG2_BUNDLE = 10
local LAST_BUNDLE = (1 << (cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE - LOG2_BUNDLE)) - 1

local tmp = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
local _ <close> = setmetatable({}, {
    __close = function()
        os.execute("rm -rf '" .. tmp .. "'")
    end,
})
assert(os.execute("bash ./build.sh " .. tmp), "harness error: failed to build uarch program halt.bin")

local function new_machine()
    return cartesi.machine({
        ram = { length = 0x20000 },
        uarch = { ram = { length = 0x1000, backing_store = { data_filename = tmp .. "/halt.bin" } } },
    }, {})
end

local function hex(h)
    return (h:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

-- (1) What the referee sees for this mcycle.
local h0, h1
do
    local m <close> = new_machine()
    local br = m:run_uarch(MAX - 1)
    assert(
        br == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE
            and m:read_reg("uarch_cycle") == MAX - 1
            and m:read_reg("uarch_halt") == 0,
        "harness error: uarch program did not run to cycle MAX-1 without halting"
    )
    h0 = m:get_root_hash()
    local log1 = m:log_step_uarch()
    h1 = cartesi.machine:verify_step_uarch(h0, log1)
    assert(
        h1 == m:get_root_hash() and m:read_reg("uarch_cycle") == MAX and m:read_reg("uarch_halt") == 1,
        "harness error: the step to cycle MAX did not halt the uarch or did not verify"
    )
    local log2 = m:log_step_uarch()
    local h2 = cartesi.machine:verify_step_uarch(h1, log2)
    assert(h2 == h1 and h2 == m:get_root_hash(), "harness error: the step at cycle MAX is not a verified no-op")
    local log3 = m:log_reset_uarch()
    local h3 = cartesi.machine:verify_reset_uarch(h2, log3)
    assert(h3 == m:get_root_hash() and m:read_reg("uarch_cycle") == 0, "harness error: reset did not verify")
    print("verifiers: step to cycle MAX (halts) verifies, step at MAX is a verified no-op, reset verifies")
end

-- (2) What the honest operator's builder produces for the same mcycle.
local m <close> = new_machine()
local rr = m:read_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, 32)
local ok, res = pcall(m.collect_uarch_cycle_bundle, m, LAST_BUNDLE, LOG2_BUNDLE, { rr, rr })
if not ok then
    print(
        string.format(
            "FAIL: collect_uarch_cycle_bundle cannot build the uarch computation hash of an mcycle the verifiers fully "
                .. "accept (uarch halts on the step to cycle MAX): %s [machine left at uarch_cycle=%d uarch_halt=%d]",
            tostring(res),
            m:read_reg("uarch_cycle"),
            m:read_reg("uarch_halt")
        )
    )
    os.exit(1)
end
local n = #res
assert(n == 1 << LOG2_BUNDLE, "FAIL: last bundle has " .. n .. " leaves")
local function expect(i, want, what)
    if res[i] ~= want then
        print(string.format("FAIL: bundle leaf %d (%s) is %s, verifiers give %s", i, what, hex(res[i]), hex(want)))
        os.exit(1)
    end
end
expect(n - 2, h0, "state after uarch cycle MAX-1")
expect(n - 1, h1, "halted state after uarch cycle MAX")
if res[n] == h1 then
    print("FAIL: the last bundle leaf is the halted state, not the reset state")
    os.exit(1)
end
print("PASS: the uarch-cycle builder agrees with the verifiers when the uarch halts on the step to cycle MAX")
os.exit(0)
