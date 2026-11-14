-- R1-R11-1: does MetaStep.step (machine-solidity-step v0.17.0-test1, regenerated from audit/prt2) map positions to
-- transition forms differently from the manual's referee (validate_state_transition_response) and Dave's
-- CartesiStateTransition?
--
-- The candidate called MetaStep with counter = index of the BEFORE-state (Dave's convention) and found that it
-- runs the uarch reset after uarch cycle 0 and refuses the honest closing step+reset. But the pinned MetaStep
-- documents its counter as "Number of meta-steps performed, counting this one ... Callers that instead number
-- transitions by their source state must pass counter as that number plus one" (byte-identical in released/,
-- regenerated/ and Dave's machine/step/src). So this test drives MetaStep with its DOCUMENTED convention,
-- counter = before-index + 1, and asserts what R3 requires of a referee verifier (StepVerifier.metaStep on a
-- private anvil, over the regenerated step):
--   * at uarch cycle 0 of an mcycle (ordinary step): the honest step log is accepted with the canonical after-hash
--     (native uarch step), and a step+reset log is rejected;
--   * at the last uarch cycle (step followed by reset): the honest step+reset log is accepted with the canonical
--     after-hash (native step + reset), and a step-only log is rejected;
--   * the same at the next uarch span (counters SPAN+1 and 2*SPAN).
-- The candidate's own observations (wrong convention) are printed as INFO lines and not asserted. MetaStep has no
-- input-delivery path by design (it takes no input parameters); the delivery form is a separate verifier path
-- (SendCmioResponse then UArchStep), so the candidate's step-only-at-input observation is also INFO only.
--
-- Exit 0: MetaStep agrees with the manual's form map under its documented counter convention (candidate refuted).
-- Exit 1: some accepted log yields a non-canonical after-hash, or an honest log is refused. Exit 2: setup error.
local harness = require("harness")
local cartesi = require("cartesi")
local evm = require("evm_step")

local SPAN = 1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE

local function sh(cmd)
    local p = assert(io.popen(cmd, "r"))
    local out = p:read("a")
    p:close()
    return out
end

-- private anvil with the StepVerifier runtime code built by the shared EVM harness (not the harness's 8546 anvil)
local function start_anvil()
    local artifact = harness.WORK .. "/evm/out/StepVerifier.sol/StepVerifier.json"
    local f = io.open(artifact, "rb")
    if not f then harness.setup_error("missing " .. artifact .. " (run bugs/harness/solidity-step/evm/start.sh once)") end
    f:close()
    local code = sh(string.format("jq -r .deployedBytecode.object %q", artifact)):gsub("%s", "")
    if not code:match("^0x[0-9a-fA-F]+$") or #code < 1000 then harness.setup_error("bad StepVerifier artifact") end
    math.randomseed(os.time() ~ tonumber(tostring({}):match("0x(%x+)"), 16))
    for _ = 1, 20 do
        local port = 30000 + math.random(0, 9999)
        local rpc = "http://127.0.0.1:" .. port
        if sh("cast block-number --rpc-url " .. rpc .. " 2>/dev/null"):match("%d") == nil then
            local pid = sh(string.format(
                "nohup anvil --port %d --hardfork prague --code-size-limit 4000000 --disable-block-gas-limit " ..
                "--silent > /dev/null 2>&1 & echo $!", port)):match("%d+")
            local up = false
            for _ = 1, 100 do
                if sh("cast block-number --rpc-url " .. rpc .. " 2>/dev/null"):match("%d") then up = true; break end
                sh("sleep 0.1")
            end
            if up then
                local addr = "0x00000000000000000000000000000000005e1f00"
                local codef = os.tmpname()
                local cf = assert(io.open(codef, "w"))
                cf:write(string.format('{"jsonrpc":"2.0","id":1,"method":"anvil_setCode","params":["%s","%s"]}',
                    addr, code))
                cf:close()
                sh(string.format("curl -sS --noproxy '*' -H 'Content-Type: application/json' --data-binary @%s %s",
                    codef, rpc))
                os.remove(codef)
                return pid, rpc, addr
            end
            if pid then os.execute("kill " .. pid .. " 2>/dev/null") end
        end
    end
    harness.setup_error("could not start a private anvil")
end

local function h(x) return x and evm.hex(x):sub(1, 18) or "nil" end

local function run(e)
    local failures = 0
    local function check(cond, what)
        print((cond and "ok   " or "FAIL ") .. what)
        if not cond then failures = failures + 1 end
    end
    local function accepted(label, counter, expected, ok, r)
        check(ok and r == expected, string.format("%s: metaStep(counter=%d) accepted with canonical %s (got %s %s)",
            label, counter, h(expected), tostring(ok), ok and h(r) or tostring(r)))
    end
    local function rejected(label, counter, ok, r)
        check(not ok, string.format("%s: metaStep(counter=%d) rejected (got %s %s)",
            label, counter, tostring(ok), ok and h(r) or tostring(r)))
    end

    -- the evm verifier must work at all (sanity: plain step on the same harness)
    local cfg = harness.config_dir("baremetal-minimal") .. "/machine"

    -- (A) ordinary step at uarch cycle 0 (before-index 0 => MetaStep counter 1), and at the next span (SPAN+1)
    do
        local m <close> = harness.machine(cfg)
        if m:read_reg("uarch_cycle") ~= 0 then harness.setup_error("baremetal-minimal not at uarch cycle 0") end
        local before = m:get_root_hash()
        local step_log = m:log_step_uarch()
        local canonical = m:get_root_hash()
        local reset_log = m:log_reset_uarch()
        local after_reset = m:get_root_hash()
        local okp, rp = e:step(before, step_log)
        if not (okp and rp == canonical) then harness.setup_error("EVM StepVerifier.step does not verify an honest step") end
        for _, c in ipairs({ 1, SPAN + 1 }) do
            accepted("ordinary step", c, canonical, e:meta_step(before, c, step_log))
            rejected("ordinary step, step+reset log", c, e:meta_step(before, c, step_log, reset_log))
        end
        -- candidate's observation, with counter = before-index (convention MetaStep's docs exclude)
        local ok0, r0 = e:meta_step(before, 0, step_log, reset_log)
        print(string.format("INFO counter=0 (not a meta-step count) step+reset: %s %s (step+reset hash %s)",
            tostring(ok0), ok0 and h(r0) or tostring(r0), h(after_reset)))
    end

    -- (B) closing step+reset at the last uarch cycle (before-index SPAN-1 => MetaStep counter SPAN), and 2*SPAN
    do
        local m <close> = harness.machine(cfg)
        m:run_uarch(cartesi.UARCH_CYCLE_MAX)
        local before = m:get_root_hash()
        local step_log = m:log_step_uarch()
        local after_step = m:get_root_hash()
        local reset_log = m:log_reset_uarch()
        local canonical = m:get_root_hash()
        -- native control: the same position verified with the separate step+reset path
        local okc, rc = e:step_then_reset(before, step_log, reset_log)
        if not (okc and rc == canonical) then harness.setup_error("EVM stepThenReset does not verify an honest step+reset") end
        for _, c in ipairs({ SPAN, 2 * SPAN }) do
            accepted("closing step+reset", c, canonical, e:meta_step(before, c, step_log, reset_log))
            rejected("closing, step-only log", c, e:meta_step(before, c, step_log))
        end
        local okd, rd = e:meta_step(before, SPAN - 1, step_log, reset_log)
        print(string.format("INFO counter=SPAN-1 (before-index convention) honest step+reset: %s %s",
            tostring(okd), okd and h(rd) or tostring(rd)))
        print(string.format("INFO step-only hash at that position would be %s", h(after_step)))
    end

    return harness.expect(failures == 0,
        "R3: every log the verifier accepts yields the canonical after-hash, and the honest log of the transition " ..
        "form at the position verifies (MetaStep driven with its documented counter = meta-steps counting this one); " ..
        failures .. " failure(s)")
end

harness.main(function()
    local pid, rpc, addr = start_anvil()
    local e = evm.connect(rpc, addr)
    local ok, res = pcall(run, e)
    os.remove(e.tmp)
    os.execute("kill " .. pid .. " 2>/dev/null")
    if not ok then error(res, 0) end
    return res
end)
