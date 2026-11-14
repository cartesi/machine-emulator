-- bugs/R3-VARDIRTY-2: a host allocation failure inside a log producer leaves the machine half-way through the
-- logged transition (a state no transition produces), and a retry on the same machine diverges.
--
-- For each N = 1, 2, ..., a child process (child.lua) runs one logged transition on a fresh machine while the
-- N-th operator new request throws std::bad_alloc (nth-new.cpp, LD_PRELOAD). After a failed call the test
-- requires that the machine be at the before-state or at the after-state of a control run of the same
-- transition, never at a third state. The sweep stops a few N after the failures first leave the machine at the
-- after-state (the transition is then fully applied; later failures come from verification or result conversion).
local harness = require("harness")

harness.main(function()
    local here = os.getenv("PWD")
    local ok_tmp, out_tmp = harness.sh("mktemp -d \"${TMPDIR:-/tmp}/r3-vardirty-2.XXXXXX\"")
    local tmp = (out_tmp or ""):gsub("%s+$", "")
    if not ok_tmp or tmp == "" then harness.setup_error("cannot create temp dir") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local so = tmp .. "/nth-new.so"
    local okb, outb = harness.sh(string.format("g++ -O2 -shared -fPIC -o '%s' '%s/nth-new.cpp' 2>&1", so, here))
    if not okb then
        cleanup()
        harness.setup_error("cannot build nth-new.so: " .. outb)
    end

    local function run_child(op, n)
        local armf = string.format("%s/arm.%s.%d", tmp, op, n)
        local cntf = string.format("%s/count.%s.%d", tmp, op, n)
        local cmd = string.format("NTH=%d NTH_ARM_FILE='%s' NTH_COUNT_FILE='%s' LD_PRELOAD='%s' lua5.4 '%s/child.lua' %s 2>&1",
            n, armf, cntf, so, here, op)
        local _, out = harness.sh(cmd)
        os.remove(armf)
        local f = io.open(cntf, "r")
        local count, injected
        if f then
            count, injected = f:read("a"):match("(%d+) (%d)")
            f:close()
            os.remove(cntf)
        end
        local line = out:match("RESULT %S+ ([^\n]*)")
        local kind = line and line:match("^(%S+)") or "CRASH"
        return kind, line or out:gsub("\n", " "):sub(1, 300), tonumber(count), injected == "1"
    end

    local violations = {}
    local summary = {}
    for _, op in ipairs({ "step", "send" }) do
        -- calibration: no injection, count the requests made during the call
        local kind0, line0, total = run_child(op, 0)
        if kind0 ~= "OK" or not total then
            cleanup()
            harness.setup_error(op .. ": calibration run failed: " .. tostring(line0))
        end
        local kinds, first = {}, {}
        local after_transition, failures = 0, 0
        local n = 0
        while n < total and after_transition < 4 do
            n = n + 1
            local kind, line, _, injected = run_child(op, n)
            if kind ~= "OK" and kind ~= "CRASH" and not injected then
                cleanup()
                harness.setup_error(op .. " N=" .. n .. ": the call failed without an injected fault: " .. line)
            end
            kinds[#kinds + 1] = kind
            if not first[kind] then first[kind] = { n = n, line = line } end
            if kind ~= "OK" and kind ~= "CRASH" then failures = failures + 1 end
            if kind == "PARTIAL" then
                violations[#violations + 1] = { op = op, n = n, line = line }
            end
            if kind == "COMPLETE" or kind == "OK" or (kind == "CRASH" and first.COMPLETE) then
                after_transition = after_transition + 1
            end
        end
        if failures == 0 then
            cleanup()
            harness.setup_error(op .. ": no injected failure was observed")
        end
        -- compress the per-N kinds into ranges
        local ranges, s = {}, 1
        for i = 2, #kinds + 1 do
            if kinds[i] ~= kinds[s] then
                ranges[#ranges + 1] = string.format("N=%d..%d %s", s, i - 1, kinds[s])
                s = i
            end
        end
        summary[#summary + 1] = string.format("%s (calibration: %d requests while armed): %s", op, total,
            table.concat(ranges, ", "))
    end
    cleanup()

    for _, l in ipairs(summary) do print(l) end
    if #violations == 0 then
        print("every failed log call left the machine at the before-state or the after-state")
        return true
    end
    local shown = {}
    for _, v in ipairs(violations) do
        local key = v.op .. (v.line:match("state: (.-) mid_root") or "")
        if not shown[key] then
            shown[key] = true
            print(string.format("%s N=%d: %s", v.op, v.n, v.line))
        end
    end
    return harness.expect(false, "THREAT_MODEL section 4 / R4 / R9: a host allocation failure inside a log producer "
        .. "(log_step_uarch, log_send_cmio_response) must not leave the machine at a state that no transition "
        .. "produces (half-applied transition); the honest operator that keeps using the machine then computes a "
        .. "wrong hash or a log that does not verify from the canonical before-hash")
end)
