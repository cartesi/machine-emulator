-- R1-R14-1: guest console output multiplies the cost of mcycle hash collection when the console output is to_buffer.
--
-- A guest stores 100000 HTIF console putchar('\n') back to back (about one per mcycle, 106259 mcycles in all) and
-- halts. Each case runs in a child process (child.lua) on a fresh machine, with the PRT recipe geometry (sampling
-- period 2^10 mcycles, bundles of 2^4 samples), and reports its process CPU time for the collection only.
--
--   roots-*   honest-operator loop over collect_mcycle_root_hashes, resuming after each console-output break and
--             draining the buffer (read_console_output) when it is to_buffer;
--   bundle-*  collect_mcycle_bundle(0, 10, 4) repeated until the halt.
--
-- Control (same run, same guest, same hashes): console to_file /dev/null with every_line, where the interpreter
-- also stops at every one of the 100000 newlines to flush, but the flush happens inside the collection call.
-- Requirement (THREAT_MODEL R12, section 8 High case): the cost of "a part of a claim" is at most linear in the
-- cycles it executes, and the guest must not multiply it by a constant factor; console output is not part of
-- the specified semantics (R14: output to the host must not affect the state). The test asserts:
--   1. every case collects the same hashes and reaches the same final root hash (R14, R2);
--   2. CPU(to_buffer) <= FACTOR * CPU(to_file control), for both collection paths (R12).
local harness = require("harness")

local FACTOR = 10 -- wide margin: about 1x expected without the defect; >100x observed on audit/prt2
local CONTROL_REPEATS = 3

harness.main(function()
    local tmp = os.getenv("R1_R14_1_TMP")
    local own_tmp = false
    if not tmp then
        local ok, out = harness.sh("mktemp -d")
        if not ok then harness.setup_error("mktemp failed") end
        tmp, own_tmp = out:gsub("%s+$", ""), true
    end
    local function cleanup()
        if own_tmp then os.execute("rm -rf '" .. tmp .. "'") end
    end

    local guest = tmp .. "/guest.bin"
    local ok = os.execute(string.format("'%s/baremetal/build.sh' -o '%s' guest.S > '%s/build.log' 2>&1",
        os.getenv("HARNESS"), guest, tmp))
    if not ok then
        io.stderr:write(harness.read_file(tmp .. "/build.log"))
        cleanup()
        harness.setup_error("cannot build the bare-metal guest")
    end

    -- Runs one case in a child; returns the parsed result line and the number of buffer-overflow warnings
    -- the child wrote to stderr (counted, not stored: it can be ~100k lines)
    local function run_case(case)
        local out, err = tmp .. "/" .. case .. ".out", tmp .. "/" .. case .. ".err"
        local cmd = string.format("lua5.4 child.lua '%s' %s 2>&1 > '%s' | " ..
                "awk '/^WARNING: console output buffer is out of space/ { n++; next } { print > \"%s\" } " ..
                "END { print n + 0 }'", guest, case, out, err)
        local _, warnings = harness.sh(cmd)
        local line = harness.read_file(out)
        local r = {}
        r.cpu = tonumber(line:match("cpu=([%d%.]+)"))
        r.mcycle = tonumber(line:match("mcycle=(%d+)"))
        r.calls = tonumber(line:match("calls=(%d+)"))
        r.hashes = line:match("hashes=(0x%x+)")
        r.final = line:match("final=(0x%x+)")
        r.warnings = tonumber(warnings) or -1
        if not (r.cpu and r.mcycle and r.hashes and r.final) then
            local f = io.open(err, "rb")
            io.stderr:write(f and f:read("a") or "", "\n")
            if f then f:close() end
            cleanup()
            harness.setup_error("child case " .. case .. " failed")
        end
        io.stderr:write(string.format("%-14s cpu=%8.4fs mcycle=%d calls=%d stderr_warnings=%d hashes=%s final=%s\n",
            case, r.cpu, r.mcycle, r.calls, r.warnings, r.hashes:sub(1, 18), r.final:sub(1, 18)))
        return r
    end
    local function control(case) -- slowest of several runs: the conservative choice for the bound
        local worst
        for _ = 1, CONTROL_REPEATS do
            local r = run_case(case)
            if not worst or r.cpu > worst.cpu then worst = r end
        end
        return worst
    end

    local res = {}
    res["roots-null"] = run_case("roots-null")
    res["roots-file"] = control("roots-file")
    res["roots-buffer"] = run_case("roots-buffer")
    -- information only: the same number of console-output breaks without hash collection (cost per break)
    res["run-buffer"] = run_case("run-buffer")
    res["bundle-null"] = run_case("bundle-null")
    res["bundle-file"] = control("bundle-file")
    res["bundle-buffer"] = run_case("bundle-buffer")
    cleanup()

    local pass = true
    -- 1. console output must not affect the state or the collected hashes
    local same = true
    for _, kind in ipairs({ "roots", "bundle" }) do
        local ref = res[kind .. "-null"]
        for _, c in ipairs({ "-file", "-buffer" }) do
            local r = res[kind .. c]
            same = same and r.hashes == ref.hashes and r.final == ref.final and r.mcycle == ref.mcycle
        end
    end
    same = same and res["roots-null"].final == res["bundle-null"].final
    pass = harness.expect(same, "R14/R2: collected hashes and final root hash do not depend on the console") and pass

    -- 2. guest console output must not multiply the collection cost (to_buffer vs. a control with as many flushes)
    for _, kind in ipairs({ "roots", "bundle" }) do
        local b, f = res[kind .. "-buffer"], res[kind .. "-file"]
        local ratio = b.cpu / math.max(f.cpu, 1e-6)
        local fn = kind == "roots" and "collect_mcycle_root_hashes" or "collect_mcycle_bundle"
        pass = harness.expect(b.cpu <= FACTOR * f.cpu, string.format(
            "R12/section 8: %s with a to_buffer console costs %.1fx the same collection with the to_file " ..
            "control (%.3fs vs %.3fs for %d mcycles, %d collection calls, %d stderr warnings); bound %dx",
            fn, ratio, b.cpu, f.cpu, b.mcycle, b.calls, b.warnings, FACTOR)) and pass
    end
    return pass
end)
