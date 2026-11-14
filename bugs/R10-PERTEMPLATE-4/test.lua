-- R10-PERTEMPLATE-4: config.json of a stored machine is outside the hashed state, and the loader reads it whole and
-- parses it into a full nlohmann::json DOM, silently ignoring members it does not know. Whoever hands the operator a
-- template directory can therefore pad config.json with an unknown member (here a long array of zeros, which
-- compresses to almost nothing) and choose how much memory the honest operator spends adopting it, although the
-- hashed contents are exactly those of a valid template. machine::clone_stored then copies the padded file byte for
-- byte into every clone (the PRT player clones for every snapshot it keeps), so every later load pays again.
--
-- The test copies the harness's stored bare-metal template (64 MiB RAM, waiting at a manual yield with the accepted
-- reason, root in root-hash.txt) as the control, and makes copies whose ONLY difference is an extra top-level member
-- "x-padding" in config.json, of PAD_SMALL and PAD_BIG bytes. Each copy is adopted as O1 requires (load without
-- sharing, clear_hash_tree = true, get_root_hash) in its own child process, which reports its peak resident memory.
--
-- Required (R12: loading a machine has a worst case in host memory that is bounded and at most linear in the bytes
-- it covers; section 8: once a snapshot meets the valid-template conditions, nothing it carries outside the hashed
-- state may crash the honest operator; section 2: obtaining its valid template is on the honest operator's path):
-- the padded copy is adopted, with the control's root hash, at a peak memory bounded by the machine itself: at most
-- the larger of RATIO_LIMIT times the control's and the control's plus twice the bytes of all its address ranges.
-- Otherwise exit 1.
local harness = require("harness")

local MiB = 1024 * 1024
local PAD_BIG = (tonumber(os.getenv("R10PT4_PAD_MIB") or "") or 64) * MiB
local PAD_SMALL = PAD_BIG // 4
local RATIO_LIMIT = 2.0

harness.main(function()
    local cfgdir = harness.config_dir("baremetal-template")
    local src = cfgdir .. "/machine"
    local f = io.open(src .. "/config.json", "rb")
    if not f then harness.setup_error("missing " .. src .. " (run bugs/harness/configs/make-configs.sh)") end
    f:close()
    local expected_root = harness.read_file(cfgdir .. "/root-hash.txt"):gsub("%s", ""):gsub("^0x", ""):lower()

    local ok, tmp = harness.sh("mktemp -d -t r10-pertemplate-4.XXXXXX")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local function die(msg)
        cleanup()
        harness.setup_error(msg)
    end
    local function sh_or_die(cmd)
        local okc, out = harness.sh(cmd .. " 2>&1")
        if not okc then die("command failed: " .. cmd .. "\n" .. out) end
        return out
    end
    local function fsize(path) return tonumber((sh_or_die(string.format("stat -c %%s '%s'", path)):match("%d+"))) end

    local child = os.getenv("REPO") .. "/bugs/R10-PERTEMPLATE-4/child.lua"
    local function run_child(mode, dir, to)
        local okc, out = harness.sh(string.format("lua5.4 '%s' %s '%s' '%s' 2>&1", child, mode, dir, to or ""))
        local root, hwm, cpu = out:match("OK (%S+) (%d+) ([%d%.]+)")
        if root then return { root = root, hwm = tonumber(hwm), cpu = tonumber(cpu) } end
        local msg = out:match("LOADFAIL ([^\n]*)")
        if msg then return { fail = msg } end
        return { fail = "child process died: " .. tostring(okc) .. " " .. out }
    end

    local control = tmp .. "/control"
    sh_or_die(string.format("cp -a --sparse=always '%s' '%s'", src, control))
    local cfg = harness.read_file(control .. "/config.json")
    if cfg:sub(1, 1) ~= "{" then die("config.json does not start with '{'") end

    -- copy of the control whose config.json carries an extra, unknown top-level member of about pad bytes
    local function craft(pad)
        local dir = string.format("%s/pad-%d", tmp, pad)
        sh_or_die(string.format("cp -a --sparse=always '%s' '%s'", src, dir))
        local out = assert(io.open(dir .. "/config.json", "wb"))
        out:write('{"x-padding":[0')
        local chunk = string.rep(",0", MiB // 2) -- 1 MiB
        for _ = 1, pad // MiB do
            out:write(chunk)
        end
        out:write("],", cfg:sub(2))
        out:close()
        return dir
    end

    -- bytes the machine covers (all its address ranges)
    local machine_bytes = 0
    do
        local cartesi = require("cartesi")
        local okm, m = pcall(cartesi.machine, control, {}, cartesi.SHARING_NONE)
        if not okm then die("cannot load control: " .. tostring(m)) end
        for _, ar in ipairs(m:get_address_ranges()) do
            machine_bytes = machine_bytes + ar.length
        end
        m:destroy()
    end

    local ctl = run_child("adopt", control)
    if ctl.fail then die("control adoption failed: " .. ctl.fail) end
    if ctl.root ~= expected_root then die("control root " .. ctl.root .. " differs from root-hash.txt " .. expected_root) end
    print(string.format("machine covers %.1f MiB in its address ranges; control config.json %d bytes",
        machine_bytes / MiB, #cfg))
    print(string.format("control:            VmHWM=%8d kB cpu=%.2f s root=%s", ctl.hwm, ctl.cpu, ctl.root))

    local small_dir = craft(PAD_SMALL)
    local small_cfg = fsize(small_dir .. "/config.json")
    local small = run_child("adopt", small_dir)
    os.execute(string.format("rm -rf '%s'", small_dir))
    local big_dir = craft(PAD_BIG)
    local big_cfg = fsize(big_dir .. "/config.json")
    local big = run_child("adopt", big_dir)
    local gz = tonumber((sh_or_die(string.format("gzip -c '%s/config.json' | wc -c", big_dir)):match("%d+")))
    print(string.format("padded config.json of %d bytes compresses (gzip) to %d bytes", big_cfg, gz))
    for _, r in ipairs({ { small_cfg, small }, { big_cfg, big } }) do
        local n, res = r[1], r[2]
        if res.fail then
            print(string.format("padded config.json %10d bytes: adoption FAILED: %s", n, res.fail))
        else
            print(string.format("padded config.json %10d bytes: VmHWM=%8d kB cpu=%.2f s root=%s (%.2fx control)", n,
                res.hwm, res.cpu, res.root, res.hwm / ctl.hwm))
        end
    end
    if not small.fail and not big.fail then
        print(string.format("marginal peak memory: %.2f bytes per byte of unhashed padding (small->big)",
            (big.hwm - small.hwm) * 1024 / (big_cfg - small_cfg)))
    end

    -- propagation (information): what clone_stored and store write for the padded template
    local clone = run_child("clone", big_dir, tmp .. "/clone")
    if clone.fail then
        print("clone_stored of the padded template FAILED: " .. clone.fail)
    else
        print(string.format("clone_stored: VmHWM=%d kB; clone's config.json %d bytes (source %d bytes)", clone.hwm,
            fsize(tmp .. "/clone/config.json"), big_cfg))
        os.execute(string.format("rm -rf '%s/clone'", tmp))
    end
    local st = run_child("store", big_dir, tmp .. "/stored")
    if not st.fail then
        print(string.format("load+store normalizes it: stored config.json %d bytes", fsize(tmp .. "/stored/config.json")))
    end
    cleanup()

    if big.fail then
        return harness.expect(false, "O1/R4, section 8: the operator must be able to adopt a template whose hashed "
            .. "contents are valid, whatever unknown members its unhashed config.json carries (load failed: "
            .. big.fail .. ")")
    end
    if big.root ~= expected_root then
        return harness.expect(false, "R1: unhashed config.json padding changed the root hash: " .. big.root)
    end
    local limit_kb = math.max(RATIO_LIMIT * ctl.hwm, ctl.hwm + 2 * machine_bytes // 1024)
    print(string.format("allowed peak: %d kB (max of %.1fx control, control + 2 x %.1f MiB of address ranges)",
        limit_kb, RATIO_LIMIT, machine_bytes / MiB))
    return harness.expect(big.hwm <= limit_kb, string.format(
        "R12 (loading a machine is bounded and at most linear in the bytes it covers) and section 8 (nothing a "
            .. "snapshot that meets the valid-template conditions carries outside the hashed state may crash the "
            .. "honest operator): adopting the same contents with %d bytes of unknown members in config.json must "
            .. "cost at most %d kB of peak memory (bounded by the machine's own size); observed %d kB, %.2fx the "
            .. "control's %d kB",
        big_cfg - #cfg, limit_kb, big.hwm, big.hwm / ctl.hwm, ctl.hwm))
end)
