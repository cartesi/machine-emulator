-- R1-O1-2: the page hash-tree cache capacity hash_tree.phtc_size of a stored machine comes from its config.json,
-- which is outside the hashed state and survives the O1 rebuild (clear_hash_tree). Whoever hands the operator the
-- template directory therefore chooses the memory (and time) the honest operator spends adopting it, independent
-- of the machine's contents.
--
-- The test copies the harness's stored bare-metal template (64 MiB RAM, waiting at a manual yield with the accepted
-- reason, stored with the default phtc_size 4096), and makes a second copy whose ONLY difference is
-- config.json hash_tree.phtc_size = BIG (much larger than the number of pages in the whole machine) with a sparse
-- hash_tree.phtc of the matching length (no data, no disk cost). Both copies have the same hashed contents.
-- Each copy is adopted as O1 requires (load without sharing, clear_hash_tree = true) in its own child process,
-- which reports the root hash and its peak resident memory (VmHWM).
--
-- Required (R12, section 4/8): loading a machine costs at most linear in the bytes it covers, and nothing a snapshot
-- carries outside the hashed state may crash the honest operator. Same contents => the adoption must cost about
-- the same. The test fails (exit 1) when the crafted copy needs more peak memory than the larger of RATIO_LIMIT times
-- the control's and the control's plus a cache covering every page of the machine (or cannot be adopted, or yields
-- a different root).
local harness = require("harness")

local BIG = tonumber(os.getenv("R1O12_BIG") or "") or 65536 -- phtc entries in the crafted copy
local MID = BIG // 4 -- second point, to show the cost is linear in phtc_size
local RATIO_LIMIT = 2.0

harness.main(function()
    local src = harness.config_dir("baremetal-template") .. "/machine"
    local f = io.open(src .. "/config.json", "rb")
    if not f then harness.setup_error("missing " .. src .. " (run bugs/harness/configs/make-configs.sh)") end
    f:close()
    local expected_root = harness.read_file(harness.config_dir("baremetal-template") .. "/root-hash.txt")
        :gsub("%s", ""):gsub("^0x", ""):lower()

    local ok, tmp = harness.sh("mktemp -d -t r1-o1-2.XXXXXX")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end

    local function sh_or_die(cmd)
        local okc, out = harness.sh(cmd .. " 2>&1")
        if not okc then
            cleanup()
            harness.setup_error("command failed: " .. cmd .. "\n" .. out)
        end
        return out
    end

    -- storage length of hash_tree.phtc for n entries: header + n metadata, page aligned, + n payloads (12 KiB each)
    local function phtc_length(n) return ((8 + 24 + n * 32 + 4095) // 4096) * 4096 + n * 12288 end

    local control = tmp .. "/control"
    sh_or_die(string.format("cp -a --sparse=always '%s' '%s'", src, control))
    local cfg = harness.read_file(control .. "/config.json")
    local stored_n = tonumber(cfg:match('"phtc_size"%s*:%s*(%d+)'))
    if not stored_n then cleanup() harness.setup_error("no phtc_size in config.json") end
    -- validate the length formula against the file the emulator itself wrote
    local real_len = tonumber(sh_or_die(string.format("stat -c %%s '%s/hash_tree.phtc'", control)))
    if real_len ~= phtc_length(stored_n) then
        cleanup()
        harness.setup_error(string.format("phtc length formula mismatch: %d vs %d", real_len, phtc_length(stored_n)))
    end

    -- make a copy that differs from the control only in cached hash-tree data / unhashed config
    local function craft(n)
        local dir = string.format("%s/phtc-%d", tmp, n)
        sh_or_die(string.format("cp -a --sparse=always '%s' '%s'", src, dir))
        local new_cfg, count = cfg:gsub('("phtc_size"%s*:%s*)%d+', "%1" .. n)
        if count ~= 1 then cleanup() harness.setup_error("cannot edit phtc_size") end
        local out = assert(io.open(dir .. "/config.json", "wb"))
        out:write(new_cfg)
        out:close()
        sh_or_die(string.format("rm -f '%s/hash_tree.phtc' && truncate -s %d '%s/hash_tree.phtc'", dir, phtc_length(n),
            dir))
        return dir
    end

    local child = os.getenv("REPO") .. "/bugs/R1-O1-2/child.lua"
    local function adopt(dir)
        local okc, out = harness.sh(string.format("lua5.4 '%s' '%s' 2>&1", child, dir))
        local root, hwm, cpu, n = out:match("OK (%x+) (%d+) ([%d%.]+) (%d+)")
        if root then
            return { root = root, hwm = tonumber(hwm), cpu = tonumber(cpu), n = tonumber(n) }
        end
        local msg = out:match("LOADFAIL ([^\n]*)")
        if msg then return { fail = msg } end
        return { fail = "child process died: " .. tostring(okc) .. " " .. out }
    end

    -- pages the machine actually covers (all address ranges)
    local pages = 0
    do
        local cartesi = require("cartesi")
        local okm, m = pcall(cartesi.machine, control, {}, cartesi.SHARING_NONE)
        if not okm then cleanup() harness.setup_error("cannot load control: " .. tostring(m)) end
        for _, ar in ipairs(m:get_address_ranges()) do
            pages = pages + (ar.length + 4095) // 4096
        end
        m:destroy()
    end

    local ctl = adopt(control)
    if ctl.fail then
        cleanup()
        harness.setup_error("control adoption failed: " .. ctl.fail)
    end
    if ctl.root ~= expected_root then
        cleanup()
        harness.setup_error("control root " .. ctl.root .. " differs from root-hash.txt " .. expected_root)
    end
    print(string.format("machine covers %d pages (%.1f MiB)", pages, pages * 4096 / 2 ^ 20))
    print(string.format("control: phtc_size=%-6d VmHWM=%7d kB cpu=%.2f s root=%s", ctl.n, ctl.hwm, ctl.cpu, ctl.root))

    local mid = adopt(craft(MID))
    os.execute(string.format("rm -rf '%s/phtc-%d'", tmp, MID))
    local big = adopt(craft(BIG))
    cleanup()

    for _, r in ipairs({ { MID, mid }, { BIG, big } }) do
        local n, res = r[1], r[2]
        if res.fail then
            print(string.format("crafted phtc_size=%d: adoption FAILED: %s", n, res.fail))
        else
            print(string.format("crafted: phtc_size=%-6d VmHWM=%7d kB cpu=%.2f s root=%s  (%.2fx control memory)",
                res.n, res.hwm, res.cpu, res.root, res.hwm / ctl.hwm))
        end
    end
    if not mid.fail and not big.fail then
        print(string.format("marginal cost: %.1f kB of peak resident memory per phtc entry (MID->BIG)",
            (big.hwm - mid.hwm) / (BIG - MID)))
        print(string.format("phtc_size survives clear_hash_tree: stored %d entries -> loaded %d", BIG, big.n))
    end

    if big.fail then
        return harness.expect(false, "O1/R4: the operator must be able to adopt a template whose hashed contents are "
            .. "valid, whatever unhashed cached hash-tree configuration it carries (load failed: " .. big.fail .. ")")
    end
    if big.root ~= expected_root then
        return harness.expect(false, "R1/R9: unhashed phtc_size changed the root hash: " .. big.root)
    end
    -- Allowed: at most RATIO_LIMIT x the control, or the control plus a page cache that covers every page of the
    -- machine (12 KiB of payload per page), whichever is larger. A fix that clamps the stored capacity to the
    -- machine's own size (bounded by the hashed contents) therefore passes; a cost set by phtc_size alone does not.
    local limit_kb = math.max(RATIO_LIMIT * ctl.hwm, ctl.hwm + pages * 12288 // 1024)
    print(string.format("allowed peak: %d kB (max of %.1fx control, control + %d pages x 12 KiB)", limit_kb,
        RATIO_LIMIT, pages))
    return harness.expect(big.hwm <= limit_kb, string.format(
        "R12 (loading a machine is bounded and at most linear in the bytes it covers) and section 4/8 (nothing a "
            .. "snapshot carries outside the hashed state may crash the honest operator): adopting the same "
            .. "contents with config.json phtc_size=%d (machine has %d pages) must cost at most %d kB of peak memory "
            .. "(bounded by the machine's size); observed %d kB, %.2fx the control's %d kB",
        BIG, pages, limit_kb, big.hwm, big.hwm / ctl.hwm, ctl.hwm))
end)
