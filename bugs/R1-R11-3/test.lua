-- R1-R11-3: a stored keccak256 machine can be re-instantiated with hash_tree.hash_function = "sha256" while the
-- emulator reuses the hash-tree data (.sht/.phtc/.dht/.dpt) that was computed under keccak256. The resulting machine's
-- root hash, proofs and verify_hash_tree() are then inconsistent with its contents under sha256 (R9), and the manual
-- says a machine initialized for one hash function "can never be used" with the other.
--
-- Required (THREAT_MODEL R9, R11; manual "hash_tree" entry): creating that machine is refused, or the machine it
-- creates has the sha256 content hash of its contents (equal to the root of the same contents with the tree rebuilt
-- from scratch under sha256), proofs that match its contents, and a hash tree that verifies.
local harness = require("harness")

local function deep_copy(t)
    if type(t) ~= "table" then return t end
    local r = {}
    for k, v in pairs(t) do r[k] = deep_copy(v) end
    return r
end

-- Clear every cached hash-tree file name in a config, so the tree is rebuilt from the contents alone.
local function strip_tree_files(t)
    if type(t) ~= "table" then return end
    for k, v in pairs(t) do
        if k == "dht_filename" or k == "dpt_filename" or k == "sht_filename" or k == "phtc_filename" then
            t[k] = ""
        elseif type(v) == "table" then
            strip_tree_files(v)
        end
    end
end

-- raises (harness.main maps it to exit 2) so that the temporary directory is still removed
local function setup_fail(msg) error("setup error: " .. msg, 0) end

local function hx(s) return "0x" .. harness.hex(s) end

harness.main(function()
    local cartesi = require("cartesi")
    local ht = require("cartesi.hash-tree")

    local mk_ok, mk_out = harness.sh("mktemp -d")
    local tmp = (mk_out or ""):gsub("%s+$", "")
    if not mk_ok or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end

    local ok, res = xpcall(function()
        local RAM = cartesi.AR_RAM_START
        -- 1. A keccak256 machine (the default) with some non-zero RAM contents, stored by the emulator itself.
        do
            local m <close> = cartesi.machine({
                ram = { length = 1 << 16 },
                hash_tree = { hash_function = "keccak256" },
            }, {})
            for i = 0, 15 do
                m:write_memory(RAM + i * 4096 + 64 * i, string.rep(string.char(0x41 + i), 100 + i))
            end
            m:get_root_hash()
            m:store(tmp .. "/keccak")
        end

        local base <close> = cartesi.machine(tmp .. "/keccak", {})
        local cfg = base:get_initial_config()
        if cfg.hash_tree.hash_function ~= "keccak256" then setup_fail("stored machine is not keccak256") end
        if cfg.hash_tree.sht_filename == "" or cfg.ram.backing_store.dht_filename == "" then
            setup_fail("stored config does not reference its hash-tree files")
        end
        local keccak_root = base:get_root_hash()

        -- Control: under the stored function, reusing the stored tree files gives the same root as rebuilding them.
        do
            local c = deep_copy(cfg)
            strip_tree_files(c)
            local k2 <close> = cartesi.machine(c, {})
            if k2:get_root_hash() ~= keccak_root then
                setup_fail("control failed: rebuilt keccak256 tree differs from the stored one")
            end
        end

        -- Reference: the sha256 content hash of the same contents, tree rebuilt from the contents alone.
        local ref_cfg = deep_copy(cfg)
        ref_cfg.hash_tree.hash_function = "sha256"
        strip_tree_files(ref_cfg)
        local ref <close> = cartesi.machine(ref_cfg, {})
        local sha_root = ref:get_root_hash()
        if sha_root == keccak_root then setup_fail("sha256 and keccak256 roots coincide") end
        local page = ref:read_memory(RAM, 4096)
        if ref:get_proof(RAM, 12).target_hash ~= ht.get_data_root_hash(page, 12, "sha256") then
            setup_fail("reference sha256 machine is itself inconsistent")
        end
        if not ref:verify_hash_tree() then setup_fail("reference sha256 tree does not verify") end
        print("keccak256 root (stored)         ", hx(keccak_root))
        print("sha256 root (rebuilt, reference)", hx(sha_root))

        -- The operation under test: the stored machine's config, with only the hash function changed.
        local sw_cfg = deep_copy(cfg)
        sw_cfg.hash_tree.hash_function = "sha256"
        local created, sw = pcall(cartesi.machine, sw_cfg, {})
        if not created then
            print("creation refused: " .. tostring(sw))
            return harness.expect(true, "creating a sha256 machine over keccak256 hash-tree data is refused")
        end
        local m <close> = sw
        local root = m:get_root_hash()
        local proof_target = m:get_proof(RAM, 12).target_hash
        local page_ok = proof_target == ht.get_data_root_hash(m:read_memory(RAM, 4096), 12, "sha256")
        local verified = m:verify_hash_tree()
        local root_after = m:get_root_hash()
        print("switched machine root           ", hx(root))
        print("  equals sha256 reference       ", root == sha_root)
        print("  equals keccak256 root         ", root == keccak_root)
        print("  RAM page proof matches sha256 ", page_ok)
        print("  verify_hash_tree()            ", verified)
        print("  root after verify             ", hx(root_after))

        local good = root == sha_root and root_after == sha_root and page_ok and verified
        return harness.expect(good,
            "R9: a machine created from a stored keccak256 machine's config with hash_function=sha256 must be " ..
            "refused or hash its contents under sha256 (root = rebuilt sha256 root, proofs match, tree verifies)")
    end, debug.traceback)
    cleanup()
    if not ok then error(res, 0) end
    return res
end)
