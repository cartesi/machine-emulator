-- R1-O1-1: the documented O1 rebuild (runtime option clear_hash_tree) cannot adopt a stored machine whose
-- hashed contents are intact but whose cached hash-tree files (hash_tree.sht, hash_tree.phtc, *.dht, *.dpt)
-- are malformed or missing: the loader parses and validates that cached data before it clears it, and throws.
--
-- Asserted (THREAT_MODEL O1, section 5 "the emulator must make them possible to follow", sections 4 and 8):
-- for every case below, cartesi.machine(dir, {clear_hash_tree = true}) succeeds and get_root_hash() equals the
-- content hash of the untouched machine. Only cached hash-tree files are touched; every .bin and config.json is
-- byte-identical to the original stored machine.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")

    local src = harness.config_dir("baremetal-template") .. "/machine"
    if not io.open(src .. "/config.json", "rb") then harness.setup_error("missing stored machine " .. src) end

    local ok_tmp, tmp = harness.sh("mktemp -d /tmp/r1-o1-1.XXXXXX")
    tmp = tmp and tmp:gsub("%s+$", "")
    if not ok_tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
    local function sh(cmd)
        if not os.execute(cmd) then
            cleanup()
            harness.setup_error("command failed: " .. cmd)
        end
    end
    local function write_at(path, off, data)
        local f = assert(io.open(path, "r+b"), path)
        f:seek("set", off)
        f:write(data)
        f:close()
    end

    -- A stored machine written by this emulator, with sharing (as an operator would have it on disk).
    local base = tmp .. "/base"
    local ok_setup, err = pcall(function()
        local m <close> = cartesi.machine(src, { clear_hash_tree = true }, cartesi.SHARING_NONE)
        m:get_root_hash()
        m:store(base, cartesi.SHARING_ALL)
    end)
    if not ok_setup then cleanup(); harness.setup_error("cannot store base machine: " .. tostring(err)) end

    -- Reference content hash: the rebuilt root of the untouched directory.
    local ok_ref, ref = pcall(function()
        local m <close> = cartesi.machine(base, { clear_hash_tree = true }, cartesi.SHARING_NONE)
        return m:get_root_hash()
    end)
    if not ok_ref then cleanup(); harness.setup_error("cannot load untouched base: " .. tostring(ref)) end
    print("reference root hash (rebuilt from contents): 0x" .. harness.hex(ref))

    local ram = "0000000080000000-4000000"
    -- sht layout: node_type {int64 left, right, parent; uint32 log2_size; uint8 hash[32]} = 64 bytes per node.
    local controls = {
        { "control: garbage in the root hash of hash_tree.sht", function(d)
            write_at(d .. "/hash_tree.sht", 64 + 28, string.rep("\xab", 32))
        end },
        { "control: garbage in the first page hashes of the RAM .dht", function(d)
            write_at(d .. "/" .. ram .. ".dht", 0, string.rep("\xcd", 256))
        end },
    }
    local cases = {
        { "hash_tree.sht: left index of sparse node 2 changed", function(d)
            write_at(d .. "/hash_tree.sht", 2 * 64, string.pack("<i8", 77))
        end },
        { "hash_tree.sht truncated to 64 bytes", function(d) sh("truncate -s 64 '" .. d .. "/hash_tree.sht'") end },
        { "hash_tree.phtc: unknown file tag", function(d)
            write_at(d .. "/hash_tree.phtc", 0, string.pack("<I8", 0x1234))
        end },
        { "RAM .dpt truncated to 10 bytes", function(d) sh("truncate -s 10 '" .. d .. "/" .. ram .. ".dpt'") end },
        { "RAM .dht missing", function(d) sh("rm '" .. d .. "/" .. ram .. ".dht'") end },
    }

    local function try(i, c, sharing)
        local d = string.format("%s/case%d-%d", tmp, i, sharing)
        sh("cp -a --sparse=always '" .. base .. "' '" .. d .. "'")
        c[2](d)
        local ok, res = pcall(function()
            local m <close> = cartesi.machine(d, { clear_hash_tree = true }, sharing)
            return m:get_root_hash()
        end)
        sh("rm -rf '" .. d .. "'")
        if not ok then return false, "load with clear_hash_tree FAILS: " .. tostring(res) end
        if res ~= ref then return false, "rebuilt root differs: 0x" .. harness.hex(res) end
        return true, "rebuilt, root matches"
    end

    local sharings = { { cartesi.SHARING_NONE, "SHARING_NONE" }, { cartesi.SHARING_ALL, "SHARING_ALL" } }

    -- Controls: hash-only corruption of cached data must be neutralized by the rebuild (else the test is broken).
    for i, c in ipairs(controls) do
        for _, s in ipairs(sharings) do
            local ok, msg = try(100 + i, c, s[1])
            print(string.format("[%s] %s: %s", s[2], c[1], msg))
            if not ok then cleanup(); harness.setup_error("control failed: " .. c[1]) end
        end
    end

    local failures = 0
    for i, c in ipairs(cases) do
        for _, s in ipairs(sharings) do
            local ok, msg = try(i, c, s[1])
            print(string.format("[%s] %s: %s", s[2], c[1], msg))
            if not ok then failures = failures + 1 end
        end
    end
    cleanup()

    return harness.expect(failures == 0, string.format(
        "O1/section 5: a stored machine whose contents are intact must be adoptable by rebuilding its cached " ..
        "hash-tree data (clear_hash_tree) to the content hash; %d of %d load(s) failed", failures, 2 * #cases))
end)
