-- R2-DFSTORED-1: machine:store(dir, SHARING_NONE | SHARING_CONFIG) after an O1 rebuild (clear_hash_tree)
-- copies the adopted directory's un-rebuilt .dht/.dpt files, so the operator's own stored and synced snapshot
-- reloads with the stale cached root hash instead of the content hash.
--
-- Required (THREAT_MODEL.md): R9 "The content hash must equal the root of the actual contents. This applies to
-- every cached, incremental, or persisted hash, after any sequence of documented operations. It includes ...
-- every snapshot the emulator itself writes" (a directory that O2 guarantees); section 5 "O1 and O2 bind the
-- emulator too ... A defect that defeats the rebuild itself ... is not excused by them."
--
-- Exit: 0 fixed, 1 bug present, 2 setup error.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local src = harness.config_dir("baremetal-template") .. "/machine"
    local ram_bin = "0000000080000000-4000000.bin"
    if not io.open(src .. "/" .. ram_bin, "rb") then
        harness.setup_error("missing " .. src .. " (run bugs/harness/configs/make-configs.sh)")
    end

    local p = io.popen("mktemp -d /tmp/r2-dfstored-1.XXXXXX")
    local tmp = p:read("l")
    p:close()
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    -- setup errors inside the pcall are raised as { setup = msg } so the temp dir is removed before exit 2
    local function setup_error(msg) error({ setup = msg }) end
    local function sh(cmd)
        local ok = os.execute(cmd)
        if not ok then error({ setup = "command failed: " .. cmd }) end
    end

    local results = {}
    local ok, err = pcall(function()
        -- 1. A "foreign" template whose cached hash-tree data describes other contents. Its contents are what
        --    an operator would check against the on-chain commitment after the O1 rebuild.
        local tmpl = tmp .. "/tmpl"
        sh("cp -a --reflink=auto '" .. src .. "' '" .. tmpl .. "'")
        do -- make sure the cache files are populated and clean for the current contents
            local m <close> = cartesi.new()
            m:load(tmpl, nil, cartesi.SHARING_ALL)
            m:get_root_hash()
        end
        cartesi.machine:sync_stored(tmpl)
        -- change one RAM page behind the cache's back: the .dht/.dpt files now describe the old contents
        local f = assert(io.open(tmpl .. "/" .. ram_bin, "r+b"))
        f:seek("set", 0x100000)
        f:write(string.rep("\xAB", 64))
        f:close()

        local stale
        do
            local m <close> = cartesi.machine(tmpl)
            stale = m:get_root_hash()
        end
        local H -- content hash, as O1 requires it to be computed
        do
            local m <close> = cartesi.machine(tmpl, { clear_hash_tree = true })
            H = m:get_root_hash()
            if not m:verify_hash_tree() then setup_error("rebuilt tree does not verify") end
        end
        if H == stale then setup_error("could not make the template's cached data stale") end
        io.stderr:write("template stale cached root: 0x", harness.hex(stale), "\n")
        io.stderr:write("template content hash (O1): 0x", harness.hex(H), "\n")

        -- 2. For each store mode: adopt with the O1 rebuild, store, sync, reload own snapshot without rebuild.
        for _, mode in ipairs({ "all", "config", "none" }) do
            local sharing = ({ none = cartesi.SHARING_NONE, config = cartesi.SHARING_CONFIG, all = cartesi.SHARING_ALL })[mode]
            local mine = tmp .. "/mine-" .. mode
            do
                local m <close> = cartesi.machine(tmpl, { clear_hash_tree = true })
                if m:get_root_hash() ~= H then setup_error("O1 rebuild not reproducible") end
                m:store(mine, sharing)
            end
            cartesi.machine:sync_stored(mine)
            local reloaded, verified, rebuilt
            do
                local m <close> = cartesi.machine(mine)
                reloaded = m:get_root_hash()
                verified = m:verify_hash_tree()
            end
            do
                local m <close> = cartesi.machine(mine, { clear_hash_tree = true })
                rebuilt = m:get_root_hash()
            end
            if rebuilt ~= H then
                setup_error("mode " .. mode .. ": stored contents differ from the adopted machine's")
            end
            io.stderr:write(string.format("store sharing=%-6s reload root 0x%s  (%s)  verify_hash_tree=%s\n", mode,
                harness.hex(reloaded), reloaded == H and "== content hash" or
                (reloaded == stale and "== STALE template cache" or "other"), tostring(verified)))
            results[#results + 1] = { mode = mode, ok = (reloaded == H and verified) }
            sh("rm -rf '" .. mine .. "'")
        end
    end)
    os.execute("rm -rf '" .. tmp .. "'")
    if not ok then
        if type(err) == "table" and err.setup then harness.setup_error(err.setup) end
        error(err, 0)
    end

    local all_ok = true
    for _, r in ipairs(results) do
        all_ok = harness.expect(r.ok, "R9/O1: after an O1 rebuild, store(dir, sharing=" .. r.mode ..
            ") + sync_stored, the reloaded snapshot's root hash equals the content hash and its hash tree verifies")
            and all_ok
    end
    return all_ok
end)
