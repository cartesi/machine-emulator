-- R1-O1-3: the PRT player's template adoption (prt.store_first_epoch_checkpoint) must rebuild the cached
-- hash-tree data of the template before it reads the root hash it records for epoch 0 (O1). Exit 1 while it
-- records a root read from stale cached data, 0 once it records the content hash, 2 on setup errors.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local prt = require("prt")

    local function sh(cmd)
        if not os.execute(cmd) then
            harness.setup_error("command failed: " .. cmd)
        end
    end
    local function capture(cmd)
        local p = assert(io.popen(cmd))
        local s = p:read("a")
        p:close()
        return (s:gsub("%s+$", ""))
    end
    local function root_of(dir, runtime)
        local m <close> = cartesi.machine(dir, runtime or {}, cartesi.SHARING_NONE)
        return m:get_root_hash()
    end

    local src = harness.config_dir("baremetal-template") .. "/machine"
    local expected_hex = capture("cat " .. harness.config_dir("baremetal-template") .. "/root-hash.txt"):lower()
    if not expected_hex:match("^0x%x+$") then
        harness.setup_error("baremetal-template is not built (bugs/harness/configs/make-configs.sh)")
    end

    local tmp = capture("mktemp -d \"${TMPDIR:-/tmp}/r1-o1-3.XXXXXX\"")
    if tmp == "" then
        harness.setup_error("mktemp failed")
    end
    local _ <close> = setmetatable({}, {
        __close = function()
            os.execute("rm -rf '" .. tmp .. "'")
        end,
    })

    -- A valid template stored with its full cached hash-tree data (as anyone could distribute it).
    local template = tmp .. "/template"
    do
        local m <close> = cartesi.machine(src, { clear_hash_tree = true }, cartesi.SHARING_NONE)
        m:get_root_hash()
        m:store(template, cartesi.SHARING_ALL)
    end
    -- The template's content hash: the root rebuilt from its contents alone. This is what the application's
    -- on-chain template hash commits to.
    local content_hash = root_of(template, { clear_hash_tree = true })
    if cartesi.tohex(content_hash):lower() ~= expected_hex then
        harness.setup_error("baremetal-template content hash differs from root-hash.txt")
    end

    -- Control: on the untouched copy, the player records the content hash (the function works).
    do
        local copy = tmp .. "/control-template"
        sh("cp -a '" .. template .. "' '" .. copy .. "'")
        local out = tmp .. "/control-epoch-0"
        local ok, err = pcall(prt.store_first_epoch_checkpoint, copy, prt.new_geometry(10), out)
        if not ok then
            harness.setup_error("control store_first_epoch_checkpoint failed: " .. tostring(err))
        end
        local _, _, manifest = prt.load_epoch_checkpoint(out)
        if manifest.final_state_hash:lower() ~= expected_hex then
            harness.setup_error("control checkpoint records " .. manifest.final_state_hash)
        end
        print("control: untouched template, epoch-0 checkpoint records " .. manifest.final_state_hash)
    end

    -- Make only the cached hash-tree data stale: overwrite one node of the RAM dense hash tree and mark the
    -- RAM dirty-page tree clean, so nothing recomputes that node on a load without a rebuild. No .bin file
    -- and no config.json changes, so the contents (and the content hash) are those of the valid template.
    do
        local f = assert(io.open(template .. "/0000000080000000-4000000.dht", "r+b"))
        f:seek("set", 96)
        f:write(string.rep("\x11", 32))
        f:close()
        local g = assert(io.open(template .. "/0000000080000000-4000000.dpt", "r+b"))
        local n = g:seek("end")
        g:seek("set", 0)
        g:write("\1" .. string.rep("\0", n - 1))
        g:close()
    end
    -- Control: the documented rebuild (O1) still yields the content hash, so the template is still valid.
    local rebuilt = root_of(template, { clear_hash_tree = true })
    if rebuilt ~= content_hash then
        harness.setup_error("the rebuild no longer yields the content hash; the template's contents changed")
    end
    local cached = root_of(template, {})
    print("template content hash (rebuilt with clear_hash_tree): " .. cartesi.tohex(content_hash))
    print("root read from the stale cached data (no rebuild):    " .. cartesi.tohex(cached))

    -- The player's adoption of the template, as prt-demo.lua does before launching the players.
    local out = tmp .. "/epoch-0"
    local ok, err = pcall(prt.store_first_epoch_checkpoint, template, prt.new_geometry(10), out)
    if not ok then
        print("store_first_epoch_checkpoint refused the valid template: " .. tostring(err))
        return harness.expect(false, "O1: the player must adopt the valid template (rebuild, then compare)")
    end
    local _, _, manifest = prt.load_epoch_checkpoint(out)
    print("epoch-0 checkpoint initial_state_hash: " .. manifest.initial_state_hash)
    print("epoch-0 checkpoint final_state_hash:   " .. manifest.final_state_hash)
    -- crisium.lua then asserts manifest.final_state_hash == the on-chain template hash ("epoch 0's checkpoint
    -- is not the template"), and new_stored_player asserts that the checkpoint machine, rebuilt, has that hash.
    local checkpoint_rebuilt = root_of(out, { clear_hash_tree = true })
    print("epoch-0 checkpoint machine rebuilt:    " .. cartesi.tohex(checkpoint_rebuilt)
        .. (cartesi.tohex(checkpoint_rebuilt):lower() == manifest.final_state_hash:lower()
            and " (matches the manifest)" or " (differs from the manifest: new_stored_player would abort too)"))
    local good = manifest.final_state_hash:lower() == expected_hex and manifest.initial_state_hash:lower() == expected_hex
    return harness.expect(
        good,
        "O1: adopting a stored machine rebuilds the cached hash-tree data, and only then compares/records the root "
            .. "hash (epoch-0 checkpoint must record the template's content hash "
            .. expected_hex
            .. ")"
    )
end)
