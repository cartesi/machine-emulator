-- R5-INVHASH-1: replace_memory_range with backing_store.mark_pages_dirty = true (or without a .dpt file) on a
-- machine whose hash tree was already updated keeps the inner nodes of the supplied .dht file instead of
-- recomputing them, so the root hash, node hashes and stored snapshots disagree with the contents (R9).
--
-- Required (doc/README.md, backing_store): "When both tree filenames are supplied and both files already exist,
-- the emulator reuses the dirty-page flags ... Otherwise, it marks all pages dirty. Setting
-- backing_store.mark_pages_dirty to true forces all pages to be marked dirty even when both tree files exist, so
-- their hashes are recomputed on the next hash-tree update."
-- R9: "The content hash must equal the root of the actual contents. This applies to every cached, incremental,
-- or persisted hash, after any sequence of documented operations ... and every snapshot the emulator itself writes."
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local hex = harness.hex

    local tmp = assert(io.popen("mktemp -d"):read("l"))
    if not tmp or tmp == "" then harness.setup_error("mktemp failed") end
    local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end

    local function wfile(name, data)
        local f = assert(io.open(name, "wb"))
        f:write(data)
        f:close()
    end

    local START, LEN = 0x80000000000000, 0x8000 -- one flash drive of 8 pages
    local A = string.rep("A", LEN)
    local B = string.rep("B", 0x3000) .. string.rep("C", LEN - 0x3000)
    wfile(tmp .. "/a.bin", A)
    wfile(tmp .. "/b.bin", B)
    local function cfg(bs) return { ram = { length = 1 << 20 }, flash_drive = { { start = START, length = LEN, backing_store = bs } } } end

    -- Reference: the content hash of a machine holding image B (fresh machine, trees computed from contents).
    local ref = cartesi.machine(cfg({ data_filename = tmp .. "/b.bin" }))
    local href = ref:get_root_hash()
    local href_node = ref:get_node_hash(START, 15)
    -- Emulator-written .dht/.dpt for image B
    ref:store(tmp .. "/st")
    ref:destroy()
    local dht_path = string.format("%s/st/%016x-%x.dht", tmp, START, LEN)
    local dpt_path = string.format("%s/st/%016x-%x.dpt", tmp, START, LEN)
    local dht = harness.read_file(dht_path)
    if #dht ~= 16 * 32 then cleanup(); harness.setup_error("unexpected .dht size " .. #dht) end
    -- Tree file whose inner nodes (indices 1..7) are garbage and whose 8 leaves (indices 8..15) are the true page
    -- hashes. mark_pages_dirty / a missing .dpt must make the emulator recompute every page hash and every node
    -- above it, so the content of the inner nodes must not matter.
    wfile(tmp .. "/bad.dht", dht:sub(1, 32) .. string.rep("\xEE", 7 * 32) .. dht:sub(8 * 32 + 1))
    wfile(tmp .. "/b.dpt", harness.read_file(dpt_path))

    local bs_mark = { data_filename = tmp .. "/b.bin", dht_filename = tmp .. "/bad.dht",
        dpt_filename = tmp .. "/b.dpt", mark_pages_dirty = true }
    local bs_nodpt = { data_filename = tmp .. "/b.bin", dht_filename = tmp .. "/bad.dht" }

    -- Control: the same backing stores at machine creation give the content hash.
    local c1 = cartesi.machine(cfg(bs_mark))
    local c2 = cartesi.machine(cfg(bs_nodpt))
    local hc1, hc2 = c1:get_root_hash(), c2:get_root_hash()
    c1:destroy(); c2:destroy()
    print("content hash (fresh machine, image B):     " .. hex(href))
    print("creation with mark_pages_dirty tree files: " .. hex(hc1))
    print("creation with .dht but no .dpt:            " .. hex(hc2))
    if hc1 ~= href or hc2 ~= href then
        cleanup()
        harness.setup_error("control failed: the same tree files at creation do not give the content hash")
    end

    local ok = true
    local function check(cond, what)
        ok = harness.expect(cond, what) and ok
    end

    for _, v in ipairs({ { "mark_pages_dirty=true", bs_mark }, { "no dpt_filename", bs_nodpt } }) do
        local name, bs = v[1], v[2]
        local m = cartesi.machine(cfg({ data_filename = tmp .. "/a.bin" }))
        m:get_root_hash() -- any successful hash-tree update before the replace
        m:replace_memory_range({ start = START, length = LEN, backing_store = bs })
        local h = m:get_root_hash()
        local node = m:get_node_hash(START, 15)
        print(string.format("[%s] root after replace:         %s", name, hex(h)))
        print(string.format("[%s] range node after replace:   %s (content: %s)", name, hex(node), hex(href_node)))
        print(string.format("[%s] verify_hash_tree():         %s", name, tostring(m:verify_hash_tree())))
        check(h == href, "[" .. name .. "] root hash after replace_memory_range equals the content hash (R9, manual)")
        check(node == href_node, "[" .. name .. "] node hash of the replaced range equals its content hash (R9)")
        if name == "no dpt_filename" then
            -- A snapshot the emulator writes: its cached root must equal the root rebuilt from its contents.
            local dir = tmp .. "/snap"
            m:store(dir)
            m:sync_stored(dir) -- make it a directory that O2 guarantees (R9: "every snapshot the emulator itself writes")
            m:destroy()
            local l = cartesi.machine(dir, {})
            local r = cartesi.machine(dir, { clear_hash_tree = true })
            local hl, hr = l:get_root_hash(), r:get_root_hash()
            l:destroy(); r:destroy()
            print(string.format("[%s] stored snapshot cached root: %s rebuilt: %s", name, hex(hl), hex(hr)))
            check(hl == hr, "[" .. name .. "] snapshot written by store() has a cached root equal to its rebuilt root (R9)")
        else
            m:destroy()
        end
    end
    cleanup()
    return ok
end)
