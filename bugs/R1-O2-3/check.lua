-- bugs/R1-O2-3: run by test.sh under LD_PRELOAD=fail-new.so (see README.md). arg[1] = temp dir.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local g = require("guest")
    local tmp = assert(arg[1], "usage: check.lua <tmpdir>")
    local arm = assert(os.getenv("FAIL_NEW_ARM_FILE"), "FAIL_NEW_ARM_FILE not set")
    local count_file = assert(os.getenv("FAIL_NEW_COUNT_FILE"), "FAIL_NEW_COUNT_FILE not set")
    local hex = function(h) return cartesi.tohex(h) end

    local image = tmp .. "/guest.bin"
    local f = assert(io.open(image, "wb"))
    f:write(g.image())
    f:close()
    local config = { ram = { length = 64 << 20, backing_store = { data_filename = image } } }
    local function pte(m) return string.unpack("<I8", m:read_memory(g.PTE_ADDR, 8)) end

    local MCYCLE_SETUP = 1000000 -- guest is in S-mode, spinning (PTE A set, D clear)
    local LOG2_PERIOD = 24 -- one period covers the spin end and the 8000 page stores

    local function prepare()
        local m = harness.machine(config)
        m:run(MCYCLE_SETUP)
        if m:read_reg("iprv") ~= 1 or pte(m) & g.PTE_A == 0 or pte(m) & g.PTE_D ~= 0 then
            harness.setup_error(string.format("guest not in the expected state: iprv=%d pte=0x%x",
                m:read_reg("iprv"), pte(m)))
        end
        return m
    end

    -- Hash-tree consistency: the cached root must equal the root rebuilt from the contents.
    local function consistency(m)
        local cached = m:get_root_hash()
        local cached_pt = m:get_node_hash(g.PT, 12)
        local verified = m:verify_hash_tree()
        m:clear_hash_tree()
        local rebuilt = m:get_root_hash()
        local rebuilt_pt = m:get_node_hash(g.PT, 12)
        return cached == rebuilt and verified, cached, rebuilt, verified, cached_pt, rebuilt_pt
    end

    -- Control: the same collection without a fault keeps the hash tree consistent.
    do
        local m <close> = prepare()
        local start = m:read_reg("mcycle")
        local r = m:collect_mcycle_root_hashes(start + (1 << LOG2_PERIOD), LOG2_PERIOD, 0, 0)
        if #r.hashes ~= 1 or pte(m) & g.PTE_D == 0 then
            harness.setup_error("control collection did not run the guest's page stores")
        end
        local ok, cached, rebuilt = consistency(m)
        if not ok then
            harness.setup_error("control (no fault) already inconsistent: " .. hex(cached) .. " vs " .. hex(rebuilt))
        end
        print("control: no fault, cached root == rebuilt root " .. hex(cached))
    end

    -- Fault: an allocation failure (std::bad_alloc) inside the interpreter during collect_mcycle_root_hashes.
    local m <close> = prepare()
    local start = m:read_reg("mcycle")
    os.remove(count_file)
    local af = assert(io.open(arm, "w"))
    af:close()
    local ok, err = pcall(m.collect_mcycle_root_hashes, m, start + (1 << LOG2_PERIOD), LOG2_PERIOD, 0, 0)
    os.remove(arm)
    local cf = io.open(count_file, "r")
    local injected = cf and cf:read("a") or ""
    if cf then cf:close() end
    if ok or injected == "" then
        harness.setup_error("no allocation failure was injected inside the collection (ok=" .. tostring(ok) ..
            "); the test cannot exercise the failed-update path")
    end
    print("collect_mcycle_root_hashes failed as injected: " .. tostring(err))
    print(string.format("after the failure: mcycle=%d (started at %d), leaf PTE at 0x%x = 0x%x (D bit %s)",
        m:read_reg("mcycle"), start, g.PTE_ADDR, pte(m), pte(m) & g.PTE_D ~= 0 and "set" or "clear"))
    if pte(m) & g.PTE_D == 0 then
        harness.setup_error("the guest did not reach its page stores before the injected failure")
    end

    -- R9: the content hash must equal the root of the actual contents, including after failed updates in a
    -- process that keeps using the machine.
    local consistent, cached, rebuilt, verified, cached_pt, rebuilt_pt = consistency(m)
    print("get_root_hash() after the failure    " .. hex(cached))
    print("root rebuilt by clear_hash_tree()    " .. hex(rebuilt))
    print("verify_hash_tree() after the failure " .. tostring(verified))
    print(string.format("page-table page 0x%x node hash: cached %s, rebuilt %s", g.PT, hex(cached_pt),
        hex(rebuilt_pt)))
    return harness.expect(consistent,
        "R9: after collect_mcycle_root_hashes fails inside a running process (host allocation failure), "
            .. "the machine's root hash must equal the root of its actual contents")
end)
