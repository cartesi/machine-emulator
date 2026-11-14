-- bugs/R3-VARDIRTY-1 (run by test.sh under LD_PRELOAD=fail-new.so with FAIL_NEW_EXACT=16384).
-- R9: after an update of the hash tree fails inside a running process, which keeps using the machine, the root
-- hash must still equal the root of the actual contents.
local harness = require("harness")

harness.main(function()
    local cartesi = require("cartesi")
    local tmp = assert(arg[1], "usage: check.lua <tmpdir>")
    local arm, count_file = tmp .. "/arm", tmp .. "/injected"

    local function new_machine()
        -- concurrency 1 makes the dense-tree batch size independent of the host's CPU count
        return cartesi.machine({ ram = { length = 64 << 20 } }, { concurrency = { update_hash_tree = 1 } })
    end
    local function dirty(m)
        for i = 0, 63 do
            m:write_memory(0x80000000 + i * 4096 * 7, string.rep("\x5a", 64))
        end
    end
    local function injected_count()
        local f = io.open(count_file, "r")
        if not f then return 0 end
        local n = 0
        for _ in f:lines() do n = n + 1 end
        f:close()
        return n
    end

    -- Control: the same operations without a fault keep the cached root equal to the rebuilt root.
    do
        local m <close> = new_machine()
        m:get_root_hash()
        dirty(m)
        m:get_root_hash()
        m:write_memory(0x80001000, "keep using the machine")
        local cached = m:get_root_hash()
        m:clear_hash_tree()
        local rebuilt = m:get_root_hash()
        if cached ~= rebuilt then harness.setup_error("control: cached root differs from rebuilt root") end
        print("control: no fault, cached root == rebuilt root " .. cartesi.tohex(cached))
    end

    local m <close> = new_machine()
    m:get_root_hash()
    dirty(m) -- 64 dirty pages: update_dirty_pages hashes them, then update_dense_trees runs
    io.open(arm, "w"):close()
    local ok, err = pcall(m.get_root_hash, m)
    os.remove(arm)
    if ok then harness.setup_error("get_root_hash did not fail: the fault was not injected") end
    if injected_count() ~= 1 then harness.setup_error("expected exactly one injected allocation failure") end
    print("get_root_hash failed as injected (16384-byte dense-tree batch reservation): " .. tostring(err))

    -- The process keeps using the machine (R9: "updates that fail inside a running process, which then keeps
    -- using the machine")
    m:write_memory(0x80001000, "keep using the machine")
    local ok2, cached = pcall(m.get_root_hash, m)
    if not ok2 then
        -- failing loudly again is not a wrong hash
        print("get_root_hash after the failure raised: " .. tostring(cached))
        return true
    end
    local verified = m:verify_hash_tree()
    m:clear_hash_tree()
    local rebuilt = m:get_root_hash()
    print("get_root_hash() after the failure  " .. cartesi.tohex(cached))
    print("root rebuilt by clear_hash_tree()  " .. cartesi.tohex(rebuilt))
    print("verify_hash_tree() after the failure " .. tostring(verified))
    return harness.expect(cached == rebuilt,
        "R9: after hash_tree::update fails inside a running process (host allocation failure), get_root_hash() "
            .. "must equal the root of the actual contents")
end)
