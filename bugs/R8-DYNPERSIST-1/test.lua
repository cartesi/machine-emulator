-- R8-DYNPERSIST-1: write_memory/write_word change shared RAM before marking the page dirty, so a process stop in
-- between leaves a stored machine whose hash tree does not commit to its contents.
--
-- With SHARING_ALL, the RAM .bin, .dpt (dirty-page tree) and .dht (page hashes) files of a stored machine are
-- MAP_SHARED and are what the next load trusts. machine::write_memory and machine::write_word store the data into
-- the mapped RAM first and only then call mark_dirty_page_and_up; nothing else records the pending change (host API
-- writes do not go through the write TLB). For each of write_memory and write_word, this test:
--   1. stores a minimal 1 MiB-RAM machine;
--   2. under gdb, reopens it SHARING_ALL, calls get_root_hash, then makes one 8-byte host write to RAM page 64 and
--      SIGKILLs the process the instant the shared RAM byte changes (crash.lua, kill-after-data-store.py);
--   3. reopens the directory and checks that its root hash commits to its contents: it must equal the root of an
--      uninterrupted machine that received the same write (oracle), and verify_hash_tree() must be true.
-- Correct behavior (R9: every persisted hash equals the root of the actual contents, including after interrupted
-- updates; R2: persisting/restoring agrees with an uninterrupted run). On feature/prt-audit the reopened root is the
-- pre-write root and verify_hash_tree() is false, so the test exits nonzero.
-- CONTROL=1 runs crash.lua to completion without gdb; that passes.
local cartesi = require("cartesi")
local C = dofile("common.lua")

local function sh(cmd)
    local p = assert(io.popen(cmd .. " 2>&1"))
    local out = p:read("a")
    p:close()
    return out
end

local tmp = sh("mktemp -d"):gsub("%s+$", "")
local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
local function harness(msg, out)
    if out then io.stderr:write(out) end
    print("HARNESS ERROR: " .. msg)
    cleanup()
    os.exit(2)
end

local failures = {}
for _, fn in ipairs({ "write_memory", "write_word" }) do
    local dir = tmp .. "/" .. fn
    -- 1. Stored machine
    local pre_root
    do
        local m = C.new_machine()
        pre_root = m:get_root_hash()
        m:store(dir)
        m:destroy()
    end
    -- Oracle: uninterrupted machine that received the same write
    local oracle_root
    do
        local m = C.new_machine()
        C.apply(m, fn)
        oracle_root = m:get_root_hash()
        m:destroy()
    end
    -- 2. Crash between the data store and the dirty mark
    if os.getenv("CONTROL") == "1" then
        local out = sh(string.format("lua5.4 crash.lua '%s' %s", dir, fn))
        if not out:find("CRASH%-STAGE%-NOT%-KILLED") then harness("control crash stage failed", out) end
    else
        local out = sh(string.format(
            "RAM_FILE='%s' WATCH_OFF=%d API_FN=cm_%s gdb -q -batch -x kill-after-data-store.py --args lua5.4 crash.lua '%s' %s",
            C.RAM_BIN, C.OFFSET, fn, dir, fn))
        if not out:find("WATCH%-ARMED byte=0") or not out:find("DATA%-STORED byte=171") or not out:find("SIGKILL")
            or out:find("CRASH%-STAGE%-NOT%-KILLED") then
            harness("gdb did not stop " .. fn .. " right after its data store", out)
        end
    end
    -- 3. Reopen and check that the persisted hash tree commits to the contents
    local m = cartesi.new()
    m:load(dir, nil, cartesi.SHARING_ALL)
    local word = m:read_word(C.TARGET)
    local root = m:get_root_hash()
    local ok, consistent = pcall(m.verify_hash_tree, m)
    if not ok then consistent = false end
    m:destroy()
    if word ~= C.WORD then harness(fn .. ": the write did not reach the shared RAM file") end
    print(string.format("%s: memory word=0x%x reopened root=%s pre-write root=%s oracle root=%s verify_hash_tree=%s",
        fn, word, cartesi.tohex(root), cartesi.tohex(pre_root), cartesi.tohex(oracle_root), tostring(consistent)))
    if root ~= oracle_root or not consistent then
        failures[#failures + 1] = fn .. (root == pre_root and " (root is the pre-write root)" or "")
    end
end
cleanup()
if #failures > 0 then
    print("FAIL: a stop between the RAM store and the dirty mark in " .. table.concat(failures, ", ")
        .. " leaves the shared stored machine with a clean .dpt and stale .dht, so the reloaded root hash does not "
        .. "commit to its contents (R9, R2)")
    os.exit(1)
end
print("OK: reopened machines' root hashes commit to their contents")
