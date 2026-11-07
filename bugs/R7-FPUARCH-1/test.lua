-- R7-FPUARCH-1: an interrupted mark-dirty in a shared stored machine leaves a stale hash tree.
--
-- dirty_page_tree::do_mark_dirty_leaf_position_and_up stores the leaf before its ancestors and stops
-- early at an already-dirty node. With SHARING_ALL, the dirty-page tree is a MAP_SHARED mapping of
-- <dir>/<range>.dpt that the next load trusts. This test:
--   1. stores a machine whose guest keeps writing RAM page 5 through its write-TLB entry;
--   2. under gdb, reopens it the way the stored PRT player does (load SHARING_ALL + get_root_hash),
--      asks for the root hash again at the same state, and SIGKILLs the process right after that
--      update stores page 5's leaf as dirty, before its parent (crash.lua, kill-after-leaf-store.py);
--   3. reopens it again (the root hash still matches the stored one, so recovery accepts it),
--      runs the guest further and compares the root hash with an uninterrupted run of the same
--      machine to the same mcycle, and checks verify_hash_tree().
-- Correct behavior (R9, R2): the crash-recovered machine's hash tree matches its contents and its
-- root equals the uninterrupted run's. On feature/prt-audit both fail, so the test exits nonzero.
-- CONTROL=1 runs the same steps with crash.lua completing normally (no kill); that passes.
local cartesi = require("cartesi")
local C = dofile("common.lua")

local function sh(cmd)
    local p = assert(io.popen(cmd .. " 2>&1"))
    local out = p:read("a")
    p:close()
    return out
end

local tmp = sh("mktemp -d"):gsub("%s+$", "")
local dir = tmp .. "/stored"
local function cleanup() os.execute("rm -rf '" .. tmp .. "'") end
local function fail(msg, code)
    print("FAIL: " .. msg)
    cleanup()
    os.exit(code or 1)
end

-- 1. Stored machine at mcycle FIRST_RUN; page 5 is in the write TLB, the hash tree is up to date.
do
    local m = C.new_machine()
    m:run(C.FIRST_RUN)
    assert(m:read_word(C.TARGET) ~= 0, "guest did not write the target page")
    m:store(dir)
    m:destroy()
end
local stored_root
do
    local m = cartesi.new()
    m:load(dir, nil, cartesi.SHARING_ALL)
    stored_root = m:get_root_hash()
    m:destroy()
end

-- 2. Crash inside the hash-tree update of a reopen, right after page 5's leaf store.
local leaf = C.leaf_position(C.PAGE_INDEX)
if os.getenv("CONTROL") == "1" then
    local out = sh("lua5.4 crash.lua '" .. dir .. "'")
    assert(out:find("CRASH%-STAGE%-NOT%-KILLED"), out)
    goto recovery
end
do
local out = sh(string.format("DPT_FILE='%s' LEAF_POS=%d gdb -q -batch -x kill-after-leaf-store.py --args lua5.4 crash.lua '%s'",
    C.RAM_DPT, leaf, dir))
if not out:find("WATCH%-ARMED leaf=0") or not out:find("LEAF%-STORED") or not out:find("SIGKILL") then
    io.stderr:write(out)
    fail("harness error: gdb did not stop the reopen at the leaf store", 2)
end
local f = assert(io.open(dir .. "/" .. C.RAM_DPT, "rb"))
local dpt = f:read("a")
f:close()
local chain = {}
local p = leaf
while p >= 1 do
    chain[#chain + 1] = string.format("%d:%d", p, dpt:byte(p + 1))
    p = p // 2
end
print("dpt after crash (position:dirty, leaf to root): " .. table.concat(chain, " "))
end
::recovery::

-- 3. Recovery: reopen as the player does; the stored root still matches, so it resumes.
local m = cartesi.new()
m:load(dir, nil, cartesi.SHARING_ALL)
local reopened_root = m:get_root_hash()
if reopened_root ~= stored_root then
    m:destroy()
    fail("harness error: reopened root differs from stored root", 2)
end
print("reopened root matches stored root: " .. cartesi.tohex(reopened_root))
m:run(C.SECOND_RUN)
local recovered_root = m:get_root_hash()
local consistent = m:verify_hash_tree()
m:destroy()

local ref = C.new_machine()
ref:run(C.SECOND_RUN)
local reference_root = ref:get_root_hash()
ref:destroy()
print("crash-recovered root at mcycle " .. C.SECOND_RUN .. ": " .. cartesi.tohex(recovered_root))
print("uninterrupted root at mcycle " .. C.SECOND_RUN .. ":   " .. cartesi.tohex(reference_root))
print("verify_hash_tree() after recovery: " .. tostring(consistent))

if recovered_root ~= reference_root or not consistent then
    fail("a crash between the leaf and parent stores of mark-dirty left RAM page 5 dirty under clean "
        .. "ancestors in the shared .dpt; after reload its writes are never re-hashed, so the root hash is stale "
        .. "(R9, R2)")
end
cleanup()
print("OK: crash-recovered machine hashes like an uninterrupted run")
