-- R11-FAMPERSISTA-1: the native interpreter's page walk (state_access, i.e. plain run()) stores the PTE A/D update
-- into the MAP_SHARED RAM of a SHARING_ALL machine BEFORE it marks the page-table page dirty in the shared
-- dirty-page tree (.dpt). write_ram_uint64 (src/translate-virtual-address.hpp) calls a.write_memory_word() and only
-- afterwards a.mark_dirty_page(). Nothing else records the page (a walk installs no write-TLB entry for the
-- page-table page), and a reload trusts the persisted .dpt/.dht. A process stop between the two leaves a stored
-- machine whose persisted root does not commit to its contents.
--
-- This test:
--   1. stores a 1 MiB-RAM machine running guest.S (one Sv39 gigapage PTE with A=0; one translated load sets A);
--   2. in a child (child.lua) reopens it SHARING_ALL, calls get_root_hash() (hash tree up to date, .dpt clean), and
--      calls run(); under gdb (kill.py) a hardware watchpoint on the PTE byte in the shared RAM mapping fires right
--      after the page walk's store, and the child is SIGKILLed there (asserted: inside write_ram_uint64);
--   3. reopens the directory and checks R9/R2: its root equals the root recomputed from its contents alone
--      (load with clear_hash_tree), verify_hash_tree() is true, and after 200 more mcycles both still agree.
-- On feature/prt-audit the persisted root is stale (exit 1). If the mark precedes the store (the fix), the .dpt
-- already covers the PTE page when the store lands, and the test exits 0. Harness problems exit 2.
local cartesi = require("cartesi")
local C = dofile("common.lua")
local hex = cartesi.tohex

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

if sh("command -v gdb") == "" then harness("gdb not found") end

local dir = tmp .. "/m"
do
    local m = C.new_machine()
    m:store(dir)
    m:destroy()
end
local ramname = string.format("%016x-%x.bin", C.RAM, 1 << 20)
if not io.open(dir .. "/" .. ramname, "rb") then harness("RAM file not found: " .. ramname) end

local out = sh(string.format("RAM_FILE='%s' WATCH_OFF=%d API_FN=cm_run nice -n 10 gdb -q -batch -nx -x kill.py " ..
    "--args lua5.4 child.lua '%s'", ramname, C.PTE_ADDR - C.RAM, dir))
local frame = out:match("FRAME ([^\n]*)")
if not out:find("WATCH%-ARMED") or not out:find("STORED") or not frame then
    harness("gdb did not stop the child at the PTE store", out)
end
if not frame:find("write_ram_uint64", 1, true) or not out:find("state_access", 1, true) then
    harness("PTE store happened outside write_ram_uint64<state_access>: " .. frame, out)
end
print("child killed right after the PTE store, at: " .. frame)

local r = cartesi.machine(dir)
local pte = string.unpack("<I8", r:read_memory(C.PTE_ADDR, 8))
if pte ~= C.PTE_ACCESSED then harness(string.format("PTE 0x%x after reload, expected 0x%x", pte, C.PTE_ACCESSED)) end
local h_reload = r:get_root_hash()
local verified, verr = r:verify_hash_tree()
local rc = cartesi.new()
rc:load(dir, { clear_hash_tree = true })
local h_true = rc:get_root_hash()
r:run(r:read_reg("mcycle") + 200)
rc:run(rc:read_reg("mcycle") + 200)
local a_reload, a_true = r:get_root_hash(), rc:get_root_hash()
print(string.format("reloaded PTE 0x%x", pte))
print("reloaded root   " .. hex(h_reload))
print("recomputed root " .. hex(h_true))
print("verify_hash_tree " .. tostring(verified) .. (verr and (" (" .. tostring(verr) .. ")") or ""))
print("+200 mcycles reloaded " .. hex(a_reload) .. " recomputed " .. hex(a_true))
r:destroy()
rc:destroy()
cleanup()
if not (h_reload == h_true and verified and a_reload == a_true) then
    print(string.format("FAIL: SIGKILL right after the page walk's A-bit store in plain run() left a SHARING_ALL " ..
        "stored machine whose persisted root %s differs from the root of its contents %s: write_ram_uint64 " ..
        "stores before mark_dirty_page (violates R9/R2)", hex(h_reload), hex(h_true)))
    os.exit(1)
end
print("OK: persisted hash tree commits to its contents after a run interrupted at the page-walk PTE store")
os.exit(0)
