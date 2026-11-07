-- R9-GOALRESTORE-1: collect_mcycle_root_hashes defers the dirty-page marks of page-walk A/D writes to the end of
-- each sampling period, so a process stop during collection leaves a SHARING_ALL stored machine whose persisted
-- hash tree does not commit to its contents.
--
-- collect_mcycle_hashes_state_access only records written pages in an in-process set (context.dirty_pages) and copies
-- them into the shared dirty-page tree (.dpt) after interpret_with_console returns at the next period target.
-- Page-walk A/D updates go through write_ram_uint64, which skips mark_dirty_page for this accessor (it is not an
-- i_accept_dirty_pages), and no write-TLB slot records the page-table page. For each mode, this test:
--   1. stores a 1 MiB-RAM machine running guest.S (one Sv39 gigapage PTE with A=0; one translated load sets A);
--   2. reopens it SHARING_ALL in a child process (child.lua) and runs it in place, then SIGKILLs the child once the
--      A-bit write is visible in the shared RAM file, plus 1 s (kill-after-pte.sh);
--   3. reopens the directory and checks R9: its root hash equals the root recomputed from its contents alone
--      (load with clear_hash_tree), verify_hash_tree() is true, and after 200 more mcycles it still agrees with
--      the recomputed copy (R2).
-- Mode "collect" (collect_mcycle_root_hashes, period 2^40, as builder:run in the PRT player) is the defect case;
-- on feature/prt-audit the reopened root is stale, so the test exits 1. Mode "run" (plain run, whose state_access
-- marks the page right after the write) is the control and must pass; if it does not, the harness exits 2.
-- Correct behavior (R9: every persisted hash equals the root of the actual contents, including after interrupted
-- updates; R2: persisting/restoring agrees) makes both modes pass, and the test exit 0.
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

local function check(mode)
    local dir = tmp .. "/" .. mode
    do
        local m = C.new_machine()
        m:store(dir)
        m:destroy()
    end
    local ram = string.format("%s/%016x-%x.bin", dir, C.RAM, 1 << 20)
    if not io.open(ram, "rb") then harness("RAM file not found: " .. ram) end
    local out = sh(string.format("bash kill-after-pte.sh '%s' %s '%s' %d %016x", dir, mode, ram,
        C.PTE_ADDR - C.RAM, C.PTE_ACCESSED))
    if not out:find("KILLED") then harness(mode .. ": child was not killed as planned", out) end
    local r = cartesi.machine(dir)
    local pte = string.unpack("<I8", r:read_memory(C.PTE_ADDR, 8))
    if pte ~= C.PTE_ACCESSED then harness(string.format("%s: PTE 0x%x after reload", mode, pte)) end
    local h_reload = r:get_root_hash()
    local verified = r:verify_hash_tree()
    local rc = cartesi.new()
    rc:load(dir, { clear_hash_tree = true })
    local h_true = rc:get_root_hash()
    r:run(r:read_reg("mcycle") + 200)
    rc:run(rc:read_reg("mcycle") + 200)
    local a_reload, a_true = r:get_root_hash(), rc:get_root_hash()
    print(string.format("[%s] reloaded PTE 0x%x mcycle %d", mode, pte, r:read_reg("mcycle") - 200))
    print(string.format("[%s] reloaded root   %s", mode, hex(h_reload)))
    print(string.format("[%s] recomputed root %s", mode, hex(h_true)))
    print(string.format("[%s] verify_hash_tree %s", mode, tostring(verified)))
    print(string.format("[%s] +200 mcycles reloaded %s recomputed %s", mode, hex(a_reload), hex(a_true)))
    r:destroy()
    rc:destroy()
    return h_reload == h_true and verified and a_reload == a_true, h_reload, h_true
end

local ok_run = check("run")
if not ok_run then harness("control (plain run) also left a stale hash tree; the kill window is not the claimed one") end
local ok_collect, h_reload, h_true = check("collect")
cleanup()
if not ok_collect then
    print(string.format("FAIL: after SIGKILL during collect_mcycle_root_hashes, the SHARING_ALL stored machine holds the "
        .. "page-walk A-bit PTE write but its persisted root %s differs from the root of its contents %s "
        .. "(page-table page never marked dirty in .dpt; violates R9/R2)", hex(h_reload), hex(h_true)))
    os.exit(1)
end
print("OK: persisted hash tree commits to its contents after an interrupted collect and an interrupted run")
os.exit(0)
