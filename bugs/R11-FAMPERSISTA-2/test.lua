-- R11-FAMPERSISTA-2: replace_memory_range drops write-TLB dirty marks pending against the replaced range.
--
-- A guest page written through a write-TLB slot is recorded only by that slot until mark_write_tlb_dirty_pages
-- runs. machine::replace_memory_range swaps in the new range without first flushing those marks into the old
-- range's dirty-page tree. With a machine loaded SHARING_ALL from directory D, the old range's .bin in D holds the
-- guest's bytes while its .dpt/.dht still claim the previous (clean) hash. The later flush (sfence.vma, ~machine)
-- marks the page in the NEW range instead. Reloading D, a snapshot the emulator itself wrote in place, then yields
-- a root hash that does not commit to D's contents (R9 hash integrity, R2 persisting/sharing agreement).
-- Severity: Medium (persistence defect off the honest operator's path; the PRT player never replaces ranges).
--
-- The test asserts the correct behavior: after reload, get_root_hash() equals the root recomputed from contents
-- alone (clear_hash_tree) and verify_hash_tree() succeeds. A control run that flushes the marks (get_root_hash)
-- before replacing must pass, proving the harness itself is sound. Exit 1 = defect present, 2 = harness error.
local cartesi = require("cartesi")
local hex = cartesi.tohex

os.execute("bash ./build.sh")
local code = assert(io.open("guest.bin", "rb"), "guest.bin missing (build failed)"):read("a")

local RAM = 0x80000000
local FLAG = 0x80001000
local FL = 0x80000000000000
local WORD = 0x1122334455667788

local tmp = os.tmpname()
os.remove(tmp)
assert(os.execute("mkdir -p " .. tmp))
local zero = tmp .. "/zero.bin"
do
    local f = assert(io.open(zero, "wb"))
    f:write(string.rep("\0", 4096))
    f:close()
end

-- Runs the scenario in directory D. If flush_first, flushes pending marks before replacing (control path).
local function scenario(name, flush_first)
    local D = tmp .. "/" .. name
    local m0 = cartesi.machine({
        processor = { registers = { pc = RAM } },
        ram = { length = 1 << 20 },
        flash_drive = { { start = FL, length = 4096 } },
    })
    m0:write_memory(RAM, code)
    m0:store(D)
    m0:destroy()

    local m = cartesi.new()
    m:load(D, nil, cartesi.SHARING_ALL)
    m:get_root_hash()
    m:run(1000) -- guest stores WORD to flash through the write TLB and spins on FLAG
    assert(m:read_word(FL) == WORD, "harness: guest did not write the flash word")
    if flush_first then m:get_root_hash() end
    m:replace_memory_range({ start = FL, length = 4096, backing_store = { data_filename = zero } })
    m:write_word(FLAG, 1)
    m:run(2000) -- guest executes sfence.vma, flushing its write-TLB slot into the replacement range
    m:destroy()

    local r = cartesi.new()
    r:load(D)
    local word = r:read_word(FL)
    local reloaded = r:get_root_hash()
    local ok_verify = r:verify_hash_tree()
    r:destroy()
    local rc = cartesi.new()
    rc:load(D, { clear_hash_tree = true })
    local recomputed = rc:get_root_hash()
    rc:destroy()
    return word, reloaded, recomputed, ok_verify
end

local cw, crel, crec, cver = scenario("control", true)
local w, rel, rec, ver = scenario("defect", false)
os.execute("rm -rf " .. tmp)

print(string.format("control: flash word %x reloaded %s recomputed %s verify %s", cw, hex(crel), hex(crec), cver))
print(string.format("defect:  flash word %x reloaded %s recomputed %s verify %s", w, hex(rel), hex(rec), ver))

if cw ~= WORD or crel ~= crec or not cver then
    print("HARNESS ERROR: control scenario (marks flushed before replace) is itself inconsistent")
    os.exit(2)
end
if w ~= WORD then
    print("HARNESS ERROR: stored flash file does not hold the guest's word")
    os.exit(2)
end
if rel ~= rec or not ver then
    print("FAIL: after replace_memory_range on a SHARING_ALL machine, the stored directory's hash tree no longer "
        .. "commits to its flash contents (pending write-TLB dirty mark lost): reloaded root " .. hex(rel)
        .. " ~= recomputed root " .. hex(rec) .. ", verify_hash_tree=" .. tostring(ver))
    os.exit(1)
end
print("OK: stored directory stays consistent after replace_memory_range")
os.exit(0)
