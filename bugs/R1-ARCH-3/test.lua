#!/usr/bin/env lua5.4
-- R1-ARCH-3: page-table walks must honor physical-memory attributes on the PTE accesses themselves.
-- RISC-V privileged spec, "Virtual Address Translation Process" (Sv39): step 2, "If accessing pte violates a PMA or
-- PMP check, raise an access-fault exception corresponding to the original access type"; and, since the emulator
-- updates A/D in hardware, step 7: the PTE update "if this access violates a PMA or PMP check, raise an access-fault
-- exception corresponding to the original access type". Translation never succeeds with A (or D, for stores) left clear.
-- src/translate-virtual-address.hpp ignores the result of write_ram_uint64 for the A/D update ("Can't fail since read
-- succeeded earlier"), which is false for a read-only memory range (readable, not writeable), and returns plain
-- "false" when the PTE read fails, which callers turn into a page fault instead of an access fault.
-- The bare-metal guest ptro.S (built at test time) runs, in S-mode with Sv39:
--   0 fetch through a PTE with A=0 in a read-only flash drive   -> expect instruction access fault (1)
--   1 load  through a PTE with A=0 in a read-only flash drive   -> expect load access fault (5)
--   2 store through a PTE with D=0 in a read-only flash drive   -> expect store/AMO access fault (7)
--   3 fetch with satp's root table in the CLINT device range    -> expect instruction access fault (1)
--   4 fetch with satp's root table in an unmapped address hole  -> expect instruction access fault (1)
--   5 control: fetch through a PTE with A=0 in RAM              -> ecall from S (9), and A gets set
-- It runs natively and on the uarch (the path the on-chain step verifier mirrors), checks both agree, then asserts
-- the architecturally required outcomes. Exits 1 while the defect is present.
local cartesi = require("cartesi")

local tmp = os.tmpname()
os.remove(tmp)
assert(os.execute("mkdir -p " .. tmp))
local function cleanup() os.execute("rm -rf " .. tmp) end
if not os.execute("bash ./build.sh " .. tmp) then
    cleanup()
    io.stderr:write("harness error: could not build ptro.S\n")
    os.exit(2)
end
local bin = tmp .. "/ptro.bin"

-- Read-only page table image: Sv39 root with gigapage leaves mapping onto physical 0x80000000 (ppn 0x80000).
local PPN = 0x80000 << 10
local V, R, W, X, A, D = 0x1, 0x2, 0x4, 0x8, 0x40, 0x80
local RO_PT, RAM_PT, RESULT = 0x100000000, 0x80006000, 0x80008000
local ro_entries = {
    [2] = PPN | V | R | X | A, -- code, A already set: no update needed
    [3] = PPN | V | R | W | X, -- A=0: the load case needs A set
    [4] = PPN | V | R | W | A, -- D=0: the store case needs D set
    [5] = PPN | V | R | X, -- A=0: the fetch case needs A set
}
local pt = {}
for i = 0, 511 do pt[#pt + 1] = string.pack("<I8", ro_entries[i] or 0) end
local ptfile = tmp .. "/pt.bin"
local f = assert(io.open(ptfile, "wb"))
f:write(table.concat(pt))
f:close()

local CASES = {
    { name = "fetch via RO PTE with A=0", want = 1, tval = 0x140000000 },
    { name = "load via RO PTE with A=0", want = 5, tval = 0xC0005000 },
    { name = "store via RO PTE with D=0", want = 7, tval = 0x100005000 },
    { name = "fetch, root table in CLINT", want = 1 },
    { name = "fetch, root table in hole", want = 1 },
    { name = "control: fetch via RAM PTE A=0", want = 9 },
}

local function new_machine()
    return cartesi.machine({
        ram = { length = 1 << 20, backing_store = { data_filename = bin } },
        flash_drive = { { start = RO_PT, length = 4096, read_only = true, backing_store = { data_filename = ptfile } } },
    })
end

local function collect(m)
    assert(m:read_reg("iflags_H") ~= 0, "harness error: guest did not halt")
    assert(m:read_reg("htif_tohost_data") >> 1 == 0, "harness error: guest exit code nonzero")
    local r = {}
    for i = 0, #CASES - 1 do
        local cause, tval = string.unpack("<I8I8", m:read_memory(RESULT + 16 * i, 16))
        r[i + 1] = { cause = cause, tval = tval }
    end
    r.ro = {}
    for i = 2, 5 do r.ro[i] = string.unpack("<I8", m:read_memory(RO_PT + 8 * i, 8)) end
    r.ram_pte = string.unpack("<I8", m:read_memory(RAM_PT + 16, 8))
    return r, m:get_root_hash(), m:read_reg("mcycle")
end

local function run_native()
    local m <close> = new_machine()
    m:run(100000)
    return collect(m)
end

local function run_uarch()
    local m <close> = new_machine()
    local n = 0
    while m:read_reg("iflags_H") == 0 do
        if m:run_uarch() == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then m:reset_uarch() end
        n = n + 1
        assert(n < 100000, "harness error: uarch run did not halt")
    end
    return collect(m)
end

local ok_n, nres, nhash, ncycle = pcall(run_native)
local ok_u, ures, uhash, ucycle = pcall(run_uarch)
cleanup()
if not ok_n or not ok_u then
    io.stderr:write("harness error: ", tostring(ok_n and ures or nres), "\n")
    os.exit(2)
end

for i, c in ipairs(CASES) do
    print(string.format("case %d %-32s native: mcause=%2d mtval=0x%09x | uarch: mcause=%2d mtval=0x%09x | want %d",
        i - 1, c.name, nres[i].cause, nres[i].tval, ures[i].cause, ures[i].tval, c.want))
end
print(string.format("read-only PTEs after run: [3]=0x%x [4]=0x%x [5]=0x%x; RAM PTE after run: 0x%x",
    nres.ro[3], nres.ro[4], nres.ro[5], nres.ram_pte))
print(string.format("native mcycle=%d uarch mcycle=%d root hashes %s", ncycle, ucycle,
    nhash == uhash and "equal" or "DIFFER"))
if nhash ~= uhash or ncycle ~= ucycle then
    print("FAIL: native and uarch paths diverge (unexpected, different bug)")
    os.exit(3)
end
-- Control must behave: a RAM-resident PTE gets A set and the S-mode code runs.
if nres[6].cause ~= 9 or nres.ram_pte & A == 0 then
    print("harness error: control case (RAM page table) did not behave as expected")
    os.exit(2)
end

local failed = {}
for i = 1, 5 do
    local c, r = CASES[i], nres[i]
    if r.cause ~= c.want or (c.tval and r.tval ~= c.tval) then
        failed[#failed + 1] = string.format("case %d (%s) got mcause %d, want %d", i - 1, c.name, r.cause, c.want)
    end
end
if #failed > 0 then
    print("FAIL: page walk ignores PMA failures on PTE accesses (A/D update to read-only memory silently dropped, " ..
        "PTE load from non-memory raises page fault instead of access fault): " .. table.concat(failed, "; "))
    os.exit(1)
end
print("OK: PTE accesses that violate PMAs raise access faults on native and uarch paths")
