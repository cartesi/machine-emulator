#!/usr/bin/env lua5.4
-- R1-ARCH-2: SC.W/SC.D to a misaligned address must raise a store/AMO address-misaligned exception (mcause 6),
-- whether or not a reservation is held (RISC-V A extension, "Load-Reserved/Store-Conditional Instructions": "If the
-- address is not naturally aligned, an address-misaligned exception or an access-fault exception will be generated";
-- the Sail model checks alignment before matching the reservation). execute_SC in src/interpret.cpp only reaches the
-- alignment check through write_virtual_memory when ilrsc == vaddr, so with no reservation it silently writes rd = 1.
-- The test boots the bare-metal guest scmis.S (built at test time) and runs it both with the native interpreter and
-- with the uarch (the path the on-chain step verifier mirrors). It checks that both paths agree (root hash and
-- results) and then asserts the architecturally required outcome. Exits 1 while the defect is present.
local cartesi = require("cartesi")

local tmp = os.tmpname()
os.remove(tmp)
assert(os.execute("mkdir -p " .. tmp))
local function cleanup() os.execute("rm -rf " .. tmp) end
if not os.execute("bash ./build.sh " .. tmp) then
    cleanup()
    io.stderr:write("harness error: could not build scmis.S\n")
    os.exit(2)
end
local bin = tmp .. "/scmis.bin"

local RESULT = 0x80003000
local DATA = 0x80002000
local CASES = {
    { name = "sc.w misaligned, no reservation", addr = DATA + 1, want_cause = 6 },
    { name = "sc.d misaligned, no reservation", addr = DATA + 4, want_cause = 6 },
    { name = "sc.w aligned, no reservation (control)", addr = DATA, want_cause = 0, want_rd = 1 },
    { name = "sw misaligned (control)", addr = DATA + 1, want_cause = 6 },
}

local function new_machine()
    return cartesi.machine({ ram = { length = 1 << 20, backing_store = { data_filename = bin } } })
end

local function read_results(m)
    local r = {}
    for i = 0, #CASES - 1 do
        local s = m:read_memory(RESULT + 24 * i, 24)
        local cause, tval, rd = string.unpack("<I8I8I8", s)
        r[i + 1] = { cause = cause, tval = tval, rd = rd }
    end
    return r
end

local function run_native()
    local m <close> = new_machine()
    m:run(100000)
    assert(m:read_reg("iflags_H") ~= 0, "harness error: native run did not halt")
    assert(m:read_reg("htif_tohost_data") >> 1 == 0, "harness error: guest exit code nonzero")
    return read_results(m), m:get_root_hash(), m:read_reg("mcycle")
end

local function run_uarch()
    local m <close> = new_machine()
    local n = 0
    while m:read_reg("iflags_H") == 0 do
        if m:run_uarch() == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then m:reset_uarch() end
        n = n + 1
        assert(n < 100000, "harness error: uarch run did not halt")
    end
    assert(m:read_reg("htif_tohost_data") >> 1 == 0, "harness error: guest exit code nonzero")
    return read_results(m), m:get_root_hash(), m:read_reg("mcycle")
end

local nres, nhash, ncycle = run_native()
local ures, uhash, ucycle = run_uarch()
cleanup()

for i, c in ipairs(CASES) do
    print(string.format("case %d %-40s native: mcause=%d mtval=0x%x rd=0x%x | uarch: mcause=%d mtval=0x%x rd=0x%x",
        i - 1, c.name, nres[i].cause, nres[i].tval, nres[i].rd, ures[i].cause, ures[i].tval, ures[i].rd))
end
print(string.format("native mcycle=%d uarch mcycle=%d root hashes %s", ncycle, ucycle,
    nhash == uhash and "equal" or "DIFFER"))
-- The defect is claimed to be consistent across paths; a divergence would be a different (worse) bug.
if nhash ~= uhash or ncycle ~= ucycle then
    print("FAIL: native and uarch paths diverge (unexpected, different bug)")
    os.exit(3)
end

local failed = false
for i, c in ipairs(CASES) do
    local r = nres[i]
    local ok
    if c.want_cause ~= 0 then
        ok = r.cause == c.want_cause and r.tval == c.addr and r.rd == 0xdead
    else
        ok = r.cause == 0 and r.rd == c.want_rd
    end
    if not ok then
        failed = true
        if c.want_cause ~= 0 then
            print(string.format("FAIL: %s at 0x%x: expected store/AMO address-misaligned trap (mcause %d, mtval 0x%x), " ..
                "got mcause=%d and rd=%d (silent SC failure, no exception)", c.name, c.addr, c.want_cause, c.addr,
                r.cause, r.rd))
        else
            print(string.format("FAIL: %s: expected no trap and rd=%d, got mcause=%d rd=%d", c.name, c.want_rd,
                r.cause, r.rd))
        end
    end
end
if failed then os.exit(1) end
print("OK: misaligned SC.W/SC.D raise store/AMO address-misaligned exceptions on native and uarch paths")
