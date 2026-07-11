-- uarch-cycle-profile.lua -- attribute one mcycle's uarch cycles to ELF symbols
--
-- PURPOSE
--   Answers "where do the uarch cycles of machine cycle N go?" by stepping the
--   microarchitecture one cycle at a time, reading uarch_pc before each cycle, and
--   bucketing the executed instruction into the ELF symbol that contains that pc.
--   Its motivating use: sizing what an ISA change (e.g. RV64I -> RV64IM) would save,
--   by reporting how many cycles sit inside the compiler's soft-multiply/divide
--   runtime (__muldi3, __udivdi3, __multi3, ...), which the M extension collapses
--   into single instructions. Also useful for any hot-spot hunt in the uarch build.
--
-- USAGE
--   source ~/ctsi2/setup-env.env && eval "$(luarocks path)" && eval $(make env)
--   lua5.4 tools/uarch-cycle-profile.lua <program.bin> <mcycle> [top_n] [elf]
--     program.bin  a bare-metal machine RAM image (tests/build/machine/*.bin)
--     mcycle       the machine cycle to profile (the uarch then interprets exactly
--                  this one mcycle; pick candidates from a cycle-count sweep such
--                  as .claude/benches/mcycle-corpus.csv, columns program,mcycle,cycles)
--     top_n        symbols to list individually (default 25)
--     elf          uarch ELF with symbols (default ../uarch/uarch-ram.elf relative
--                  to solidity-step/, i.e. run from the solidity-step directory)
--
-- HOW IT WORKS (for reproducing variants)
--   1. Symbols come from `nm --demangle --defined-only <elf>`, keeping text-ish
--      kinds (T/t/W/w), sorted by address; a pc belongs to the nearest symbol at
--      or below it. The uarch ELF is linked at its runtime base (RAM 0x600000),
--      so uarch_pc values map straight onto nm addresses -- verify this holds by
--      checking the "unmapped pc" bucket stays ~0.
--   2. machine:run(mcycle) advances the machine NATIVELY (fast) to just before the
--      target mcycle; machine:run_uarch(k) then executes uarch cycles up to k.
--      Stepping k = 1, 2, 3, ... executes one uarch cycle per call; uarch_pc read
--      before each call is the instruction that cycle executes.
--   3. The loop ends when uarch_halt_flag is set (the uarch signals mcycle done).
--
-- OUTPUT
--   One line per symbol (cycles, %, name), descending, then a summary line
--   "soft mul/div cycles" counting every symbol matching the libgcc/compiler-rt
--   integer helpers (__muldi3 __divdi3 __udivdi3 __moddi3 __umoddi3 and their
--   128-bit ti3 forms): that number is the theoretical maximum M-extension win
--   for this mcycle (an upper bound: with M each call site still spends a few
--   cycles on the mul/div instruction itself and argument setup).
--
-- COST: native run to the target mcycle plus ~2 FFI calls per uarch cycle;
-- an 18k-cycle mcycle profiles in seconds.

local cartesi = require("cartesi")

local prog, target = arg[1], tonumber(arg[2])
local top_n = tonumber(arg[3]) or 25
local elf = arg[4] or "../uarch/uarch-ram.elf"
assert(prog and target, "usage: uarch-cycle-profile.lua <program.bin> <mcycle> [top_n] [elf]")

local function load_symbols(path)
    local syms = {}
    local f = assert(io.popen("nm --demangle --defined-only " .. path))
    for line in f:lines() do
        local addr, kind, name = line:match("^(%x+) (%a) (.+)$")
        if addr and (kind == "T" or kind == "t" or kind == "W" or kind == "w") then
            syms[#syms + 1] = { addr = tonumber(addr, 16), name = name }
        end
    end
    f:close()
    assert(#syms > 0, "no text symbols found in " .. path .. " (wrong nm or stripped ELF?)")
    table.sort(syms, function(a, b) return a.addr < b.addr end)
    return syms
end

-- nearest symbol at or below pc (binary search); nil when pc precedes all symbols
local function sym_for(syms, pc)
    if pc < syms[1].addr then return nil end
    local lo, hi = 1, #syms
    while lo < hi do
        local mid = (lo + hi + 1) // 2
        if syms[mid].addr <= pc then lo = mid else hi = mid - 1 end
    end
    return syms[lo].name
end

local syms = load_symbols(elf)

local m = assert(cartesi.machine({
    ram = { length = 32 << 20, backing_store = { data_filename = prog } },
    flash_drive = { { start = 0x80000000000000, length = 0x40000 } },
}))
m:run(target)
assert(m:read_reg("mcycle") == target, "program halted before the target mcycle")

local counts, cycles = {}, 0
while m:read_reg("uarch_halt_flag") == 0 do
    local name = sym_for(syms, m:read_reg("uarch_pc")) or "(unmapped pc)"
    counts[name] = (counts[name] or 0) + 1
    cycles = cycles + 1
    m:run_uarch(cycles)
    assert(cycles <= 1 << 21, "runaway uarch execution (no halt)")
end

local rows = {}
for name, n in pairs(counts) do
    rows[#rows + 1] = { name = name, n = n }
end
table.sort(rows, function(a, b) return a.n > b.n end)

print(string.format("%s mcycle %d: %d uarch cycles, %d symbols touched", prog, target, cycles, #rows))
local softmuldiv, shown = 0, 0
for i, r in ipairs(rows) do
    if i <= top_n then
        print(string.format("%8d  %5.1f%%  %s", r.n, 100 * r.n / cycles, r.name))
        shown = shown + r.n
    end
    if r.name:match("^__u?(mul)[dts]i%d") or r.name:match("^__u?(div)[dts]i%d")
        or r.name:match("^__u?(mod)[dts]i%d") then
        softmuldiv = softmuldiv + r.n
    end
end
if cycles > shown then
    print(string.format("%8d  %5.1f%%  (all other symbols)", cycles - shown, 100 * (cycles - shown) / cycles))
end
print(string.format("soft mul/div cycles: %d (%.1f%%)  -- upper bound of the RV64IM win here",
    softmuldiv, 100 * softmuldiv / cycles))
