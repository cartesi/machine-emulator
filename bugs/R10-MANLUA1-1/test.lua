#!/usr/bin/env lua5.4
-- R10-MANLUA1-1: the HTIF Halt sub-device ignores the ihalt bit mask (src/htif-address-range.cpp htif_halt).
--
-- Manual (doc/README.md, HTIF section): "Registers ihalt, iconsole, and iyield are bit masks specifying the
-- commands that are available for the respective devices. Unavailable commands are silently ignored by the
-- machine." processor.registers.htif.ihalt is a documented config field (default 0x1). htif_yield and htif_console
-- check their masks; htif_halt does not read ihalt at all.
--
-- This test builds a bare-metal guest (halt.S) that writes tohost = 1 (DEV=HALT, CMD=HALT, DATA=1) and then spins.
-- It checks:
--   control: with ihalt = 1 the machine halts (iflags_H = 1), so the guest and harness are correct;
--   defect:  with ihalt = 0 the halt command is unavailable and must be silently ignored: run(1000) must reach
--            mcycle 1000 with iflags_H = 0 and break reason REACHED_TARGET_MCYCLE, on the native path and on the
--            uarch path (run_uarch + reset_uarch per mcycle).
-- It also checks that native and uarch agree on the root hash (the deviation is consistent across paths: Medium).
-- Exits nonzero while the defect is present.

local cartesi = require("cartesi")

local outdir = assert(io.popen("mktemp -d"):read("l"), "harness error: mktemp failed")
assert(os.execute("bash ./build.sh " .. outdir), "harness error: failed to build guest halt.bin")
local bin = outdir .. "/halt.bin"

local function make_machine(ihalt)
    return cartesi.machine({
        ram = { length = 0x10000, backing_store = { data_filename = bin } },
        processor = { registers = { htif = { ihalt = ihalt } } },
    })
end

local function cleanup() os.execute("rm -rf " .. outdir) end

-- Control: ihalt = 1 must halt.
do
    local m <close> = make_machine(1)
    assert(m:read_reg("htif_ihalt") == 1, "harness error: ihalt not set to 1")
    local br = m:run(1000)
    if br ~= cartesi.BREAK_REASON_HALTED or m:read_reg("iflags_H") ~= 1 then
        cleanup()
        error("harness error: control machine with ihalt=1 did not halt")
    end
    print(string.format("control ihalt=1: break_reason=%d iflags_H=%d mcycle=%d (halts, as expected)", br,
        m:read_reg("iflags_H"), m:read_reg("mcycle")))
end

local failures = {}

-- Native path, ihalt = 0.
local native <close> = make_machine(0)
assert(native:read_reg("htif_ihalt") == 0, "harness error: ihalt not set to 0")
local br = native:run(1000)
local nH, nmcycle = native:read_reg("iflags_H"), native:read_reg("mcycle")
print(string.format("native ihalt=0: break_reason=%d iflags_H=%d mcycle=%d tohost=0x%x", br, nH, nmcycle,
    native:read_reg("htif_tohost")))
if nH ~= 0 or br == cartesi.BREAK_REASON_HALTED or nmcycle ~= 1000 then
    failures[#failures + 1] = string.format("native: halted at mcycle %d (iflags_H=%d, break_reason=%d)", nmcycle, nH, br)
end

-- Uarch path, ihalt = 0: 8 mcycles via run_uarch + reset_uarch.
local uarch <close> = make_machine(0)
local UM = 8
for i = 1, UM do
    uarch:run_uarch(cartesi.UARCH_CYCLE_MAX)
    uarch:reset_uarch()
end
local uH, umcycle = uarch:read_reg("iflags_H"), uarch:read_reg("mcycle")
print(string.format("uarch  ihalt=0: after %d run_uarch/reset_uarch: iflags_H=%d mcycle=%d", UM, uH, umcycle))
if uH ~= 0 or umcycle ~= UM then
    failures[#failures + 1] = string.format("uarch: halted at mcycle %d (iflags_H=%d)", umcycle, uH)
end

-- Consistency: native and uarch should reach the same state (both halted at the same mcycle under the defect).
local ref <close> = make_machine(0)
ref:run(umcycle)
if ref:get_root_hash() ~= uarch:get_root_hash() then
    print("note: native and uarch root hashes DIFFER at mcycle " .. umcycle .. " (would be Critical, not Medium)")
else
    print("native and uarch agree on the root hash at mcycle " .. umcycle .. " (deviation consistent across paths)")
end

cleanup()

if #failures > 0 then
    print("FAIL: HTIF halt command executed although htif.ihalt=0 marks it unavailable (manual: silently ignored); "
        .. table.concat(failures, "; "))
    os.exit(1)
end
print("OK: halt command ignored when ihalt=0")
os.exit(0)
