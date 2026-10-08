#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local cartesi = require("cartesi")
local usage = [[Usage: uarch-page-xray.lua (--config CONFIG.json | --stored DIR) MCYCLE [UARCH.elf]
Trace one whole mcycle to revise the hot-function order in uarch/uarch-ram.ld.in.
Run after eval "$(make -s env)" from the repository root. MCYCLE is the cycle
before the instruction. Default ELF: uarch/uarch-ram.elf; NM selects the nm
executable (default riscv64-unknown-elf-nm). The ELF must match the guest image.
Output is text: executed code pages/symbols, data pages and witness geometry.
The machine must reach MCYCLE without external inputs and have a reset uarch.
]]
if arg[1] == "--help" then
    print(usage)
    return
end
assert((arg[1] == "--config" or arg[1] == "--stored") and arg[2] and arg[3] and not arg[5], usage)
local target = assert(math.tointeger(tonumber(arg[3])), "MCYCLE must be an integer")
assert(target >= 0, "MCYCLE must be nonnegative")
local function quote(s)
    return "'" .. s:gsub("'", "'\\''") .. "'"
end
local symbols = {}
local nm = assert(
    io.popen(
        quote(os.getenv("NM") or "riscv64-unknown-elf-nm")
            .. " -nS --defined-only --demangle "
            .. quote(arg[4] or "uarch/uarch-ram.elf"),
        "r"
    )
)
for line in nm:lines() do
    local address, size, kind, name = line:match("^(%x+)%s+(%x+)%s+(%a)%s+(.+)$")
    if not address then -- GNU nm omits the size column for zero-sized symbols.
        address, kind, name = line:match("^(%x+)%s+(%a)%s+(.+)$")
        size = "0"
    end
    if address then
        symbols[#symbols + 1] = { start = tonumber(address, 16), size = tonumber(size, 16), kind = kind, name = name }
    end
end
assert(nm:close(), "nm failed")
assert(#symbols > 0, "nm returned no symbols with sizes")
-- Assembly entry points may omit .size; bound those by the next symbol.
for i, s in ipairs(symbols) do
    if s.size == 0 and s.kind:match("[Tt]") and symbols[i + 1] then
        s.size = symbols[i + 1].start - s.start
    end
end
local function symbol_at(address)
    for _, s in ipairs(symbols) do
        if s.start <= address and address < s.start + s.size then
            return s.name
        end
    end
    return "<no sized symbol>"
end
local config = arg[2]
if arg[1] == "--config" then
    local f <close> = assert(io.open(config, "rb"))
    config = cartesi.fromjson(f:read("a"))
end
local options = { console = { output_destination = "to_null" } }
local m <close> = cartesi.machine(config, options)
local recorder <close> = cartesi.machine(config, options)
for _, machine in ipairs({ m, recorder }) do
    assert(machine:read_reg("mcycle") <= target, "machine is already past MCYCLE")
    machine:run(target)
    assert(machine:read_reg("mcycle") == target, "machine stopped before MCYCLE; supply a stored state after input")
    assert(machine:read_reg("uarch_cycle") == 0 and machine:read_reg("uarch_halt") == 0, "uarch must be reset")
end
local before = m:get_root_hash()
assert(before == recorder:get_root_hash(), "initial roots differ")
local limit = 1 << 20
local log = recorder:log_step_uarch(limit)
assert(recorder:read_reg("uarch_halt") ~= 0 and recorder:read_reg("mcycle") == target + 1, "not a whole mcycle")
assert(log:sub(1, 8) == "CTSI\3\0\0\0", "unsupported step-log format")
local pages, nodes, siblings = string.unpack("<I8I8I8", log, 17)
assert(nodes == 0 and #log == 40 + pages * 4136 + siblings * 32, "unexpected whole-mcycle log geometry")
assert(cartesi.machine:verify_step_uarch(before, log, limit) == recorder:get_root_hash(), "replay root differs")

local code, data, tables, ecalls = {}, {}, {}, {}
local cycles = 0
while m:read_reg("uarch_halt") == 0 do
    assert(cycles < limit, "uarch did not halt")
    local pc = m:read_reg("uarch_pc")
    local name = symbol_at(pc)
    local page = pc & ~4095
    code[page] = code[page] or { cycles = 0, symbols = {} }
    code[page].cycles = code[page].cycles + 1
    code[page].symbols[name] = (code[page].symbols[name] or 0) + 1
    local insn = string.unpack("<I4", m:read_memory(pc, 4))
    local op = insn & 127
    if op == 3 or op == 35 then -- RV64I loads/stores; bridge addresses are physical machine addresses.
        local rs1 = (insn >> 15) & 31
        local offset = op == 3 and insn >> 20 or ((insn >> 25) << 5) | ((insn >> 7) & 31)
        offset = offset >= 0x800 and offset - 0x1000 or offset
        local address = m:read_reg("uarch_x" .. rs1) + offset
        page = address & ~4095
        data[page] = true
        if name:find("translate_virtual_address", 1, true) and page >= cartesi.AR_RAM_START then
            tables[page] = true
        end
    elseif insn == 0x73 then
        local fn = m:read_reg("uarch_x17")
        ecalls[fn] = (ecalls[fn] or 0) + 1
    end
    cycles = cycles + 1
    m:run_uarch(cycles)
end
assert(
    cycles == recorder:read_reg("uarch_cycle") and m:get_root_hash() == recorder:get_root_hash(),
    "trace/log mismatch"
)
local function sorted_keys(t)
    local keys = {}
    for k in pairs(t) do
        keys[#keys + 1] = k
    end
    table.sort(keys)
    return keys
end
print(
    string.format(
        "mcycle %d: %d uarch cycles; %d witness pages; %d log bytes; %d siblings",
        target,
        cycles,
        pages,
        #log,
        siblings
    )
)
print(
    string.format(
        "verifyMcycle calldata: %d bytes (164 + padded log); gas: not measured",
        164 + ((#log + 31) // 32) * 32
    )
)
print("Uarch code pages (executed symbols; counts are cycles):")
for _, page in ipairs(sorted_keys(code)) do
    print(string.format("  0x%016x  %d cycles%s", page, code[page].cycles, data[page] and " (also data)" or ""))
    for _, name in ipairs(sorted_keys(code[page].symbols)) do
        print(string.format("    %d  %s", code[page].symbols[name], name))
    end
end
print("Other witness pages (page-table labels inferred from translation-function accesses):")
for i = 0, pages - 1 do
    local page = string.unpack("<I8", log, 41 + i * 4136) << 12
    if not code[page] then
        local kind
        if page == cartesi.AR_SHADOW_STATE_START then
            kind = "registers"
        elseif
            page >= cartesi.AR_SHADOW_TLB_START
            and page < cartesi.AR_SHADOW_TLB_START + cartesi.AR_SHADOW_TLB_LENGTH
        then
            kind = "TLB"
        elseif page == cartesi.AR_PMAS_START then
            kind = "PMA descriptors"
        elseif page == cartesi.AR_SHADOW_UARCH_STATE_START then
            kind = "uarch registers"
        elseif
            page >= cartesi.AR_UARCH_RAM_START and page < cartesi.AR_UARCH_RAM_START + cartesi.AR_UARCH_RAM_LENGTH
        then
            kind = "uarch data/stack"
        elseif tables[page] then
            kind = "page table"
        else
            kind = "RAM/device (macro code or data)"
        end
        print(string.format("  0x%016x  %s", page, kind))
        if kind == "uarch data/stack" then
            for _, s in ipairs(symbols) do
                if s.size > 0 and s.start < page + 4096 and s.start + s.size > page then
                    print("    " .. s.name)
                end
            end
        end
    end
end
for _, fn in ipairs(sorted_keys(ecalls)) do
    print(string.format("ECALL %d: %d", fn, ecalls[fn]))
end
print("Whole-log replay and single-step trace roots agree.")
