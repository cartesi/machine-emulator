#!/usr/bin/env lua5.4
-- Copy-and-patch stencil extractor (see copy-patch-rvvm.md).
--
-- Consumes one or more stencil objects, validates that every stencil is
-- expressible by the supported patch kinds, and emits a C header with the
-- code bytes, patch descriptors, and placement lookup tables, plus a
-- readable manifest.
--
-- Two container formats:
-- - ELF64 (the structural C TU, compiled bare-metal; and every TU on Linux
--   hosts): full patch-kind set, one .text.cp_* section per stencil.
-- - Mach-O arm64 (the semantic C++ TU compiled natively on macOS): branch
--   relocations only (ARM64_RELOC_BRANCH26 patches the same B field as
--   ELF's JUMP26); function extents come from symbol boundaries and the
--   true stencil size is the last relocation plus four, with trailing
--   alignment padding validated and dropped.
--
-- Validation is fail-closed: any unknown relocation type, unexpected target
-- symbol, bad addend, misaligned or out-of-bounds or overlapping patch,
-- malformed layout, duplicate stencil, or unexpected trailing bytes aborts.
--
-- Usage: lua5.4 cp-extract.lua <output.h> <output-manifest.txt> <obj>...

local hdr_path = assert(arg[1], "usage: cp-extract.lua <header> <manifest> <obj>...")
local man_path = assert(arg[2])
if arg[3] == nil then
    io.stderr:write("cp-extract: no input objects\n")
    os.exit(1)
end

local function die(fmt, ...)
    io.stderr:write("cp-extract: " .. fmt:format(...) .. "\n")
    os.exit(1)
end

local CONT_ORDINAL = { cp_cont_0 = 0, cp_cont_1 = 1 }
local IMM_ORDINAL = { cp_imm64_0 = 0, cp_imm64_1 = 1 }

-- Instruction encodings verified at patch sites before a field rewrite is
-- declared legal.
local A64_B_OPCODE, A64_B_MASK = 0x14000000, 0xfc000000 -- unconditional B
local A64_MOV_WIDE_BITS = 0x25 -- movz/movk share bits 23-28 = 100101
local A64_NOP = 0xd503201f
local X86_JMP_REL32 = 0xe9 -- jmp rel32 opcode byte
local X86_TWOBYTE, X86_JCC_LO, X86_JCC_HI = 0x0f, 0x80, 0x8f -- jcc rel32

--------------------------------------------------------------------------
-- ELF64 relocatable objects
--------------------------------------------------------------------------

local EM_AARCH64, EM_X86_64 = 183, 62
local SHT_SYMTAB, SHT_RELA, SHT_PROGBITS = 2, 4, 1

local function parse_elf(data, path)
    if data:byte(5) ~= 2 or data:byte(6) ~= 1 then
        die("%s: expected ELF64 little-endian", path)
    end
    local e_machine = string.unpack("<I2", data, 0x12 + 1)
    local arch
    if e_machine == EM_AARCH64 then
        arch = "aarch64"
    elseif e_machine == EM_X86_64 then
        arch = "x86_64"
    else
        die("%s: expected EM_AARCH64 or EM_X86_64, got machine %d", path, e_machine)
    end
    local e_shoff = string.unpack("<I8", data, 0x28 + 1)
    local e_shentsize = string.unpack("<I2", data, 0x3a + 1)
    local e_shnum = string.unpack("<I2", data, 0x3c + 1)
    local e_shstrndx = string.unpack("<I2", data, 0x3e + 1)
    if e_shentsize ~= 64 then
        die("%s: unexpected section header entry size %d", path, e_shentsize)
    end

    local sections = {}
    for i = 0, e_shnum - 1 do
        local base = e_shoff + i * 64 + 1
        local name_off, sh_type, flags, _, offset, size, link, info = string.unpack("<I4I4I8I8I8I8I4I4", data, base)
        sections[i] =
            { name_off = name_off, type = sh_type, flags = flags, offset = offset, size = size, link = link,
                info = info }
    end
    local shstr = sections[e_shstrndx]
    local function str_at(tab_off, off)
        return data:match("^[^\0]*", tab_off + off + 1) or ""
    end
    for i = 0, e_shnum - 1 do
        sections[i].name = str_at(shstr.offset, sections[i].name_off)
    end

    local symtab, strtab
    for i = 0, e_shnum - 1 do
        if sections[i].type == SHT_SYMTAB then
            symtab = sections[i]
            strtab = sections[symtab.link]
        end
    end
    if not symtab then
        die("%s: no symbol table", path)
    end
    local syms = {}
    local nsyms = symtab.size // 24
    for i = 0, nsyms - 1 do
        local base = symtab.offset + i * 24 + 1
        local name_off, info, _, shndx, value, size = string.unpack("<I4BBI2I8I8", data, base)
        syms[i] = { name = str_at(strtab.offset, name_off), info = info, shndx = shndx, value = value, size = size }
    end

    local RELOC_KIND
    if arch == "aarch64" then
        RELOC_KIND = {
            [264] = "G0", -- R_AARCH64_MOVW_UABS_G0_NC
            [266] = "G1", -- R_AARCH64_MOVW_UABS_G1_NC
            [268] = "G2", -- R_AARCH64_MOVW_UABS_G2_NC
            [269] = "G3", -- R_AARCH64_MOVW_UABS_G3
            [282] = "JUMP26", -- R_AARCH64_JUMP26
        }
    else
        RELOC_KIND = {
            [1] = "ABS64", -- R_X86_64_64
            [2] = "JMPREL32", -- R_X86_64_PC32
            [4] = "JMPREL32", -- R_X86_64_PLT32
        }
    end

    local rela_by_target = {}
    for i = 0, e_shnum - 1 do
        if sections[i].type == SHT_RELA then
            rela_by_target[sections[i].info] = sections[i]
        end
    end

    local stencils = {}
    for i = 0, e_shnum - 1 do
        local s = sections[i]
        local name = s.name:match("^%.text%.(cp_.+)$")
        if s.type == SHT_PROGBITS and name then
            if s.flags & 0x4 == 0 then
                die("%s: section not executable", name)
            end
            if s.size == 0 or (arch == "aarch64" and s.size % 4 ~= 0) then
                die("%s: bad section size %d", name, s.size)
            end
            local found
            for j = 0, nsyms - 1 do
                local sym = syms[j]
                -- "$x"/"$d" are AArch64 mapping symbols, not functions
                if sym.shndx == i and sym.name ~= "" and sym.name:sub(1, 1) ~= "$" then
                    if found then
                        die("%s: multiple symbols in section", name)
                    end
                    found = sym
                end
            end
            if not found or found.name ~= name then
                die("%s: missing or misnamed function symbol", name)
            end
            if found.value ~= 0 or found.size ~= s.size then
                die("%s: symbol does not span section (value %d size %d, section %d)", name, found.value,
                    found.size, s.size)
            end

            local code = data:sub(s.offset + 1, s.offset + s.size)
            local patches = {}
            local seen_off = {}
            local rela = rela_by_target[i]
            if rela then
                local nrel = rela.size // 24
                for r = 0, nrel - 1 do
                    local base = rela.offset + r * 24 + 1
                    local off, info, addend = string.unpack("<I8I8i8", data, base)
                    local rtype = info & 0xffffffff
                    local rsym = info >> 32
                    local kind = RELOC_KIND[rtype]
                    if not kind then
                        die("%s: unsupported relocation type %d at +%d", name, rtype, off)
                    end
                    local width = kind == "ABS64" and 8 or 4
                    if off + width > s.size then
                        die("%s: out-of-bounds patch at +%d", name, off)
                    end
                    if arch == "aarch64" and off % 4 ~= 0 then
                        die("%s: misaligned patch at +%d", name, off)
                    end
                    if seen_off[off] then
                        die("%s: overlapping patches at +%d", name, off)
                    end
                    seen_off[off] = true
                    local target = syms[rsym] and syms[rsym].name or "?"
                    local ordinal
                    if kind == "JUMP26" or kind == "JMPREL32" then
                        ordinal = CONT_ORDINAL[target]
                        if not ordinal then
                            die("%s: %s to unexpected symbol %s", name, kind, target)
                        end
                        if kind == "JUMP26" then
                            if addend ~= 0 then
                                die("%s: JUMP26 with addend %d at +%d", name, addend, off)
                            end
                            local insn = string.unpack("<I4", code, off + 1)
                            if insn & A64_B_MASK ~= A64_B_OPCODE then
                                die("%s: JUMP26 patch site +%d is not a B instruction (%08x)", name, off, insn)
                            end
                        else
                            if addend ~= -4 then
                                die("%s: JMPREL32 with addend %d at +%d", name, addend, off)
                            end
                            local jmp = off >= 1 and code:byte(off) == X86_JMP_REL32
                            local jcc = off >= 2 and code:byte(off - 1) == X86_TWOBYTE and
                                code:byte(off) >= X86_JCC_LO and code:byte(off) <= X86_JCC_HI
                            if not jmp and not jcc then
                                die("%s: JMPREL32 patch site +%d is not jmp/jcc rel32", name, off)
                            end
                        end
                    else
                        ordinal = IMM_ORDINAL[target]
                        if not ordinal then
                            die("%s: %s to unexpected symbol %s", name, kind, target)
                        end
                        if kind == "ABS64" then
                            if addend < 0 then
                                die("%s: ABS64 with negative addend %d at +%d", name, addend, off)
                            end
                        else
                            if addend ~= 0 then
                                die("%s: %s with addend %d at +%d", name, kind, addend, off)
                            end
                            local insn = string.unpack("<I4", code, off + 1)
                            if (insn >> 23) & 0x3f ~= A64_MOV_WIDE_BITS then
                                die("%s: %s patch site +%d is not movz/movk (%08x)", name, kind, off, insn)
                            end
                        end
                    end
                    patches[#patches + 1] = { offset = off, kind = kind, ordinal = ordinal, addend = addend }
                end
            end
            table.sort(patches, function(a, b)
                return a.offset < b.offset
            end)
            stencils[#stencils + 1] = { name = name, code = code, patches = patches }
        end
    end
    return stencils
end

--------------------------------------------------------------------------
-- Mach-O arm64 relocatable objects (semantic TU compiled natively on macOS)
--------------------------------------------------------------------------

local MACHO_MAGIC_64 = 0xfeedfacf
local CPU_TYPE_ARM64 = 0x0100000c
local LC_SEGMENT_64, LC_SYMTAB = 0x19, 0x2
local ARM64_RELOC_BRANCH26 = 2

local function parse_macho(data, path)
    local cputype = string.unpack("<I4", data, 5)
    if cputype ~= CPU_TYPE_ARM64 then
        die("%s: expected Mach-O arm64, got cputype 0x%x", path, cputype)
    end
    local ncmds = string.unpack("<I4", data, 17)
    local pos = 33 -- after the 32-byte mach_header_64
    local text -- {offset, size, reloff, nreloc}
    local text_ordinal
    local symoff, nsyms, stroff
    local ordinal = 0
    for _ = 1, ncmds do
        local cmd, cmdsize = string.unpack("<I4I4", data, pos)
        if cmd == LC_SEGMENT_64 then
            local nsects = string.unpack("<I4", data, pos + 64)
            for sect = 0, nsects - 1 do
                local sbase = pos + 72 + sect * 80
                local sectname = data:match("^[^\0]*", sbase)
                local segname = data:match("^[^\0]*", sbase + 16)
                local _, size, offset, _, reloff, nreloc = string.unpack("<I8I8I4I4I4I4", data, sbase + 32)
                ordinal = ordinal + 1
                if segname == "__TEXT" and sectname == "__text" then
                    text = { offset = offset, size = size, reloff = reloff, nreloc = nreloc }
                    text_ordinal = ordinal
                end
            end
        elseif cmd == LC_SYMTAB then
            symoff, nsyms, stroff = string.unpack("<I4I4I4", data, pos + 8)
        end
        pos = pos + cmdsize
    end
    if not text then
        die("%s: no (__TEXT,__text) section", path)
    end
    if not symoff then
        die("%s: no symbol table", path)
    end

    -- Symbols: nlist_64 records; keep _cp_* defined in __text plus the
    -- full list for relocation targets.
    local syms = {}
    local funcs = {}
    for i = 0, nsyms - 1 do
        local base = symoff + i * 16 + 1
        local n_strx, _, n_sect, _, n_value = string.unpack("<I4BBI2I8", data, base)
        local name = data:match("^[^\0]*", stroff + n_strx + 1) or ""
        syms[i] = { name = name, sect = n_sect, value = n_value }
        if n_sect == text_ordinal and name:sub(1, 4) == "_cp_" then
            funcs[#funcs + 1] = { name = name:sub(2), start = n_value }
        end
    end
    if #funcs == 0 then
        die("%s: no cp_* symbols in __text", path)
    end
    table.sort(funcs, function(a, b)
        return a.start < b.start
    end)
    for i = 1, #funcs do
        funcs[i].limit = i < #funcs and funcs[i + 1].start or text.size
        funcs[i].patches = {}
    end

    -- Relocations: branch continuations only in this format.
    local function func_at(addr)
        local lo, hi = 1, #funcs
        while lo < hi do
            local mid = (lo + hi + 1) // 2
            if funcs[mid].start <= addr then
                lo = mid
            else
                hi = mid - 1
            end
        end
        return funcs[lo]
    end
    for r = 0, text.nreloc - 1 do
        local base = text.reloff + r * 8 + 1
        local r_address, info = string.unpack("<i4I4", data, base)
        local symnum = info & 0xffffff
        local pcrel = (info >> 24) & 1
        local length = (info >> 25) & 3
        local extern = (info >> 27) & 1
        local rtype = (info >> 28) & 0xf
        if rtype ~= ARM64_RELOC_BRANCH26 or pcrel ~= 1 or length ~= 2 or extern ~= 1 then
            die("%s: unsupported Mach-O relocation (type %d pcrel %d length %d extern %d) at +%d", path, rtype,
                pcrel, length, extern, r_address)
        end
        local target = syms[symnum] and syms[symnum].name or "?"
        local ordinal_ = CONT_ORDINAL[target:sub(2)]
        if not ordinal_ then
            die("%s: BRANCH26 to unexpected symbol %s at +%d", path, target, r_address)
        end
        local fn = func_at(r_address)
        if r_address < fn.start or r_address + 4 > fn.limit or r_address % 4 ~= 0 then
            die("%s: relocation at +%d outside or misaligned in %s", path, r_address, fn.name)
        end
        local off = r_address - fn.start
        local insn = string.unpack("<I4", data, text.offset + r_address + 1)
        if insn & A64_B_MASK ~= A64_B_OPCODE then
            die("%s: BRANCH26 patch site +%d is not a B instruction (%08x)", fn.name, off, insn)
        end
        fn.patches[#fn.patches + 1] = { offset = off, kind = "JUMP26", ordinal = ordinal_, addend = 0 }
    end

    -- True size is the last relocation plus four; trailing bytes up to the
    -- next symbol must be alignment padding.
    local stencils = {}
    for _, fn in ipairs(funcs) do
        if #fn.patches == 0 then
            die("%s: no continuation relocation (every semantic stencil ends in a branch)", fn.name)
        end
        table.sort(fn.patches, function(a, b)
            return a.offset < b.offset
        end)
        local seen = {}
        for _, p in ipairs(fn.patches) do
            if seen[p.offset] then
                die("%s: overlapping patches at +%d", fn.name, p.offset)
            end
            seen[p.offset] = true
        end
        local size = fn.patches[#fn.patches].offset + 4
        for pad = fn.start + size, fn.limit - 4, 4 do
            local word = string.unpack("<I4", data, text.offset + pad + 1)
            if word ~= 0 and word ~= A64_NOP then
                die("%s: unexpected trailing bytes at +%d (%08x)", fn.name, pad - fn.start, word)
            end
        end
        local code = data:sub(text.offset + fn.start + 1, text.offset + fn.start + size)
        stencils[#stencils + 1] = { name = fn.name, code = code, patches = fn.patches }
    end
    return stencils
end

--------------------------------------------------------------------------
-- Merge and emit
--------------------------------------------------------------------------

local stencils = {}
local by_name = {}
for i = 3, #arg do
    local f = assert(io.open(arg[i], "rb"))
    local data = f:read("a")
    f:close()
    local list
    if data:sub(1, 4) == "\127ELF" then
        list = parse_elf(data, arg[i])
    elseif string.unpack("<I4", data, 1) == MACHO_MAGIC_64 then
        list = parse_macho(data, arg[i])
    else
        die("%s: neither ELF64 nor Mach-O 64", arg[i])
    end
    for _, st in ipairs(list) do
        if by_name[st.name] then
            die("duplicate stencil %s (in %s)", st.name, arg[i])
        end
        by_name[st.name] = true
        stencils[#stencils + 1] = st
    end
end
if #stencils == 0 then
    die("no cp_* stencils found")
end
table.sort(stencils, function(a, b)
    return a.name < b.name
end)

local hdr = assert(io.open(hdr_path, "w"))
local man = assert(io.open(man_path, "w"))
hdr:write([[
/* Generated by tools/cp-extract.lua. Do not edit. */
#ifndef CP_STENCILS_TABLES_H
#define CP_STENCILS_TABLES_H
#include <stdint.h>

enum cp_patch_kind { CP_P_JUMP26, CP_P_G0, CP_P_G1, CP_P_G2, CP_P_G3, CP_P_ABS64, CP_P_JMPREL32 };
typedef struct {
    uint16_t offset;
    uint8_t kind;
    uint8_t ordinal;
    int32_t addend;
} cp_patch_t;
typedef struct {
    const uint8_t *code;
    uint16_t size;
    uint16_t npatches;
    const cp_patch_t *patches;
} cp_stencil_t;

]])

local KIND_ENUM = {
    JUMP26 = "CP_P_JUMP26",
    G0 = "CP_P_G0",
    G1 = "CP_P_G1",
    G2 = "CP_P_G2",
    G3 = "CP_P_G3",
    ABS64 = "CP_P_ABS64",
    JMPREL32 = "CP_P_JMPREL32",
}

for _, st in ipairs(stencils) do
    local bytes = {}
    for k = 1, #st.code do
        bytes[k] = string.format("%d", st.code:byte(k))
    end
    hdr:write(("static const uint8_t cp_code_%s[] = {%s};\n"):format(st.name, table.concat(bytes, ",")))
    if #st.patches > 0 then
        local recs = {}
        for _, p in ipairs(st.patches) do
            recs[#recs + 1] = ("{%d,%s,%d,%d}"):format(p.offset, KIND_ENUM[p.kind], p.ordinal, p.addend)
        end
        hdr:write(("static const cp_patch_t cp_patches_%s[] = {%s};\n"):format(st.name, table.concat(recs, ",")))
    end
    hdr:write(("static const cp_stencil_t cp_s_%s = {cp_code_%s, %d, %d, %s};\n"):format(st.name, st.name, #st.code,
        #st.patches, #st.patches > 0 and ("cp_patches_" .. st.name) or "0"))
    local pdesc = {}
    for _, p in ipairs(st.patches) do
        pdesc[#pdesc + 1] = ("%s@%d#%d%s"):format(p.kind, p.offset, p.ordinal,
            p.addend ~= 0 and ("+" .. p.addend) or "")
    end
    man:write(("%s size %d patches [%s]\n"):format(st.name, #st.code, table.concat(pdesc, " ")))
end

-- Placement lookup tables, discovered from stencil names: cp_<f>_d_s1_s2
-- families get [8][8][8] tables, cp_<f>_d_s [8][8], cp_<f>_d [8].
-- Completeness of every discovered family is enforced.
local fams = { [3] = {}, [2] = {}, [1] = {} }
for name in pairs(by_name) do
    local f3 = name:match("^cp_(.-)_([0-6])_([0-6])_([0-6])$")
    local f2 = not f3 and name:match("^cp_(.-)_([0-6])_([0-6])$")
    local f1 = not f3 and not f2 and name:match("^cp_(.-)_([0-6])$")
    if f3 then
        fams[3][f3] = true
    elseif f2 then
        fams[2][f2] = true
    elseif f1 then
        fams[1][f1] = true
    end
end
local function sorted_keys(t)
    local keys = {}
    for k in pairs(t) do
        keys[#keys + 1] = k
    end
    table.sort(keys)
    return keys
end
local function need(n)
    if not by_name[n] then
        die("incomplete enumerated family: missing %s", n)
    end
    return "&cp_s_" .. n
end
for _, fam in ipairs(sorted_keys(fams[3])) do
    hdr:write(("static const cp_stencil_t *const cp_%s_table[7][7][7] = {\n"):format(fam))
    for d = 0, 6 do
        hdr:write("{")
        for s1 = 0, 6 do
            hdr:write("{")
            local row = {}
            for s2 = 0, 6 do
                row[#row + 1] = need(("cp_%s_%d_%d_%d"):format(fam, d, s1, s2))
            end
            hdr:write(table.concat(row, ","), "},")
        end
        hdr:write("},\n")
    end
    hdr:write("};\n")
end
for _, fam in ipairs(sorted_keys(fams[2])) do
    hdr:write(("static const cp_stencil_t *const cp_%s_table[7][7] = {\n"):format(fam))
    for a = 0, 6 do
        local row = {}
        for b = 0, 6 do
            row[#row + 1] = need(("cp_%s_%d_%d"):format(fam, a, b))
        end
        hdr:write("{", table.concat(row, ","), "},\n")
    end
    hdr:write("};\n")
end
for _, fam in ipairs(sorted_keys(fams[1])) do
    local row = {}
    for a = 0, 6 do
        row[#row + 1] = need(("cp_%s_%d"):format(fam, a))
    end
    hdr:write(("static const cp_stencil_t *const cp_%s_table[7] = {%s};\n"):format(fam, table.concat(row, ",")))
end

hdr:write("\n#endif\n")
hdr:close()
man:close()

io.write(("cp-extract: %d stencils validated\n"):format(#stencils))
