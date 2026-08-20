#!/usr/bin/env lua5.4
-- Copy-and-patch stencil extractor (see copy-patch-rvvm.md).
--
-- Parses the ELF64 relocatable object produced from cp-stencils.c (compiled
-- with -ffunction-sections --target=aarch64-unknown-linux-gnu -fno-pic
-- -mcmodel=large), validates that every stencil is expressible by the
-- supported patch kinds, and emits a C header with the code bytes, patch
-- descriptors, and placement lookup tables, plus a readable manifest.
--
-- Validation is fail-closed: any unknown relocation type, unexpected target
-- symbol, nonzero addend, misaligned or out-of-bounds or overlapping patch,
-- or malformed section layout aborts with an error.
--
-- Usage: lua5.4 cp-extract.lua <stencils.o> <output.h> <output-manifest.txt>

local obj_path = assert(arg[1], "usage: cp-extract.lua <obj> <header> <manifest>")
local hdr_path = assert(arg[2])
local man_path = assert(arg[3])

local function die(fmt, ...)
    io.stderr:write("cp-extract: " .. fmt:format(...) .. "\n")
    os.exit(1)
end

local f = assert(io.open(obj_path, "rb"))
local data = f:read("a")
f:close()

-- ELF64 file-header field offsets (unpack positions are 1-based, so each is
-- the ELF spec offset plus one).
local EI_CLASS, EI_DATA = 5, 6
local ELFCLASS64, ELFDATA2LSB = 2, 1
local E_MACHINE_POS = 0x12 + 1
local E_SHOFF_POS = 0x28 + 1
local E_SHENTSIZE_POS = 0x3a + 1
local E_SHNUM_POS = 0x3c + 1
local E_SHSTRNDX_POS = 0x3e + 1
local EM_AARCH64, EM_X86_64 = 183, 62
local SHDR_SIZE, SYM_SIZE, RELA_SIZE = 64, 24, 24

-- Instruction encodings verified at patch sites before a field rewrite is
-- declared legal.
local A64_B_OPCODE, A64_B_MASK = 0x14000000, 0xfc000000 -- unconditional B
local A64_MOV_WIDE_BITS = 0x25 -- movz/movk share bits 23-28 = 100101
local X86_JMP_REL32 = 0xe9 -- jmp rel32 opcode byte
local X86_TWOBYTE, X86_JCC_LO, X86_JCC_HI = 0x0f, 0x80, 0x8f -- jcc rel32

-- ELF64 header
if data:sub(1, 4) ~= "\127ELF" then
    die("%s is not an ELF object", obj_path)
end
if data:byte(EI_CLASS) ~= ELFCLASS64 or data:byte(EI_DATA) ~= ELFDATA2LSB then
    die("expected ELF64 little-endian")
end
local e_machine = string.unpack("<I2", data, E_MACHINE_POS)
local arch
if e_machine == EM_AARCH64 then
    arch = "aarch64"
elseif e_machine == EM_X86_64 then
    arch = "x86_64"
else
    die("expected EM_AARCH64 or EM_X86_64, got machine %d", e_machine)
end
local e_shoff = string.unpack("<I8", data, E_SHOFF_POS)
local e_shentsize = string.unpack("<I2", data, E_SHENTSIZE_POS)
local e_shnum = string.unpack("<I2", data, E_SHNUM_POS)
local e_shstrndx = string.unpack("<I2", data, E_SHSTRNDX_POS)
if e_shentsize ~= SHDR_SIZE then
    die("unexpected section header entry size %d", e_shentsize)
end

-- Section headers
local sections = {}
for i = 0, e_shnum - 1 do
    local base = e_shoff + i * SHDR_SIZE + 1
    local name_off, sh_type, flags, _, offset, size, link, info, _, entsize =
        string.unpack("<I4I4I8I8I8I8I4I4I8I8", data, base)
    sections[i] = {
        name_off = name_off,
        type = sh_type,
        flags = flags,
        offset = offset,
        size = size,
        link = link,
        info = info,
        entsize = entsize,
    }
end
local shstr = sections[e_shstrndx]
local function str_at(tab_off, off)
    local s = data:match("^[^\0]*", tab_off + off + 1)
    return s or ""
end
for i = 0, e_shnum - 1 do
    sections[i].name = str_at(shstr.offset, sections[i].name_off)
end

-- Symbol table
local SHT_SYMTAB, SHT_RELA, SHT_PROGBITS = 2, 4, 1
local symtab, strtab
for i = 0, e_shnum - 1 do
    if sections[i].type == SHT_SYMTAB then
        symtab = sections[i]
        strtab = sections[symtab.link]
    end
end
if not symtab then
    die("no symbol table")
end
local syms = {}
local nsyms = symtab.size // SYM_SIZE
for i = 0, nsyms - 1 do
    local base = symtab.offset + i * SYM_SIZE + 1
    local name_off, info, _, shndx, value, size = string.unpack("<I4BBI2I8I8", data, base)
    syms[i] = { name = str_at(strtab.offset, name_off), info = info, shndx = shndx, value = value, size = size }
end

-- Supported relocations and hole symbols
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
local CONT_ORDINAL = { cp_cont_0 = 0, cp_cont_1 = 1 }
local IMM_ORDINAL = { cp_imm64_0 = 0, cp_imm64_1 = 1 }

-- Collect stencils from .text.cp_* sections
local stencils = {}
local rela_by_target = {}
for i = 0, e_shnum - 1 do
    local s = sections[i]
    if s.type == SHT_RELA then
        rela_by_target[s.info] = s
    end
end

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
        -- Exactly one defined function symbol spanning the whole section.
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
            die("%s: symbol does not span section (value %d size %d, section %d)", name, found.value, found.size,
                s.size)
        end

        local code = data:sub(s.offset + 1, s.offset + s.size)
        local patches = {}
        local seen_off = {}
        local rela = rela_by_target[i]
        if rela then
            local nrel = rela.size // RELA_SIZE
            for r = 0, nrel - 1 do
                local base = rela.offset + r * RELA_SIZE + 1
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
                        -- rel32 field of jmp (e9) or jcc (0f 8x)
                        local jmp = off >= 1 and code:byte(off) == X86_JMP_REL32
                        local jcc = off >= 2 and code:byte(off - 1) == X86_TWOBYTE and code:byte(off) >= X86_JCC_LO
                            and code:byte(off) <= X86_JCC_HI
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

if #stencils == 0 then
    die("no cp_* stencil sections found")
end
table.sort(stencils, function(a, b)
    return a.name < b.name
end)

-- Emit header
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

-- Placement lookup tables for enumerated families.
local by_name = {}
for _, st in ipairs(stencils) do
    by_name[st.name] = true
end
local function table3(family)
    hdr:write(("static const cp_stencil_t *const cp_%s_table[8][8][8] = {\n"):format(family))
    for d = 0, 7 do
        hdr:write("{")
        for s1 = 0, 7 do
            hdr:write("{")
            local row = {}
            for s2 = 0, 7 do
                local n = ("cp_%s_%d_%d_%d"):format(family, d, s1, s2)
                if not by_name[n] then
                    die("missing enumerated stencil %s", n)
                end
                row[#row + 1] = "&cp_s_" .. n
            end
            hdr:write(table.concat(row, ","), "},")
        end
        hdr:write("},\n")
    end
    hdr:write("};\n")
end
local function table2(family)
    hdr:write(("static const cp_stencil_t *const cp_%s_table[8][8] = {\n"):format(family))
    for a = 0, 7 do
        local row = {}
        for b = 0, 7 do
            local n = ("cp_%s_%d_%d"):format(family, a, b)
            if not by_name[n] then
                die("missing enumerated stencil %s", n)
            end
            row[#row + 1] = "&cp_s_" .. n
        end
        hdr:write("{", table.concat(row, ","), "},\n")
    end
    hdr:write("};\n")
end
local function table1(family)
    local row = {}
    for a = 0, 7 do
        local n = ("cp_%s_%d"):format(family, a)
        if not by_name[n] then
            die("missing enumerated stencil %s", n)
        end
        row[#row + 1] = "&cp_s_" .. n
    end
    hdr:write(("static const cp_stencil_t *const cp_%s_table[8] = {%s};\n"):format(family, table.concat(row, ",")))
end

table3("add")
table2("addi")
table2("beq")
table2("ld")
table1("li")

hdr:write("\n#endif\n")
hdr:close()
man:close()

io.write(("cp-extract: %d stencils validated\n"):format(#stencils))
