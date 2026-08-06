#!/usr/bin/env lua5.4

--[[
Mines copy-and-patch stencils out of a compiled interpret-tc-stencils.o and
emits interpret-tc-stencils.inc, the table the tail-call JIT copies from.

Usage: gen-tc-stencils.lua <object file> [interpret-tc-table.inc] > interpret-tc-stencils.inc

For each function named tc_stencil_* it extracts the machine code and every
relocation inside it. A relocation against a tc_h_* symbol is a hole: a place
the JIT writes an operand of the recorded instruction into the code. A
relocation against anything else means the stencil reaches out of itself, so
copying it to another address would not preserve its meaning; that is rejected
here rather than discovered later as a wrong root hash. The undefined-symbol
trip-wires the sources plant (a register index that never got scaled to a byte
offset, for instance) surface through the same check, by name.

This reads the object file directly instead of parsing a disassembler's output,
because the relocation offsets and addends are the whole product and text output
of them is a moving target across toolchains. Only the relocation types the
stencils actually produce are supported; an unknown one is an error, never a
silent skip.

The object must be compiled with -ffunction-sections, and not only to keep the
extraction tidy. A call between two functions of one section needs no
relocation, because the assembler already knows the distance; such a call would
copy into a trace as a branch to whatever happens to sit at that distance from
its new address. Giving every function its own section forces those calls to
become relocations against another section's symbol, which is to say it turns
the one class of escape this checker cannot see into the one class it rejects.
]]

local ELFCLASS64 = 2
local ELFDATA2LSB = 1
local SHT_SYMTAB = 2
local SHT_RELA = 4
local STT_FUNC = 2
local STT_OBJECT = 1

-- Relocation types, by machine. The value is how the patcher must write the
-- hole at that site; the interpreter side switches on the same names.
local RELOC = {
    -- x86-64
    [62] = {
        name = "x86_64",
        [10] = "ABS32", -- R_X86_64_32,   absolute, zero-extended
        [11] = "ABS32S", -- R_X86_64_32S,  absolute, sign-extended (addressing displacements)
        [1] = "ABS64", -- R_X86_64_64
        [2] = "REL32", -- R_X86_64_PC32
        [4] = "REL32", -- R_X86_64_PLT32, a direct call/jump; no PLT exists for a hole
    },
}

local function die(fmt, ...)
    io.stderr:write("gen-tc-stencils: " .. string.format(fmt, ...) .. "\n")
    os.exit(1)
end

local function read_file(path)
    local f = assert(io.open(path, "rb"), "cannot open " .. path)
    local data = f:read("a")
    f:close()
    return data
end

-- ELF64 little-endian reader ------------------------------------------------

local function parse_elf(data)
    if data:sub(1, 4) ~= "\127ELF" then
        die("not an ELF object")
    end
    if data:byte(5) ~= ELFCLASS64 or data:byte(6) ~= ELFDATA2LSB then
        die("only little-endian ELF64 objects are supported")
    end
    local machine = string.unpack("<I2", data, 19)
    local shoff = string.unpack("<I8", data, 41)
    local shentsize = string.unpack("<I2", data, 59)
    local shnum = string.unpack("<I2", data, 61)
    local shstrndx = string.unpack("<I2", data, 63)

    local sections = {}
    for i = 0, shnum - 1 do
        local o = shoff + (i * shentsize) + 1
        local s = {}
        s.name_off, s.type, s.flags, s.addr, s.offset, s.size, s.link, s.info = string.unpack("<I4I4I8I8I8I8I4I4",
            data, o)
        s.entsize = string.unpack("<I8", data, o + 56)
        s.index = i
        sections[i] = s
    end

    local shstr = sections[shstrndx]
    local function str(tab_off, off)
        local e = data:find("\0", tab_off + off + 1, true)
        return data:sub(tab_off + off + 1, e - 1)
    end
    for i = 0, shnum - 1 do
        sections[i].name = str(shstr.offset, sections[i].name_off)
    end

    return { data = data, machine = machine, sections = sections, shnum = shnum, str = str }
end

local function read_symbols(elf)
    local syms = {}
    for i = 0, elf.shnum - 1 do
        local sec = elf.sections[i]
        if sec.type == SHT_SYMTAB then
            local strtab = elf.sections[sec.link]
            local n = sec.size // 24
            for k = 0, n - 1 do
                local o = sec.offset + (k * 24) + 1
                local name_off, info, _, shndx, value, size = string.unpack("<I4I1I1I2I8I8", elf.data, o)
                syms[k] = {
                    name = elf.str(strtab.offset, name_off),
                    type = info & 0xf,
                    shndx = shndx,
                    value = value,
                    size = size,
                }
            end
            return syms
        end
    end
    die("no symbol table")
end

local function read_relocations(elf, syms, target_index)
    local relocs = {}
    for i = 0, elf.shnum - 1 do
        local sec = elf.sections[i]
        if sec.type == SHT_RELA and sec.info == target_index then
            local n = sec.size // 24
            for k = 0, n - 1 do
                local o = sec.offset + (k * 24) + 1
                local offset, info, addend = string.unpack("<I8I8i8", elf.data, o)
                relocs[#relocs + 1] = {
                    offset = offset,
                    sym = syms[info >> 32],
                    rtype = info & 0xffffffff,
                    addend = addend,
                }
            end
        end
    end
    table.sort(relocs, function(a, b)
        return a.offset < b.offset
    end)
    return relocs
end

-- Extraction ----------------------------------------------------------------

local objpath = arg[1] or die("usage: gen-tc-stencils.lua <object file>")
local elf = parse_elf(read_file(objpath))
local kinds = RELOC[elf.machine] or die("unsupported ELF machine %d", elf.machine)

local syms = read_symbols(elf)

-- One section per stencil, courtesy of -ffunction-sections
local stencils = {}
for _, s in pairs(syms) do
    if s.type == STT_FUNC and s.name:match("^tc_stencil_") then
        local sec = elf.sections[s.shndx]
        if sec.name ~= ".text." .. s.name then
            die("%s lives in section '%s', not its own: compile the stencil unit with -ffunction-sections,\n" ..
                "  or a call between two stencils would need no relocation and copy into a trace as a wild branch",
                s.name, sec.name)
        end
        stencils[#stencils + 1] = { sym = s, sec = sec }
    end
end
table.sort(stencils, function(a, b)
    return a.sec.index < b.sec.index
end)
if #stencils == 0 then
    die("no tc_stencil_* functions found in %s", objpath)
end

-- The ABI fingerprint the stencils were compiled against
local abi
for _, s in pairs(syms) do
    if s.type == STT_OBJECT and s.name == "tc_stencil_abi" then
        local sec = elf.sections[s.shndx]
        abi = {}
        for k = 0, (s.size // 8) - 1 do
            abi[k + 1] = string.unpack("<I8", elf.data, sec.offset + s.value + (k * 8) + 1)
        end
    end
end
if not abi then
    die("tc_stencil_abi not found; the stencil unit did not record what it was built against")
end

local out = {}
local function emit(fmt, ...)
    out[#out + 1] = select("#", ...) > 0 and string.format(fmt, ...) or fmt
end

-- Rejections are collected rather than fatal on the first one, so that adding a
-- batch of cases to the compiled set reports every one that does not belong in
-- a single build instead of one per rebuild.
local rejected = {}

local total_bytes = 0
local bodies = {}
for _, st in ipairs(stencils) do
    local s, sec = st.sym, st.sec
    local body = elf.data:sub(sec.offset + s.value + 1, sec.offset + s.value + s.size)
    local holes = {}
    for _, r in ipairs(read_relocations(elf, syms, sec.index)) do
        if r.offset >= s.value and r.offset < s.value + s.size then
            local name = r.sym.name
            if not name:match("^tc_h_") then
                rejected[#rejected + 1] = string.format("%-28s reaches %s (at +0x%x)", s.name:sub(12),
                    name == "" and "<a local function in another section>" or name, r.offset - s.value)
                name = "tc_h_insn" -- keep going; the build fails at the end
            end
            local kind = kinds[r.rtype]
            if not kind then
                die("%s: unsupported relocation type %d against '%s' at +0x%x", s.name, r.rtype, name,
                    r.offset - s.value)
            end
            -- An operand is a value; only a continuation is a place. If the
            -- compiler chose to materialize an operand relative to the
            -- instruction that reads it, the stencil is not relocatable at all:
            -- moved elsewhere it would compute a different number, and no patch
            -- can repair that, because the value wanted is an absolute small
            -- constant and the encoding can only reach addresses near itself.
            local hole = name:sub(6)
            if kind == "REL32" and hole ~= "cont" and hole ~= "exit" then
                rejected[#rejected + 1] = string.format("%-28s materializes %s relative to itself (at +0x%x)",
                    s.name:sub(12), hole, r.offset - s.value)
            end
            holes[#holes + 1] = {
                off = r.offset - s.value,
                kind = kind,
                hole = hole,
                addend = r.addend,
            }
        end
    end
    table.sort(holes, function(a, b)
        return a.off < b.off
    end)
    total_bytes = total_bytes + s.size
    bodies[#bodies + 1] = { name = s.name:sub(12), size = s.size, body = body, holes = holes }
end

if #rejected > 0 then
    io.stderr:write("gen-tc-stencils: these cases do not belong in the compiled set, because a stencil may\n")
    io.stderr:write("only reach its own holes; copied to another address, a reference to anything else\n")
    io.stderr:write("would point at whatever now sits at that distance:\n\n")
    for _, r in ipairs(rejected) do
        io.stderr:write("  " .. r .. "\n")
    end
    io.stderr:write("\nEither the case needs a guard that side-exits before the call, or it should be\n")
    io.stderr:write("dropped from interpret-tc-stencil-cases.inc. Disassemble one with:\n")
    io.stderr:write("  objdump -dr --section=.text.tc_stencil_<NAME> " .. objpath .. "\n")
    os.exit(1)
end

-- Emission ------------------------------------------------------------------

emit("// Generated by tools/gen-tc-stencils.lua from %s -- DO NOT EDIT.\n", objpath:match("[^/]+$"))
emit("// %d stencils, %d bytes of machine code.\n\n", #bodies, total_bytes)

emit("#define TC_STENCIL_ABI_CONTEXT_SIZE %d\n", abi[1])
emit("#define TC_STENCIL_ABI_OFF_PC %d\n", abi[2])
emit("#define TC_STENCIL_ABI_OFF_MCYCLE %d\n", abi[3])
emit("#define TC_STENCIL_ABI_OFF_TICK_END %d\n", abi[4])
emit("#define TC_STENCIL_ABI_OFF_FETCH_PAGE %d\n", abi[5])
emit("#define TC_STENCIL_ABI_OFF_FETCH_PMA %d\n", abi[6])
emit("#define TC_STENCIL_ABI_GLOBAL_REGS %d\n", abi[7])
emit("#define TC_STENCIL_ABI_PAGE_SEGMENT %d\n", abi[8])
emit("#define TC_STENCIL_ABI_PRESERVE_NONE %d\n", abi[9])
emit("#define TC_STENCIL_ABI_JIT_SHELL %d\n\n", abi[10])

emit("// The machine code, one blob for every stencil, concatenated.\n")
emit("static const uint8_t tc_stencil_code[] = {")
local col = 0
for _, b in ipairs(bodies) do
    for i = 1, #b.body do
        if col % 12 == 0 then
            emit("\n    ")
        end
        emit("0x%02x, ", b.body:byte(i))
        col = col + 1
    end
end
emit("\n};\n\n")

emit("// Every patch site of every stencil, concatenated; each stencil indexes\n")
emit("// its own run through tc_stencil_table.\n")
emit("static const tc_stencil_hole tc_stencil_holes[] = {\n")
for _, b in ipairs(bodies) do
    for _, h in ipairs(b.holes) do
        emit("    {%d, TC_HOLE_%s, TC_PATCH_%s, %d},\n", h.off, h.hole:upper(), h.kind, h.addend)
    end
end
emit("};\n\n")

emit("// One row per case, in the order interpret-tc-stencil-cases.inc lists them.\n")
emit("static const tc_stencil_desc tc_stencil_table[] = {\n")
local code_at, hole_at = 0, 0
for _, b in ipairs(bodies) do
    emit("    {%d, %d, %d, %d}, // %s\n", code_at, b.size, hole_at, #b.holes, b.name)
    code_at = code_at + b.size
    hole_at = hole_at + #b.holes
end
emit("};\n\n")

emit("// The case each row serves, by name.\n")
emit("#define TC_STENCIL_LIST(X) \\\n")
for i, b in ipairs(bodies) do
    emit("    X(%d, %s)%s\n", i - 1, b.name, i < #bodies and " \\" or "")
end
emit("\n")

-- The dispatch-id to stencil map, from the interpreter's own jump table, so a
-- recorded instruction reaches its stencil by exactly the decode that chose its
-- handler. Cases that stay with the interpreter map to none, and the emitter
-- ends the compiled part of a trace where it meets one.
local tablepath = arg[2]
if tablepath then
    local index_of = {}
    for i, b in ipairs(bodies) do
        index_of[b.name] = i - 1
    end
    local ids, n = {}, 0
    for line in assert(io.open(tablepath, "r")):lines() do
        local name = line:match("TC_LABEL%(([%w_]+)%)")
        if name then
            n = n + 1
            ids[n] = index_of[name] or -1
        end
    end
    if n ~= 65536 then
        die("%s has %d labels, expected 65536", tablepath, n)
    end
    emit("// Dispatch id to stencil index, -1 where the interpreter keeps the case.\n")
    emit("static const int16_t tc_stencil_of_id[65536] = {")
    for i = 1, n do
        if (i - 1) % 20 == 0 then
            emit("\n    ")
        end
        emit("%d,", ids[i])
    end
    emit("\n};\n\n")
end

io.write(table.concat(out))
io.flush()
