#!/usr/bin/env lua5.4

--[[
Derives interpret-tc-stencil-cases.inc, the compiled instruction set of the
copy-and-patch JIT, from interpret-tc-cases.inc, the interpreter's own case
list.

The point of deriving it is that the two cannot drift: a stencil executes the
same execute_* expression the interpreter's handler does, with the same
classification and the same length, so the only honest source for that is the
interpreter's list. Two substitutions and one filter separate them.

  * TC_MCYCLE_GET() becomes TC_STENCIL_MCYCLE(), which materializes the cycle a
    step would have observed from its static position in the block instead of
    from a countdown no straight-line step touches.
  * The profiling hooks are dropped. TC_HOOK_CALL counts calls to find heads
    worth compiling; inside compiled code there is nothing left to find.
  * Cases that cannot execute without calling something are left out, listed
    below with the reason. The list is not trusted: gen-tc-stencils.lua rejects
    any stencil that reaches beyond its own holes, so an entry that becomes
    wrong fails the build rather than quietly compiling the wrong thing.

Usage: gen-tc-stencil-cases.lua <path to interpret-tc-cases.inc>
]]

-- Why each case stays with the interpreter. A trace ends or side-exits at these.
local ineligible = {
    -- Softfloat is a library of calls, and no guard can avoid them
    FD = "floating point: calls softfloat",
    FMADD = "floating point: calls softfloat",
    FMSUB = "floating point: calls softfloat",
    FNMADD = "floating point: calls softfloat",
    FNMSUB = "floating point: calls softfloat",
    C_FLDSP = "floating point: calls softfloat",
    C_FSDSP = "floating point: calls softfloat",

    -- CSR access reaches device and machine state through cold paths
    CSRRW = "CSR access",
    CSRRS = "CSR access",
    CSRRC = "CSR access",
    CSRRWI = "CSR access",
    CSRRSI = "CSR access",
    CSRRCI = "CSR access",

    -- Atomics take the reservation and the slow memory path unconditionally
    AMO_W = "atomic: reservation and slow memory path",
    AMO_D = "atomic: reservation and slow memory path",

    -- Writes mcycle, which block accounting derives rather than stores; the AOT
    -- trace selector of section 8b excludes it for the same reason
    PRIVILEGED = "writes mcycle, which block accounting derives",
    C_EBREAK = "traps unconditionally",

    -- These materialize an operand relative to the instruction that reads it,
    -- which no patch can repair once the code is copied elsewhere; the
    -- extractor rejects them by name, and they are listed here so the build
    -- does not have to.
    --
    -- The compressed load/store family used to be here too, and it was the
    -- most expensive entry in this table: a trace stops at the first
    -- instruction it cannot compile, so excluding c.lw/c.sw/c.ld/c.sd cut
    -- almost every hot loop short. The cause was not the encoding but a
    -- narrowing: execute_C_L and execute_C_S took their register selector as
    -- uint32_t, and a relocated value that round-trips through a narrower type
    -- has to be materialized into a register instead of folding into a
    -- displacement -- exactly what reg_index exists to prevent. Widening those
    -- parameters admitted the whole family. What is left needs an operand the
    -- compiler still commits to a register: C_LDSP and C_LWSP reach rd that
    -- way, and rd is shared with every uncompressed case, so naming its
    -- encoding to recover two forms would deoptimize a hundred.
    C_EBREAK = "materializes an operand relative to itself",
    C_FLDSP = "materializes an operand relative to itself",
    C_FSDSP = "materializes an operand relative to itself",
    CSRRC = "materializes an operand relative to itself",
    CSRRCI = "materializes an operand relative to itself",
    CSRRS = "materializes an operand relative to itself",
    CSRRSI = "materializes an operand relative to itself",
    CSRRW = "materializes an operand relative to itself",
    CSRRWI = "materializes an operand relative to itself",
    FD = "materializes an operand relative to itself",
    FMADD = "materializes an operand relative to itself",
    FMSUB = "materializes an operand relative to itself",
    FNMADD = "materializes an operand relative to itself",
    FNMSUB = "materializes an operand relative to itself",
    PRIVILEGED = "materializes an operand relative to itself",
    SRLIW_SRAIW_rd0 = "materializes an operand relative to itself",

    -- Reaches the machine back-pointer even with the result discarded
    SRLIW_SRAIW_rd0 = "reaches the machine back-pointer",
}

-- Cases whose successful execution always lands at pc + LEN, so the stencil's
-- successor guard compares a patched constant against itself: three
-- instructions and a cold block for a test that cannot fail.
--
-- The interpreter classifies these 0, meaning "do not pre-decode across me",
-- because a store can overwrite the bytes a pre-load already read. That is a
-- property of fetching, and a stencil does not fetch -- it carries the words
-- the recorder saw. Whether those words are still what the guest would fetch
-- is the write-TLB question of 8b item 3, which this guard never answered
-- either way. So the classification is right for the interpreter and wrong for
-- the stencil, and only here is it overridden.
--
-- Jumps are class 0 for a second reason that does apply -- they move pc
-- arbitrarily -- and keep their guard.
local straight_line = {
    SB = true,
    SH = true,
    SW = true,
    SD = true,
    FSW = true,
    FSD = true,
    C_SB = true,
    C_SH = true,
    C_SW = true,
    C_SD = true,
    C_SWSP = true,
    C_SDSP = true,
    C_FSD = true,
}
local straight_line_seen = {}

local path = arg[1] or "interpret-tc-cases.inc"
local f = assert(io.open(path, "r"), "cannot open " .. path)

local kept, dropped = {}, {}
for line in f:lines() do
    local name = line:match("^TC_CASE%(([%w_]+),")
    if name then
        if ineligible[name] then
            dropped[#dropped + 1] = { name = name, why = ineligible[name] }
        else
            local row = line:gsub("^TC_CASE%(", "TC_STENCIL("):gsub("TC_MCYCLE_GET%(%)", "TC_STENCIL_MCYCLE()")
            -- Unwrap the profiling hook: TC_HOOK_CALL(expr) -> expr
            row = row:gsub("TC_HOOK_CALL%((.*)%)%)$", "%1)")
            if straight_line[name] then
                straight_line_seen[name] = true
                row = row:gsub("^TC_STENCIL%(([%w_]+), %d+,", "TC_STENCIL(%1, 2,")
            end
            kept[#kept + 1] = row
        end
    end
end
f:close()

if #kept == 0 then
    io.stderr:write("gen-tc-stencil-cases: no TC_CASE rows found in " .. path .. "\n")
    os.exit(1)
end

-- A name in the override list that no longer names a case is a rename that
-- would otherwise silently stop applying, so it fails the build instead.
for name in pairs(straight_line) do
    if not straight_line_seen[name] and not ineligible[name] then
        io.stderr:write("gen-tc-stencil-cases: '" .. name ..
            "' is listed straight-line but is not a case in " .. path .. "\n")
        os.exit(1)
    end
end

io.write("// Generated by tools/gen-tc-stencil-cases.lua from ", path:match("[^/]+$"), " -- DO NOT EDIT.\n")
io.write("//\n")
io.write("// The compiled instruction set of the copy-and-patch JIT: one row per stencil,\n")
io.write("// carried over from the interpreter's own case list so the two cannot drift.\n")
io.write(string.format("// %d of %d cases are compiled; the rest stay with the interpreter,\n", #kept,
    #kept + #dropped))
io.write("// which a trace reaches by side exit:\n//\n")
table.sort(dropped, function(a, b)
    return a.name < b.name
end)
for _, d in ipairs(dropped) do
    io.write(string.format("//   %-16s %s\n", d.name, d.why))
end
io.write("\n")
for _, row in ipairs(kept) do
    io.write(row, "\n")
end
io.flush()
