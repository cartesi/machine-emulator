#!/usr/bin/env lua5.4
-- R2-SOLIDITY-2: machine-solidity-step Memory.validateStrideLength is off by one. It rejects every
-- region that ends at the last leaf of the 2^64 address space, so AccessLogs.readWord/writeWord/readLeaf/
-- writeLeaf revert (Panic 0x01) on any access to leaf 0xFFFFFFFFFFFFFFE0, which the native log producer and the
-- C++ verifier handle.
--
-- What it checks (correct behavior required by THREAT_MODEL.md R2, R3, R10):
--   On a fabricated uarch before-state executing `ld x5, 0(x6)` with x6 = 0xFFFFFFFFFFFFFFF8:
--   1. native log_step_uarch logs the step and cartesi.machine:verify_step_uarch accepts the log with the
--      native after-hash (the unmapped last word reads as zero, with a valid 59-sibling proof);
--   2. the log is encoded for the chain exactly as doc/recipes/prt-ethereum.lua append_log does
--      (word access: 32-byte leaf + 59 siblings);
--   3. a Lua model of the Solidity verifier's memory path replays that encoding access by access:
--      AccessLogs.readWord/writeWord -> Memory.truncateToLeaf -> strideFromLeafAddress
--      (strideFromPhysicalAddress asserts) -> regionFromStride -> validateStrideLength -> Buffer.getRoot/peekRoot.
--      The validateStrideLength condition and the constants (LOG2_LEAF, LOG2_MAX_SIZE, MAX_SIZE, MAX_STRIDE) are
--      parsed from $MACHINE_SOLIDITY_STEP_DIR/src/Memory.sol and evaluated, so the model follows the pinned source.
--   Control: the same instruction with x6 = 0xFFFFFFFFFFFFFFD8 (second-to-last leaf) must be accepted by the model
--   with the native after-hash (validates the model, encoding and sibling order).
--   The test asserts that the Solidity model also accepts the honest last-leaf log with the native after-hash.
--   On feature/prt-audit it fails: validateStrideLength asserts stride*1 < MAX_SIZE-1 with stride = 2^59-1.
--
-- Solidity is NOT executed (no EVM available): this is a differential test of a Lua model of the pinned source.
-- Severity per section 8: High ("a divergence between paths only at demonstrably unreachable states"): address
-- ranges end at or below 2^64-4096 and the uarch reaches guest memory only through PMA lookups, so only a
-- fabricated uarch state touches the last leaf.
local cartesi = require("cartesi")

local SOL_DIR = os.getenv("MACHINE_SOLIDITY_STEP_DIR") or "/home/user/ext/machine-solidity-step"
local UARCH_RAM = cartesi.UARCH_RAM_START_ADDRESS
local LD_X5_0_X6 = (0 << 20) | (6 << 15) | (3 << 12) | (5 << 7) | 0x03 -- 0x00033283

local function harness_fail(msg)
    io.stderr:write("HARNESS ERROR: ", msg, "\n")
    os.exit(2)
end

----------------------------------------------------------------------------------------------------------------------
-- Parse the pinned Memory.sol: constants and the validateStrideLength condition.
----------------------------------------------------------------------------------------------------------------------
local f = io.open(SOL_DIR .. "/src/Memory.sol", "r") or harness_fail("cannot open Memory.sol")
local src = f:read("a")
f:close()

local function sol_expr_to_lua(e)
    e = e:gsub("Stride%.unwrap%(%s*stride%s*%)", "stride")
    e = e:gsub("stride%.unwrap%(%s*%)", "stride")
    e = e:gsub("alignedSize%.size%(%s*%)", "s")
    e = e:gsub("uint%d+%(", "(")
    e = e:gsub("!=", "~=")
    e = e:gsub("&&", " and "):gsub("||", " or ")
    return e
end

-- Constants may be declared in any order: evaluate repeatedly until all resolve.
local consts, pending = {}, {}
for _, name, expr in src:gmatch("(uint%d+)%s+constant%s+([%w_]+)%s*=%s*([^;]+);") do
    pending[#pending + 1] = { name = name, expr = expr }
end
repeat
    local progress, rest = false, {}
    for _, c in ipairs(pending) do
        local chunk = load("return " .. sol_expr_to_lua(c.expr), c.name, "t", setmetatable({}, { __index = consts }))
        if not chunk then harness_fail("cannot translate constant " .. c.name .. " = " .. c.expr) end
        local ok, v = pcall(chunk)
        if ok then consts[c.name], progress = v, true else rest[#rest + 1] = c end
    end
    pending = rest
until #pending == 0 or not progress
if #pending > 0 then harness_fail("cannot evaluate constant " .. pending[1].name) end
for _, k in ipairs({ "LOG2_LEAF", "LOG2_MAX_SIZE", "MAX_SIZE" }) do
    if not consts[k] then harness_fail("constant " .. k .. " not found in Memory.sol") end
end

local body = src:match("function%s+validateStrideLength%s*%b()[^{]*(%b{})")
    or harness_fail("validateStrideLength not found in Memory.sol")
local conds = {}
for kind, cond in body:gmatch("(%a+)(%b())%s*;") do
    if kind == "assert" or kind == "require" then
        local inner = cond:sub(2, -2):gsub(",%s*\"[^\"]*\"%s*$", "")
        conds[#conds + 1] = { kind = kind, text = inner, lua = sol_expr_to_lua(inner) }
    end
end
if #conds == 0 then harness_fail("no assert/require in validateStrideLength") end
print("Memory.sol validateStrideLength checks: " .. table.concat((function()
    local t = {}
    for _, c in ipairs(conds) do t[#t + 1] = c.kind .. "(" .. c.text .. ")" end
    return t
end)(), "; ") .. string.format("  [MAX_SIZE=0x%x MAX_STRIDE=%s]", consts.MAX_SIZE,
    consts.MAX_STRIDE and string.format("0x%x", consts.MAX_STRIDE) or "n/a"))

-- Solidity revert, carried as an error object.
local Revert = {}
local function revert(why) error(setmetatable({ why = why }, Revert), 0) end

local function validateStrideLength(stride, log2s)
    local s = 1 << log2s
    for _, c in ipairs(conds) do
        local env = setmetatable({ stride = stride, s = s }, { __index = consts })
        local chunk = load("return " .. c.lua, "validateStrideLength", "t", env)
            or harness_fail("cannot translate condition: " .. c.text)
        if not chunk() then
            revert(c.kind == "assert" and ("Panic(0x01) in Memory.validateStrideLength: assert(" .. c.text .. ")"
                .. string.format(" with stride=0x%x, s=%d", stride, s)) or ("require failed: " .. c.text))
        end
    end
end

-- Memory.strideFromPhysicalAddress (alignment asserts) for a leaf region.
local LEAF_MASK = (1 << consts.LOG2_LEAF) - 1
local function strideFromLeafAddress(addr)
    if addr & LEAF_MASK ~= 0 then revert("Panic(0x01): leaf misaligned") end
    return addr >> consts.LOG2_LEAF -- s = 1: position / 1
end

----------------------------------------------------------------------------------------------------------------------
-- Model of AccessLogs + Buffer over the chain encoding.
----------------------------------------------------------------------------------------------------------------------
local function new_ctx(root, data) return { root = root, data = data, off = 0 } end

local function consume32(ctx)
    if ctx.off + 32 > #ctx.data then revert("buffer out of bounds") end
    local v = ctx.data:sub(ctx.off + 1, ctx.off + 32)
    ctx.off = ctx.off + 32
    return v
end

-- Buffer.peekRoot / getRoot for a leaf region (logOfSize = 0, nodesCount = LOG2_MAX_SIZE).
local function peekRoot(ctx, stride, drive)
    local n = consts.LOG2_MAX_SIZE
    for i = 0, n - 1 do
        local o = ctx.off + i * 32
        if o + 32 > #ctx.data then revert("buffer out of bounds") end
        local sib = ctx.data:sub(o + 1, o + 32)
        if ((stride >> i) & 1) == 0 then
            drive = cartesi.keccak256(drive, sib)
        else
            drive = cartesi.keccak256(sib, drive)
        end
    end
    return drive, n
end
local function getRoot(ctx, stride, drive)
    local r, n = peekRoot(ctx, stride, drive)
    ctx.off = ctx.off + n * 32
    return r
end

local function region_for(addr)
    local leaf = addr & ~LEAF_MASK -- Memory.truncateToLeaf
    local stride = strideFromLeafAddress(leaf)
    validateStrideLength(stride, 0) -- Memory.regionFromStride
    return stride, addr - leaf
end

local function readWord(ctx, addr)
    local stride, off = region_for(addr)
    local leaf = consume32(ctx)
    if getRoot(ctx, stride, cartesi.keccak256(leaf)) ~= ctx.root then revert("Read word root doesn't match") end
    return string.unpack("<I8", leaf, off + 1)
end

local function writeWord(ctx, addr, val)
    local stride, off = region_for(addr)
    local old = consume32(ctx)
    local r = peekRoot(ctx, stride, cartesi.keccak256(old))
    if r ~= ctx.root then revert("Write word root doesn't match") end
    local new = old:sub(1, off) .. string.pack("<I8", val) .. old:sub(off + 9)
    ctx.root = getRoot(ctx, stride, cartesi.keccak256(new))
end

-- prt-ethereum.lua append_log, word-access branch (all uarch-step accesses here are 8-byte words).
local function encode_log(log)
    local parts = {}
    for _, a in ipairs(log.accesses) do
        if a.log2_size ~= 3 then harness_fail("unexpected non-word access") end
        parts[#parts + 1] = assert(a.read)
        for _, sib in ipairs(a.sibling_hashes) do parts[#parts + 1] = sib end
    end
    return table.concat(parts)
end

-- Replays the access sequence that UArchStep.step issues for this LD (readCycle, readHalt, readPc, readUint32(pc)
-- -> readWord, readX(6), readUint64(x6), writeX(5), writePc, writeCycle); the sequence is the one in the native log,
-- which the generated Solidity mirrors. Returns the final root or the revert reason.
local function solidity_model(before, log)
    local ctx = new_ctx(before, encode_log(log))
    local ok, err = pcall(function()
        for _, a in ipairs(log.accesses) do
            if a.type == "read" then
                readWord(ctx, a.address)
            else
                local off = a.address & LEAF_MASK
                writeWord(ctx, a.address, (string.unpack("<I8", a.written, off + 1)))
            end
        end
        if ctx.off ~= #ctx.data then revert("trailing data") end
    end)
    if ok then return ctx.root end
    if getmetatable(err) ~= Revert then harness_fail("model error: " .. tostring(err)) end
    return nil, err.why
end

----------------------------------------------------------------------------------------------------------------------
-- Native side.
----------------------------------------------------------------------------------------------------------------------
local function run_case(x6)
    local function mk()
        local m = cartesi.machine({ ram = { length = 0x10000 }, uarch = {} })
        m:write_memory(UARCH_RAM, string.pack("<I4", LD_X5_0_X6))
        m:write_reg("uarch_pc", UARCH_RAM)
        m:write_reg("uarch_x6", x6)
        return m
    end
    local m = mk()
    local before = m:get_root_hash()
    local ok, log = pcall(m.log_step_uarch, m)
    if not ok then harness_fail(string.format("native log_step_uarch failed for x6=0x%x: %s", x6, log)) end
    local after = m:get_root_hash()
    local touched = false
    for _, a in ipairs(log.accesses) do
        if a.address == x6 then touched = true end
    end
    if not touched then harness_fail(string.format("native log has no access at 0x%x", x6)) end
    local vok, vres = pcall(function() return cartesi.machine:verify_step_uarch(before, log) end)
    if not vok or vres ~= after then
        harness_fail(string.format("C++ verify_step_uarch did not accept the native log for x6=0x%x: %s", x6,
            tostring(vres)))
    end
    -- native run agrees with the log producer
    local m2 = mk()
    m2:run_uarch(1)
    if m2:get_root_hash() ~= after then harness_fail("run_uarch disagrees with log_step_uarch") end
    local sol_root, why = solidity_model(before, log)
    return after, sol_root, why, #log.accesses
end

-- Control: second-to-last leaf. The model must accept with the native after-hash.
do
    local x6 = 0xFFFFFFFFFFFFFFD8
    local after, sol_root, why = run_case(x6)
    if sol_root ~= after then
        harness_fail(string.format("control x6=0x%x: Solidity model did not reproduce the native after-hash (%s)", x6,
            tostring(why)))
    end
    print(string.format("control x6=0x%x: native log, C++ verifier and Solidity model agree on the after-hash", x6))
end

-- Defect case: last leaf.
local x6 = 0xFFFFFFFFFFFFFFF8
local after, sol_root, why, n = run_case(x6)
print(string.format("x6=0x%x: native log_step_uarch produced %d accesses; C++ verify_step_uarch accepts it", x6, n))
if sol_root == after then
    print("OK: Solidity model accepts the honest last-leaf log with the native after-hash")
    os.exit(0)
end
print(string.format("FAIL: on-chain UArchStep.step would revert on the honest log that native log_step_uarch and "
    .. "C++ verify_step_uarch accept (x6=0x%x, last leaf 0xffffffffffffffe0): %s", x6, tostring(why)))
os.exit(1)
