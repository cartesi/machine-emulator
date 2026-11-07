-- R4-VARRANGE-1: drive the PoC application through cmio advance-state and
-- assert the behavior the threat model requires.
--
-- Usage: lua5.4 check.lua <template-dir> <in-0.bin> <in-1.bin> <in-2.bin>
--
-- The template is the PoC application booted to its first RX-accepted manual
-- yield. We deliver each input with send_cmio_response and run the machine,
-- collecting every tx-output (notice) and the final manual yield (accepted /
-- rejected / halt). No revert machinery is used: we observe exactly what the
-- guest does with each input.
--
-- Correct behavior (what a correctly-designed application using libcmt as
-- documented must exhibit, THREAT_MODEL.md section 1 goal, section 2
-- "correctly designed application", and AUDIT.md machine-guest-tools role):
--   * in-0 (honest payload) is accepted and emits a notice carrying "hello".
--   * in-1 (wrapping offset) must NOT commit any notice: a correct ABI decoder
--     rejects an offset past the end of the frame, so no output exists whose
--     bytes come from outside the input payload.
--   * in-2 (wrapping offset into unmapped memory) must NOT crash/halt the
--     machine: relayed input data the honest operator must process cannot be
--     allowed to kill the application (section 8 reachability/crash clause).
--
-- The buggy libcmt (v0.18.0) accepts the wrapping offset, so in-1 commits a
-- notice built from the EvmAdvance header (bytes outside the payload) and in-2
-- dereferences unmapped memory and halts the machine. This script exits 1 in
-- either case, and exits 0 once cmt_abi_peek_bytes_d bounds the offset.

local cartesi = require("cartesi")

local tmpl = assert(arg[1], "missing template dir")
local inputs = {}
for i = 2, #arg do
    inputs[#inputs + 1] = arg[i]
end
assert(#inputs == 3, "expected 3 input files")

local MAX = cartesi.MCYCLE_MAX

local function readfile(p)
    local f = assert(io.open(p, "rb"))
    local d = f:read("a")
    f:close()
    return d
end

-- Extract the `bytes` content of a Notice(bytes) output: funsel(4) + offset(32)
-- + length(32) + data. Returns the data substring (without padding).
local function notice_bytes(out)
    if #out < 68 then
        return nil
    end
    local len = string.unpack(">I8", out, 61) -- low 8 bytes of the length word
    local lo = 68
    return out:sub(lo + 1, lo + len), len
end

local function hexdump(s)
    return (s:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end

local m <close> = cartesi.machine(tmpl)
local records = {}

for idx, path in ipairs(inputs) do
    local payload = readfile(path)
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, payload, m:get_root_hash())
    local rec = { outputs = {}, final = nil }
    while true do
        m:run(MAX)
        if m:read_reg("iflags_H") ~= 0 then
            rec.final = "halt"
            rec.exit = m:read_reg("htif_tohost_data") >> 1
            break
        elseif m:read_reg("iflags_X") ~= 0 then
            local _, reason, out = m:receive_cmio_request()
            if reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
                rec.outputs[#rec.outputs + 1] = out
            end
            -- automatic yield: continue running
        elseif m:read_reg("iflags_Y") ~= 0 then
            local reason = m:read_reg("htif_tohost_reason")
            if reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED then
                rec.final = "accepted"
            elseif reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED then
                rec.final = "rejected"
            else
                rec.final = "manual:" .. reason
            end
            break
        else
            rec.final = "unknown-break"
            break
        end
    end
    records[idx] = rec
    io.stderr:write(string.format("  input %d: final=%s outputs=%d\n", idx - 1, tostring(rec.final), #rec.outputs))
    if rec.final == "halt" then
        break
    end
end

-- The application payloads, to compare against committed notice bytes.
-- in-N payload is the inner abi (bytes) value we encoded; for in-1 it is a
-- single 32-byte word, so any notice longer/different than that is "outside
-- the payload".
local function fail(msg)
    io.stderr:write("FAIL(bug present): " .. msg .. "\n")
    os.exit(1)
end
local function infra(msg)
    io.stderr:write("INFRA ERROR: " .. msg .. "\n")
    os.exit(3)
end

-- Sanity: control input must decode normally.
local r0 = records[1]
if r0.final ~= "accepted" or #r0.outputs ~= 1 then
    infra(string.format("control input 0 did not behave (final=%s outputs=%d)", tostring(r0.final), #r0.outputs))
end
do
    local b = notice_bytes(r0.outputs[1])
    if b ~= "hello" then
        infra("control input 0 notice did not carry 'hello' (got: " .. tostring(b) .. ")")
    end
end

-- Security assertion 1: a wrapping offset must not make the app commit an
-- output. On buggy libcmt in-1 is accepted and commits a notice built from
-- bytes outside the 32-byte payload (the EvmAdvance header).
local r1 = records[2]
if r1.final == "halt" then
    fail("input 1 (wrapping offset) halted the machine (exit " .. tostring(r1.exit) .. ")")
end
if #r1.outputs > 0 then
    local b, len = notice_bytes(r1.outputs[1])
    fail(string.format(
        "input 1 committed a notice of %d bytes (%s...) from a wrapping ABI offset -- "
            .. "these bytes are outside the input payload; the output is a wrong output "
            .. "that enters the outputs Merkle root (THREAT_MODEL section 1 goal)",
        len or -1, hexdump((b or ""):sub(1, 16))))
end

-- Security assertion 2: a wrapping offset into unmapped memory must not crash
-- the application / halt the machine.
local r2 = records[3]
if not r2 then
    -- machine already halted on input 1
    fail("machine halted before input 2 could be processed")
end
if r2.final == "halt" then
    fail("input 2 (wrapping offset) segfaulted the guest and halted the machine (exit "
        .. tostring(r2.exit) .. "); every later input becomes a no-op (completeness failure)")
end

io.stderr:write("OK: wrapping ABI offsets are rejected; no wrong output, no halt.\n")
os.exit(0)
