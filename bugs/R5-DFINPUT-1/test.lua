-- R5-DFINPUT-1 -- libcmt cmt_abi_get_bool accepts non-0/1 ABI words and hands the
-- application a bool object that holds 2..255.
--
-- cmt_abi_get_bool (machine-guest-tools v0.18.0, sys-utils/libcmt/src/abi.c)
-- decodes the 32-byte word with cmt_abi_get_uint(me, sizeof(bool), &boolean),
-- which rejects nonzero bytes only among the first 31 bytes and copies the last
-- byte verbatim into the `bool`. The ABI (and libcmt's own encoder, which writes
-- only 0/1) defines any other last byte as an invalid bool, but the decoder
-- returns 0 (success). The application then holds an invalid bool representation
-- and GCC -O2 code (lbu + xori 1) treats it as both "yes" (=2) and "no" (=3).
--
-- This test builds a correctly designed ballot application (app.c) against the
-- live pinned libcmt sources with the pinned riscv64-linux-gnu-gcc at -O2, boots
-- it on the pinned kernel/rootfs, and delivers two EvmAdvance inputs over cmio:
--   in-0: payload = abi.encode(true)          (control)
--   in-1: payload = one word ending in 0x02   (attacker-chosen bytes)
-- It asserts the behavior THREAT_MODEL.md section 1 / AUDIT.md require of
-- machine-guest-tools: no input can make the app commit a wrong output. Every
-- accepted ballot must add exactly one vote; the invalid word must be rejected
-- (or at worst decoded as a valid 0/1 bool). On v0.18.0 in-1 is accepted and
-- commits the notice "ballot yes=2 no=3 ...", an output the app's logic can
-- never produce for any valid input, which enters the outputs Merkle root.
--
-- Exit: 0 bug absent, 1 bug present, 3 harness error.
local cartesi = require("cartesi")
local evmu = require("cartesi.evmu")

local here = assert(os.getenv("PWD"))
local repo = assert(os.getenv("REPO_DIR"), "source bugs/env.sh")
local build = here .. "/build"

local function infra(msg)
    io.stderr:write("INFRA ERROR: " .. msg .. "\n")
    os.exit(3)
end

-- 1. Build guest + flash drive.
if not os.execute("bash " .. here .. "/build.sh " .. build) then infra("guest build failed") end

-- 2. Boot the app to its first accepted manual yield and store it as template.
local cmd = string.format(
    "lua5.4 %s/src/cartesi-machine.lua --no-init-splash --flash-drive=label:poc,data_filename:%s/poc.ext2 "
        .. "--store=%s/tmpl -- /mnt/poc/app.rv64 >%s/boot.out 2>%s/boot.err",
    repo, build, build, build, build)
if not os.execute(cmd) then infra("template boot/store failed, see build/boot.err") end

-- 3. Inputs: honest EvmAdvance envelopes whose application payload is one ABI word.
local SIG = "EvmAdvance(uint256,address,address,uint256,uint256,uint256,uint256,bytes)"
local function input(index, payload)
    return evmu.encode_calldata(SIG, {
        31337, "0x" .. string.rep("ab", 20), "0x" .. string.rep("cd", 20),
        1, 2, 3, index, evmu.encode_hex(payload),
    })
end
local function boolword(last) return string.rep("\0", 31) .. string.char(last) end
local inputs = { input(0, boolword(0x01)), input(1, boolword(0x02)) }

-- 4. Drive cmio advance-state and collect notices / final yield per input.
local function notice_text(out)
    -- Notice(bytes): selector(4) + offset(32) + length(32) + data
    local len = string.unpack(">I8", out, 4 + 32 + 24 + 1)
    return out:sub(4 + 64 + 1, 4 + 64 + len)
end

local m = cartesi.machine(build .. "/tmpl")
local recs = {}
for i, payload in ipairs(inputs) do
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, payload, m:get_root_hash())
    local rec = { notices = {} }
    while true do
        m:run(cartesi.MCYCLE_MAX)
        if m:read_reg("iflags_H") ~= 0 then
            rec.final = "halt"
            break
        elseif m:read_reg("iflags_X") ~= 0 then
            local _, reason, out = m:receive_cmio_request()
            if reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT then
                rec.notices[#rec.notices + 1] = notice_text(out)
            end
        elseif m:read_reg("iflags_Y") ~= 0 then
            local reason = m:read_reg("htif_tohost_reason")
            rec.final = (reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED and "accepted")
                or (reason == cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED and "rejected")
                or ("manual:" .. reason)
            break
        else
            rec.final = "unknown-break"
            break
        end
    end
    recs[i] = rec
    io.stderr:write(string.format("  input %d: final=%s notices=[%s]\n", i - 1, rec.final,
        table.concat(rec.notices, " | ")))
    if rec.final == "halt" then infra("app halted on input " .. (i - 1)) end
end

-- Drop the large stored template (generated at test time).
m:destroy()
os.execute("rm -rf " .. build .. "/tmpl")

-- Control: abi.encode(true) is one yes vote.
local r0 = recs[1]
if r0.final ~= "accepted" or #r0.notices ~= 1 or r0.notices[1] ~= "ballot yes=1 no=0 total yes=1 no=0" then
    infra("control input did not produce the expected single yes vote")
end

-- Security assertion: an accepted ballot adds exactly one vote.
local r1 = recs[2]
if r1.final == "accepted" then
    for _, t in ipairs(r1.notices) do
        local y, n = t:match("^ballot yes=(%d+) no=(%d+)")
        if not y or tonumber(y) + tonumber(n) ~= 1 then
            io.stderr:write("FAIL(bug present): cmt_abi_get_bool accepted the invalid ABI bool word 0x00..02 (rc=0) and "
                .. "the app committed the wrong output '" .. t .. "' (one ballot counted as yes=" .. tostring(y)
                .. " and no=" .. tostring(n) .. "), which enters the outputs Merkle root\n")
            os.exit(1)
        end
    end
end
io.stderr:write("OK: invalid ABI bool word rejected or decoded to a valid bool; no wrong output committed\n")
os.exit(0)
