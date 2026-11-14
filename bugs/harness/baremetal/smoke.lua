-- Smoke test of the bare-metal guest builder: boots each example built by build.sh and checks its rollup
-- behavior through the cmio/yield interface. Run: lua5.4 bugs/harness/baremetal/smoke.lua (after . bugs/env.sh)
local cartesi = require("cartesi")
local hash_tree = require("cartesi.hash-tree")
local harness = require("harness")

local function config(bin)
    return {
        ram = { length = 64 << 20, backing_store = { data_filename = harness.baremetal(bin) } },
    }
end

local EMPTY_ROOT = hash_tree.frontier_get_root_hash(hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256"))

local function tohost(m)
    local v = m:read_reg("htif_tohost")
    return v >> 56, (v >> 48) & 0xff, (v >> 32) & 0xffff, v & 0xffffffff
end

local function expect_manual(m, want_reason)
    local br = m:run(math.maxinteger)
    assert(br == cartesi.BREAK_REASON_YIELDED_MANUALLY, "expected manual yield, got break reason " .. br)
    local dev, cmd, reason = tohost(m)
    assert(dev == cartesi.HTIF_DEV_YIELD and cmd == cartesi.HTIF_YIELD_CMD_MANUAL, "not a manual yield")
    assert(reason == want_reason, "manual yield reason " .. reason .. ", want " .. want_reason)
end

local function advance(m, payload)
    m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, payload, m:get_root_hash())
end

local checks = 0
local function ok(name)
    checks = checks + 1
    io.stderr:write("  ok ", name, "\n")
end

-- halt
do
    local m <close> = cartesi.machine(config("halt"))
    assert(m:run(math.maxinteger) == cartesi.BREAK_REASON_HALTED)
    assert(m:read_reg("iflags_H") ~= 0)
    assert(m:read_reg("htif_tohost_data") >> 1 == 42, "exit code")
    ok("halt: halts with exit code 42")
end

-- accept and accept-asm: initial accept with empty root, then accept each advance
for _, name in ipairs({ "accept", "accept-asm" }) do
    local m <close> = cartesi.machine(config(name))
    expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    assert(m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 32) == EMPTY_ROOT, "empty outputs root in tx buffer")
    assert(m:read_reg("htif_tohost_data") & 0xffffffff == 32, "accept length 32")
    for i = 1, 3 do
        advance(m, "input " .. i)
        expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    end
    ok(name .. ": valid-template accept, accepts advance inputs")
end

-- reject
do
    local m <close> = cartesi.machine(config("reject"))
    expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    advance(m, "x")
    expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    ok("reject: rejects advance input")
end

-- emit-output: output = request, report "r", accept with updated outputs root
do
    local m <close> = cartesi.machine(config("emit-output"))
    expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    local frontier = hash_tree.frontier(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT, "keccak256")
    for i = 1, 3 do
        local payload = string.rep(string.char(i), 100 * i)
        advance(m, payload)
        local br = m:run(math.maxinteger)
        assert(br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY, "expected output yield")
        local _, cmd, reason, len = tohost(m)
        assert(cmd == cartesi.HTIF_YIELD_CMD_AUTOMATIC and reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_OUTPUT)
        local out = m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, len)
        assert(out == payload, "output equals input")
        hash_tree.frontier_push_back(frontier, cartesi.keccak256(out))
        br = m:run(math.maxinteger)
        assert(br == cartesi.BREAK_REASON_YIELDED_AUTOMATICALLY, "expected report yield")
        _, _, reason, len = tohost(m)
        assert(reason == cartesi.HTIF_YIELD_AUTOMATIC_REASON_TX_REPORT and len == 1)
        expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
        local root = m:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 32)
        assert(root == hash_tree.frontier_get_root_hash(frontier), "guest outputs root equals host frontier root")
    end
    advance(m, "R")
    expect_manual(m, cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    ok("emit-output: output/report yields, outputs Merkle root matches host, reject on 'R'")
end

-- uarch agreement on one bare-metal mcycle (sanity of the uarch on these guests)
do
    local m <close> = cartesi.machine(config("emit-output"))
    local m2 <close> = cartesi.machine(config("emit-output"))
    for _ = 1, 50 do
        m:run_uarch(math.maxinteger)
        m:reset_uarch()
    end
    m2:run(50)
    assert(m:get_root_hash() == m2:get_root_hash(), "uarch and native agree after 50 mcycles")
    ok("uarch and native agree on 50 mcycles of emit-output")
end

io.stderr:write(string.format("baremetal smoke: %d checks passed\n", checks))
