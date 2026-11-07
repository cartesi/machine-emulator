package.preload["dkjson"] = function() return {} end
local cartesi = require("cartesi")
local enc = require("enc")
local eth = require("prt-ethereum")
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
local config = dofile("linux-config.lua")
config.dtb.entrypoint = "rollup accept >/dev/null; rollup accept"
local m = cartesi.machine(config)
assert(m:run(-1) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
local zero = cartesi.keccak256(string.rep("\0", 32))
local function merkle(data)
    local k = 5 while (1 << k) < #data do k = k + 1 end
    local lv = {}
    for i = 0, (1 << (k - 5)) - 1 do
        local leaf = data:sub(i * 32 + 1, i * 32 + 32)
        lv[#lv + 1] = (#leaf == 0) and zero or cartesi.keccak256(leaf .. string.rep("\0", 32 - #leaf))
    end
    while #lv > 1 do local n = {} for i = 1, #lv, 2 do n[#n + 1] = cartesi.keccak256(lv[i], lv[i + 1]) end lv = n end
    return lv[1]
end
local id = 0
local snapshot_dir = nil
for _, len in ipairs({ 1, 32, 33, 1000, 4096 }) do
    local data = string.rep("\x77", len - 1) .. "\x01"
    -- input-start transition: send + step (cycle with mcycle=0, ucycle=0)
    local mc = cartesi.machine(config) ; assert(mc:run(-1) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
    local before = mc:get_root_hash()
    local send_log = mc:log_send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, data, before)
    local step_log = mc:log_step_uarch()
    local response = { send_cmio_log = send_log, step_log = step_log }
    local cycle = 3 << 68
    local proof = eth.transition_proof(response, cycle, data):sub(3)
    local exp = assert(eth.raw(eth.verify_transition(response, cycle, data, eth.hex(before))))
    id = id + 1
    out:write(enc.req(id, "bridge", { { "b32", enc.hex(before) }, { "uint", 3 }, { "b32", enc.hex(merkle(data)) }, { "bytes", proof } }, exp, "input start len=" .. len))
    -- finish this mcycle with uarch, then the last-ucycle transition (no-op step + reset)
    while mc:read_reg("uarch_halt") == 0 do mc:log_step_uarch() end
    local b2 = mc:get_root_hash()
    local r2 = { step_log = mc:log_step_uarch(), reset_uarch_log = mc:log_reset_uarch() }
    local cyc2 = (3 << 68) | (0 << 20) | ((1 << 20) - 1)
    local p2 = eth.transition_proof(r2, cyc2, data):sub(3)
    local e2 = assert(eth.raw(eth.verify_transition(r2, cyc2, data, eth.hex(b2))))
    id = id + 1
    out:write(enc.req(id, "bridge", { { "b32", enc.hex(b2) }, { "uint", 4 }, { "b32", enc.hex(zero) }, { "bytes", p2 } }, e2, "last ucycle len=" .. len))
    -- ordinary step at mcycle 1
    local b3 = mc:get_root_hash()
    local r3 = { step_log = mc:log_step_uarch() }
    local cyc3 = (3 << 68) | (1 << 20) | 0
    local p3 = eth.transition_proof(r3, cyc3, data):sub(3)
    local e3 = assert(eth.raw(eth.verify_transition(r3, cyc3, data, eth.hex(b3))))
    id = id + 1
    out:write(enc.req(id, "bridge", { { "b32", enc.hex(b3) }, { "uint", 0 }, { "b32", enc.hex(zero) }, { "bytes", p3 } }, e3, "ordinary len=" .. len))
end
-- input start with no input in the slot: prefix with zero length, no send
local mc = cartesi.machine(config) ; assert(mc:run(-1) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
local b = mc:get_root_hash()
local r = { step_log = mc:log_step_uarch() }
local p = eth.transition_proof(r, 5 << 68, nil):sub(3)
local e = assert(eth.raw(eth.verify_transition(r, 5 << 68, nil, eth.hex(b))))
id = id + 1
out:write(enc.req(id, "bridge", { { "b32", enc.hex(b) }, { "uint", 1 }, { "b32", enc.hex(zero) }, { "bytes", p } }, e, "empty slot"))
out:close()
