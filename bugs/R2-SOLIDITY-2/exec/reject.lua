local cartesi = require("cartesi")
local enc = require("enc")
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
local config = dofile("linux-config.lua")
config.dtb.entrypoint = "rollup accept >/dev/null; rollup reject >/dev/null; rollup accept"
local function new() return cartesi.machine(config) end
local m = new()
assert(m:run(-1) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
local y1 = m:read_reg("mcycle")
local before = m:get_root_hash()
m:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "hello", before)
assert(m:run(-1) == cartesi.BREAK_REASON_YIELDED_MANUALLY)
local y2 = m:read_reg("mcycle")
io.stderr:write(string.format("y1=%d y2=%d tohost=%x\n", y1, y2, m:read_reg("htif_tohost")))
-- replay with uarch over the last mcycles before the rejecting yield
local m2 = new()
m2:run(y1)
m2:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, "hello", before)
m2:run(y2 - 2)
local id = 0
for mc = 1, 3 do
    while true do
        local b = m2:get_root_hash(); local l = m2:log_step_uarch(); local a = m2:get_root_hash()
        id = id + 1
        out:write(enc.req(id, "stepOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, "rej step mcycle=" .. m2:read_reg("mcycle")))
        if m2:read_reg("uarch_halt") ~= 0 then break end
    end
    local b = m2:get_root_hash(); local l = m2:log_reset_uarch()
    local a = cartesi.machine:verify_reset_uarch(b, l)
    io.stderr:write(string.format("mc %d mcycle=%d Y=%d reset->revert? %s\n", mc, m2:read_reg("mcycle"), m2:read_reg("iflags_Y"), tostring(a == before)))
    id = id + 1
    out:write(enc.req(id, "resetOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, "rej reset"))
end
out:close()
