local cartesi = require("cartesi")
local enc = require("enc")
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
local UR = cartesi.UARCH_RAM_START_ADDRESS
local id = 0
for _, addr in ipairs({ -8, -32, -40, -64 }) do
  for _, insn in ipairs({ 0x0000b283 --[[ld x5,0(x1)]], 0x0050b023 --[[sd x5,0(x1)]] }) do
    local m = cartesi.machine({ ram = { length = 1 << 12 } })
    m:write_memory(UR, string.pack("<I4", insn))
    m:write_reg("uarch_pc", UR); m:write_reg("uarch_x1", addr); m:write_reg("uarch_x5", 0x1122334455667788)
    local b = m:get_root_hash()
    local ok, l = pcall(m.log_step_uarch, m)
    if ok then
      local a = m:get_root_hash()
      local v = cartesi.machine:verify_step_uarch(b, l)
      io.stderr:write(string.format("addr=%x insn=%08x cpp log ok, cpp verify %s\n", addr, insn, tostring(v == a)))
      id = id + 1
      out:write(enc.req(id, "stepOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, string.format("addr=%x insn=%08x", addr, insn)))
    else io.stderr:write("log threw " .. tostring(l) .. "\n") end
  end
end
out:close()
