local cartesi = require("cartesi")
local enc = require("enc")
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
local config = dofile("linux-config.lua")
config.dtb.entrypoint = "ls / >/dev/null; rollup accept"
local m = cartesi.machine(config)
local found, id = 0, 0
local seed = tonumber(arg[1]) or 1
math.randomseed(seed)
local t = 1000000
while found < 12 and t < 70000000 do
  t = t + math.random(100000, 3000000)
  if m:run(t) ~= cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE then break end
  for mc = 1, 40 do
    local hit = false
    while true do
      local b = m:get_root_hash()
      local l = m:log_step_uarch()
      local tl = false
      for _, a in ipairs(l.accesses) do if a.type == "write" and a.log2_size == 5 then tl = true end end
      if tl then
        local a = m:get_root_hash(); id = id + 1; found = found + 1; hit = true
        out:write(enc.req(id, "stepOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, "tlb write mcycle=" .. m:read_reg("mcycle")))
      end
      if m:read_reg("uarch_halt") ~= 0 then break end
    end
    m:log_reset_uarch()
    if hit then break end
  end
end
io.stderr:write("tlb writes verified: " .. found .. "\n")
out:close()
