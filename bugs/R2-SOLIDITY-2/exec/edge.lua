local cartesi = require("cartesi")
local enc = require("enc")
local out = assert(io.popen((os.getenv("RUNNER") or "python3 run.py"), "w"))
local id = 0
local MAX = cartesi.UARCH_CYCLE_MAX
local cycles = { 0, MAX - 2, MAX - 1, MAX, MAX + 1, 1 << 40, -1, (1 << 63) }
local halts = { 0, 1, 2, -1 }
for _, cyc in ipairs(cycles) do
    for _, h in ipairs(halts) do
        for _, rej in ipairs({ false, true }) do
            local m = cartesi.machine({ ram = { length = 1 << 12 } })
            if rej then
                m:write_reg("iflags_Y", 1)
                m:write_reg("htif_tohost", (2 << 56) | (1 << 48) | (2 << 32))
            end
            m:write_reg("uarch_cycle", cyc); m:write_reg("uarch_halt", h)
            for s = 1, 3 do
                local b = m:get_root_hash()
                local ok, l = pcall(m.log_step_uarch, m)
                if not ok then io.stderr:write("log_step_uarch threw: cyc=" .. cyc .. " h=" .. h .. " " .. l .. "\n") break end
                local a = m:get_root_hash()
                id = id + 1
                out:write(enc.req(id, "stepOnly", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l) } }, a, string.format("cyc=%x h=%d s=%d", cyc, h, s)))
            end
            local b = m:get_root_hash()
            local l1 = m:log_step_uarch()
            local l2 = m:log_reset_uarch()
            local a = cartesi.machine:verify_reset_uarch(cartesi.machine:verify_step_uarch(b, l1), l2)
            id = id + 1
            out:write(enc.req(id, "stepReset", { { "b32", enc.hex(b) }, { "bytes", enc.proof(l1, l2) } }, a, string.format("stepReset cyc=%x h=%d rej=%s", cyc, h, tostring(rej))))
        end
    end
end
out:close()
