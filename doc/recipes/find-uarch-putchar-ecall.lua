local cartesi = require("cartesi")

local mcycle = assert(tonumber(arg[1]), "missing argument: mcycle")

local config = require("config-nothing-to-do")
local machine = cartesi.machine(config)

machine:run(mcycle)

local PUTCHAR = cartesi.UARCH_ECALL_FN_PUTCHAR
local ECALL = 0x00000073
while machine:read_reg("uarch_halt") == 0 do
    local pc = machine:read_reg("uarch_pc")
    local insn = string.unpack("<I4", machine:read_memory(pc, 4))
    if insn == ECALL and machine:read_reg("uarch_x17") == PUTCHAR then
        io.stderr:write(machine:read_reg("uarch_cycle"))
        return
    end
    local uarch_cycle = machine:read_reg("uarch_cycle")
    machine:run_uarch(uarch_cycle + 1)
    if uarch_cycle % 10 ^ 5 == 0 then
        collectgarbage("collect")
    end
end
error("putchar ecall not found before uarch halt")
