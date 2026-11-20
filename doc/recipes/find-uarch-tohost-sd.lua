local cartesi = require("cartesi")
local fs = require("cartesi.filesystem")

local stored = assert(arg[1], "missing argument: machine")
local input = assert(arg[2], "missing argument: input")
local input_mcycle_offset = assert(tonumber(arg[3]), "missing argument: input_mcycle_offset")

-- The stored machine is the state that receives the input
local machine = cartesi.machine(stored)
machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, fs.read_file(input), machine:get_root_hash())
local mcycle = machine:read_reg("mcycle") + input_mcycle_offset
repeat
until machine:run(mcycle) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE

local HTIF_TOHOST_ADDRESS = cartesi.machine:get_reg_address("htif_tohost")
local STORE = 0x23
local SD = 3
while machine:read_reg("uarch_halt") == 0 do
    local pc = machine:read_reg("uarch_pc")
    local insn = string.unpack("<I4", machine:read_memory(pc, 4))
    if insn & 0x7f == STORE and (insn >> 12) & 0x7 == SD then
        local rs1 = (insn >> 15) & 0x1f
        local imm = ((insn >> 25) << 5) | ((insn >> 7) & 0x1f)
        imm = (imm ~ 0x800) - 0x800
        if machine:read_reg("uarch_x" .. rs1) + imm == HTIF_TOHOST_ADDRESS then
            io.stderr:write(machine:read_reg("uarch_cycle"))
            return
        end
    end
    local uarch_cycle = machine:read_reg("uarch_cycle")
    machine:run_uarch(uarch_cycle + 1)
    if uarch_cycle % 10 ^ 5 == 0 then
        collectgarbage("collect")
    end
end
error("sd to htif.tohost not found before uarch halt")
