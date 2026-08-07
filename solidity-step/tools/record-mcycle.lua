#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0
--
-- Records the step log of one whole mcycle: record-mcycle.lua <program.bin> <mcycle> <out.log>

local cartesi = require("cartesi")
local prog, target, out = arg[1], tonumber(arg[2]), arg[3]
local m = assert(cartesi.machine({
    ram = { length = 32 << 20, backing_store = { data_filename = prog } },
    flash_drive = { { start = 0x80000000000000, length = 0x40000 } },
}))
while m:read_reg("mcycle") < target do
    os.remove(out)
    m:log_step_uarch(1 << 30, out)
    m:reset_uarch()
end
os.remove(out)
m:log_step_uarch(1 << 30, out)
print(string.format("recorded mcycle %d (cycles=%d) to %s", target, m:read_reg("uarch_cycle"), out))
