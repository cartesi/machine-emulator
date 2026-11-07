-- Shared setup for the R7-FPUARCH-1 test: a tiny bare-metal guest that keeps writing a counter to one RAM page.
local cartesi = require("cartesi")
local M = {}

M.RAM_START = 0x80000000
M.RAM_LENGTH = 1 << 20
M.PAGE_INDEX = 5 -- the page the guest writes
M.TARGET = M.RAM_START + M.PAGE_INDEX * 4096
M.FIRST_RUN = 1000 -- mcycles run before the machine is stored
M.SECOND_RUN = 2000 -- mcycle target after the crash-recovered reload
M.RAM_DPT = string.format("%016x-%x.dpt", M.RAM_START, M.RAM_LENGTH)

-- Guest program, hand-encoded RV64I (see guest.S for the source):
--   auipc t1, 5          # t1 = 0x80005000
-- 1: addi t0, t0, 1
--   sd    t0, 0(t1)      # store through the write TLB entry of RAM page 5
--   j     1b
M.CODE = string.pack("<I4I4I4I4", 0x00005317, 0x00128293, 0x00533023, 0xff9ff06f)

function M.new_machine()
    local m = cartesi.machine({
        processor = { registers = { pc = M.RAM_START } },
        ram = { length = M.RAM_LENGTH },
    })
    m:write_memory(M.RAM_START, M.CODE)
    return m
end

-- Position of a page's leaf in the dirty-page tree file (root at 1, leaves at 2^levels .. 2^(levels+1)-1)
function M.leaf_position(page)
    local leaves = M.RAM_LENGTH >> 12
    return leaves + page
end

return M
