local cartesi = require("cartesi")
local M = {}
M.RAM = 0x80000000
M.PTE_ADDR = 0x80010010
M.PTE_INITIAL = (0x80000 << 10) | 0xF -- V|R|W|X, A=0, D=0
M.PTE_ACCESSED = M.PTE_INITIAL | 0x40 -- A set by the page walk
function M.code()
    local f = assert(io.open("guest.bin", "rb"))
    local code = f:read("a")
    f:close()
    return code
end
function M.new_machine()
    local m = cartesi.machine({ processor = { registers = { pc = M.RAM } }, ram = { length = 1 << 20 } })
    m:write_memory(M.RAM, M.code())
    m:write_memory(M.PTE_ADDR, string.pack("<I8", M.PTE_INITIAL))
    return m
end
return M
