-- Shared setup for the R8-DYNPERSIST-1 test: a minimal machine with 1 MiB of RAM, and the host write it receives.
local cartesi = require("cartesi")
local M = {}

M.RAM_START = 0x80000000
M.RAM_LENGTH = 1 << 20
M.PAGE_INDEX = 64 -- RAM page that the host API writes
M.OFFSET = M.PAGE_INDEX * 4096 + 0x10 -- offset of the written word inside RAM
M.TARGET = M.RAM_START + M.OFFSET
M.WORD = 0xabababababababab -- value written (as a word, or as 8 bytes of 0xab)
M.RAM_BIN = string.format("%016x-%x.bin", M.RAM_START, M.RAM_LENGTH)

function M.new_machine()
    return cartesi.machine({
        processor = { registers = { pc = M.RAM_START } },
        ram = { length = M.RAM_LENGTH },
    })
end

-- Applies the host write with the given API function name ("write_memory" or "write_word")
function M.apply(m, fn)
    if fn == "write_memory" then
        m:write_memory(M.TARGET, string.rep("\xab", 8))
    elseif fn == "write_word" then
        m:write_word(M.TARGET, M.WORD)
    else
        error("unknown API function " .. tostring(fn))
    end
end

return M
