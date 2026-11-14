-- Pristine uarch state hash as the emulator's own hash tree sees it: the hash-tree node of height
-- UARCH_STATE_LOG2_SIZE at UARCH_STATE_START_ADDRESS of a fresh machine (uarch registers pristine), with the
-- uarch RAM replaced by the given binary (zero-padded), or the embedded pristine uarch RAM if no argument.
-- Usage: lua5.4 node-hash.lua [uarch-ram.bin]   -> prints the hash in hex
local cartesi = require("cartesi")
local m <close> = cartesi.machine({ ram = { length = 4096 } })
if arg[1] then
    local f = assert(io.open(arg[1], "rb"))
    local bin = f:read("a")
    f:close()
    assert(#bin <= cartesi.UARCH_RAM_LENGTH, "uarch ram image too large")
    m:write_memory(cartesi.UARCH_RAM_START_ADDRESS, bin .. string.rep("\0", cartesi.UARCH_RAM_LENGTH - #bin))
end
local p = m:get_proof(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)
io.write(cartesi.tohex(p.target_hash), "\n")
