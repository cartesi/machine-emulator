local cartesi = require"cartesi"

local machine = cartesi.machine(require"config-nothing-to-do")

local mcycle = machine:read_mcycle()
local tohost = machine:read_htif_tohost()
local line = 0
while not machine:read_iflags_H() and not machine:read_iflags_Y() do
    machine:run(mcycle+1)
    local newtohost = machine:read_htif_tohost()
    if tohost ~= newtohost then
        tohost = newtohost
        if tohost & 0xff == 0x0a then
            line = line+1
            if line == 8 then
                io.stderr:write(mcycle)
                break
            end
        end
    end
    mcycle = machine:read_mcycle()
    if mcycle % 10^5  == 0 then
        collectgarbage("collect")
    end
end
