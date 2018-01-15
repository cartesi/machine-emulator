local emu = require"emu"

local config = {
    version = 1,
    machine = "riscv64",
    interactive = true,
    memory_size = 128,
    kernel = "kernel.bin",
    cmdline = "quiet console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw",
    flash0 = {
        address = 0x60000000,
        size = 0x08000000,
        shared = false,
        label = "root",
        backing = "root.bin"
    },
}

local m = emu.create(config)

local step = 500000
local cycles_end = step
while 1 do
    local c, e = m:run(cycles_end)
    if c then
        cycles_end = cycles_end + step
        --io.stderr:write("stepping to ", cycles_end, "\n")
    else
        io.stderr:write("done in ", e, " cycles\n")
        break
    end
end
