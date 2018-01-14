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

repeat
    local c = m:interrupt_and_run(500000)
until not c
