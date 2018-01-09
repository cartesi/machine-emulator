local emu = require"emu"

local config = {
    version = 1,
    machine = "riscv64",
    memory_size = 128,
    kernel = "kernel-new.bin",
    cmdline = "quiet console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw",
    flash0 = {
        address = 0x60000000,
        size = 0x08000000,
        shared = false,
        label = "root",
        backing = "root.bin"
    },
    flash1 = {
        address = 0x68000000,
        size = 0x01000000,
        shared = true,
        label = "input",
        backing = "input.bin"
    }
}

emu.run(config)

