local emu = require"emu"

emu.run {
    version = 1,
    machine = "riscv64",
    memory_size = 128,
    kernel = "kernel.bin",
    cmdline = "quiet console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw",
    flash0 = {
        address = 0x60000000,
        size = 0x08000000,
        shared = true,
        label = "root",
        backing = "root-other.bin"
    }
}
