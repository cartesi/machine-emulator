local emu = require"emu"

emu.run {
    version = 1,
    machine = "riscv64",
    memory_size = 128,
    kernel = "kernel.bin",
    cmdline = "quiet console=hvc0 rootfstype=ext2 root=/dev/vda rw",
    drive0 = {
        file = "root.bin"
    }
}
