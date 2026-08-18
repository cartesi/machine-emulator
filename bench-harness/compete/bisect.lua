#!/usr/bin/env lua5.4
-- Checkpoint-hash harness: run <workload>, print root hash at each mcycle
-- checkpoint given on the command line (ascending). Deterministic across
-- builds, so diffing two builds' outputs locates the first divergent window.
-- Usage: LUA_CPATH=<build>/?.so lua5.4 bisect.lua <images> <workload> <m1> <m2> ...

local cartesi = require("cartesi")

local images_dir = assert(arg[1])
local workload = assert(arg[2])

local commands = {
    memcpy = "stress-ng --no-rand-seed --memcpy 1 --timeout 10m >> /dev/null",
    nop = "stress-ng --no-rand-seed --nop 1 --timeout 10m >> /dev/null",
    syscall = "stress-ng --no-rand-seed --syscall 1 --timeout 10m >> /dev/null",
}
local command = assert(commands[workload], "unknown workload")

local machine <close> = cartesi.machine({
    ram = { length = 512 * 1024 * 1024,
        backing_store = { data_filename = images_dir .. "/linux.bin" } },
    dtb = { entrypoint = command },
    flash_drive = { { backing_store = { data_filename = images_dir .. "/rootfs.ext2" } } },
})

for i = 3, #arg do
    local target = assert(tonumber(arg[i]))
    machine:run(target)
    local mcycle = machine:read_reg("mcycle")
    local hash = machine:get_root_hash()
    print(string.format("%d %s", mcycle,
        (hash:gsub(".", function(c) return string.format("%02x", c:byte()) end))))
    io.flush()
end
