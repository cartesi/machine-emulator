#!/usr/bin/env lua5.4
-- Fixed-work benchmark harness per tail-call.md section 9 / 8b item 10.
-- One workload per process: the online recorder's trace pool is a per-thread
-- static that outlives a machine object, so workloads must not share a process.
-- Usage: LUA_CPATH=<builddir>/?.so lua5.4 bench.lua <images_dir> <workload>
-- Prints one line: <workload> <elapsed_cpu_s> <mcycle> <root_hash_hex> <reason>

local cartesi = require("cartesi")

local images_dir = assert(arg[1], "missing images dir")
local workload = assert(arg[2], "missing workload name")

-- The ten workloads of tail-call.md 8b item 9. sieve and double are cpu
-- methods of the --cpu stressor; the rest are stressors of their own name.
local commands = {
    sieve = "stress-ng --no-rand-seed --cpu 1 --cpu-method sieve --timeout 10m >> /dev/null",
    double = "stress-ng --no-rand-seed --cpu 1 --cpu-method double --timeout 10m >> /dev/null",
    int64 = "stress-ng --no-rand-seed --cpu 1 --cpu-method int64 --timeout 10m >> /dev/null",
    matrixprod = "stress-ng --no-rand-seed --cpu 1 --cpu-method matrixprod --timeout 10m >> /dev/null",
    nop = "stress-ng --no-rand-seed --nop 1 --timeout 10m >> /dev/null",
    memcpy = "stress-ng --no-rand-seed --memcpy 1 --timeout 10m >> /dev/null",
    hash = "stress-ng --no-rand-seed --hash 1 --timeout 10m >> /dev/null",
    zlib = "stress-ng --no-rand-seed --zlib 1 --timeout 10m >> /dev/null",
    regs = "stress-ng --no-rand-seed --regs 1 --timeout 10m >> /dev/null",
    qsort = "stress-ng --no-rand-seed --qsort 1 --timeout 10m >> /dev/null",
    branch = "stress-ng --no-rand-seed --branch 1 --timeout 10m >> /dev/null",
    tree = "stress-ng --no-rand-seed --tree 1 --timeout 10m >> /dev/null",
    -- continuity workload of the six-workload harness (section 4)
    syscall = "stress-ng --no-rand-seed --syscall 1 --timeout 10m >> /dev/null",
}

local command = assert(commands[workload], "unknown workload: " .. workload)

local boot_mcycle = 256 * 1024 * 1024 -- boot to here first, untimed
local compute_mcycle = 1 << 30 -- then run exactly this much, timed

local machine <close> = cartesi.machine({
    ram = {
        length = 512 * 1024 * 1024,
        backing_store = {
            data_filename = images_dir .. "/linux.bin",
        },
    },
    dtb = {
        entrypoint = command,
    },
    flash_drive = {
        {
            backing_store = {
                data_filename = images_dir .. "/rootfs.ext2",
            },
        },
    },
})

-- Boot into the benchmark (untimed)
local boot_reason = machine:run(boot_mcycle)
assert(boot_reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE,
    workload .. ": boot ended early (reason=" .. tostring(boot_reason) .. ")")

-- Timed fixed-work section
local target = boot_mcycle + compute_mcycle
local start = os.clock()
local reason = machine:run(target)
local elapsed = os.clock() - start

local mcycle = machine:read_reg("mcycle")
local hash = machine:get_root_hash()

print(string.format("%s %.3f %d %s %d", workload, elapsed, mcycle,
    (hash:gsub(".", function(c) return string.format("%02x", c:byte()) end)), reason))
