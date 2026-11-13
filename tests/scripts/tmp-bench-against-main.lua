#!/usr/bin/env lua5.4
-- TEMPORARY: remove before merge, together with tmp-bench-against-main.sh and its CI job.
-- Boots into a stress-ng workload untimed, then times a fixed number of mcycles.
-- usage: tmp-bench-against-main.lua <images dir> <workload>
local cartesi = require("cartesi")

local images_dir = assert(arg[1], "missing images dir")
local workload = assert(arg[2], "missing workload")
local cpu_methods = { sieve = true, double = true, int64 = true, matrixprod = true }
local stressor = cpu_methods[workload] and ("--cpu 1 --cpu-method " .. workload) or ("--" .. workload .. " 1")
local boot_mcycle = 256 << 20
local timed_mcycles = tonumber(os.getenv("BENCH_MCYCLES") or (1 << 30))

local machine <close> = cartesi.machine({
    ram = { length = 512 << 20, backing_store = { data_filename = images_dir .. "/linux.bin" } },
    dtb = { entrypoint = "stress-ng --no-rand-seed " .. stressor .. " --timeout 10m >> /dev/null" },
    flash_drive = { { backing_store = { data_filename = images_dir .. "/rootfs.ext2" } } },
})
assert(machine:run(boot_mcycle) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE, "boot ended early")
local start = os.clock()
local reason = machine:run(boot_mcycle + timed_mcycles)
local elapsed = os.clock() - start
assert(reason == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE, "workload ended early")
print(string.format("%.3f", elapsed))
