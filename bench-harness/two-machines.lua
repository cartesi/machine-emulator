#!/usr/bin/env lua5.4
-- Per-machine trace-state gate: run two different workloads through two
-- machine objects in ONE process, sequentially and then interleaved.
-- Under the per-thread pool this was unsound (traces recorded against one
-- machine's mapping were offered to the next); per-machine state must
-- reproduce the canonical single-process hashes.
local cartesi = require("cartesi")
local images_dir = assert(arg[1], "missing images dir")

local function make(entry)
    return cartesi.machine({
        ram = { length = 512 * 1024 * 1024, backing_store = { data_filename = images_dir .. "/linux.bin" } },
        dtb = { entrypoint = entry },
        flash_drive = { { backing_store = { data_filename = images_dir .. "/rootfs.ext2" } } },
    })
end

local boot = 256 * 1024 * 1024
local target = boot + (1 << 30)
local function hex(h)
    return (h:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

-- interleaved: two live machines alternating run windows
local a = make("stress-ng --no-rand-seed --cpu 1 --cpu-method sieve --timeout 10m >> /dev/null")
local b = make("stress-ng --no-rand-seed --qsort 1 --timeout 10m >> /dev/null")
local step = 64 * 1024 * 1024
local at, bt = 0, 0
while at < target or bt < target do
    if at < target then
        at = math.min(at + step, target)
        a:run(at)
    end
    if bt < target then
        bt = math.min(bt + step, target)
        b:run(bt)
    end
end
print("sieve", a:read_reg("mcycle"), hex(a:get_root_hash()))
print("qsort", b:read_reg("mcycle"), hex(b:get_root_hash()))
a:destroy()
b:destroy()

-- sequential reuse of the thread after destruction
local c = make("stress-ng --no-rand-seed --memcpy 1 --timeout 10m >> /dev/null")
c:run(target)
print("memcpy", c:read_reg("mcycle"), hex(c:get_root_hash()))
