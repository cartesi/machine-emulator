#!/usr/bin/env lua5.4
-- Cross-emulator harness, cartesi side: boots the standard guest with an
-- extra flash drive carrying the SAME static stress-ng binary the other
-- emulators run, mounts it, runs the given command, and reports the
-- wall/cpu time from process start to machine halt plus final mcycle.
-- A "true" command gives the boot baseline to subtract.
-- Usage: LUA_CPATH=<build>/?.so lua5.4 compete.lua <linux.bin> <bench.ext2> "<cmd>"

local cartesi = require("cartesi")
local linux_image = assert(arg[1])
local rootfs = assert(arg[2]) -- rootfs copy carrying /usr/bin/stress-ng-musl
local cmd = assert(arg[3])

local entry = cmd == "true" and "true" or (cmd .. " >> /dev/null 2>&1")

-- bench-init sidesteps cartesi-init: both full-system columns (cartesi and
-- qemu-system) run the identical four-line init, so the guest software path
-- differs only in the root device name.
local machine <close> = cartesi.machine({
    ram = {
        length = 512 * 1024 * 1024,
        backing_store = { data_filename = linux_image },
    },
    dtb = {
        entrypoint = entry,
        bootargs = "quiet earlycon=sbi console=hvc0 root=/dev/pmem0 rw init=/usr/sbin/bench-init",
    },
    flash_drive = {
        { backing_store = { data_filename = rootfs } },
    },
})

local start = os.clock()
local reason = machine:run(1 << 62)
local elapsed = os.clock() - start
print(string.format("%.3f %d %d", elapsed, machine:read_reg("mcycle"), reason))
