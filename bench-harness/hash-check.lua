#!/usr/bin/env lua5.4
-- Determinism gate: boot Linux + run a stress workload for a fixed cycle count,
-- then print mcycle, break reason and the machine root hash.
-- Compare output between builds: it must be bit-identical.
package.cpath = '../src/?.so;'..package.cpath
local cartesi = require("cartesi")

local machine <close> = cartesi.machine({
  ram = {
    length = 512 << 20,
    backing_store = { data_filename = "/usr/share/cartesi-machine/images/linux.bin" },
  },
  dtb = {
    entrypoint = "stress-ng --no-rand-seed --cpu 1 --timeout 20s >> /dev/null",
  },
  flash_drive = {
    { backing_store = { data_filename = "/usr/share/cartesi-machine/images/rootfs.ext2" } },
  },
})

local reason = machine:run(400 * 1024 * 1024)
print(string.format("mcycle:  %d", machine:read_reg("mcycle")))
print(string.format("reason:  %d", reason))
print(string.format("root:    %s", (machine:get_root_hash():gsub('.', function(c)
  return string.format('%02x', string.byte(c))
end))))
