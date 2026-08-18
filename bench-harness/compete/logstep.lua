-- Boot into a syscall-heavy region, then log_step (which internally verifies
-- record->replay root-hash equality) across windows that cross SUM toggles
-- and traps.
local cartesi = require("cartesi")
local m <close> = cartesi.machine({
    ram = { length = 512*1024*1024, backing_store = { data_filename = arg[1] .. "/linux.bin" } },
    dtb = {
        entrypoint = "/usr/bin/stress-ng-musl --no-rand-seed --syscall 1 --syscall-ops 200000 >> /dev/null",
        bootargs = "quiet earlycon=sbi console=hvc0 root=/dev/pmem0 rw init=/usr/sbin/bench-init",
    },
    flash_drive = { { backing_store = { data_filename = arg[2] } } },
})
m:run(300 * 1000 * 1000) -- deep into the stressor: kernel entries + uaccess
for i = 1, 5 do
    m:log_step(100000, "/tmp/claude-0/step-" .. i .. ".log")  -- verifies internally
    m:run(m:read_reg("mcycle") + 3000000)
end
print("LOG-STEP-OK mcycle " .. m:read_reg("mcycle"))
