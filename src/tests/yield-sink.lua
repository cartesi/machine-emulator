local cartesi = require"cartesi"

print("testing yield sink")

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

local images_path = adjust_images_path(os.getenv('CARTESI_IMAGES_PATH'))

-- Config yields 5 times with progress
local config =  {
  processor = {
    mvendorid = -1,
    mimpid = -1,
    marchid = -1,
  },
  ram = {
    image_filename = images_path .. "linux.bin",
    length = 0x4000000,
  },
  rom = {
    image_filename = images_path .. "rom.bin",
    bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet mtdparts=flash.0:-(root) -- for i in $(seq 1 5); do yield progress $i; done",
  },
  htif = {
    yield_progress = true,
  },
  flash_drive = {
    {
      image_filename = images_path .. "rootfs.ext2",
      start = 0x8000000000000000,
      length = 0x3c00000,
    },
  },
}

local machine = cartesi.machine(config)

-- running the machine to maxinteger should stop early 5 times before halting
for i = 1, 5 do
    machine:run(math.maxinteger)
    -- when it stops, iflags.Y should be set
    assert(machine:read_iflags_Y())
    local mcycle = machine:read_mcycle()
    -- trying to run it without resetting iflags.Y should not advance
    machine:run(math.maxinteger)
    assert(mcycle == machine:read_mcycle())
    assert(machine:read_iflags_Y())
    -- now reset it so the machine can be advanced
    machine:reset_iflags_Y()
end
-- finally run to completion
machine:run(math.maxinteger)
assert(machine:read_iflags_H())

print("  passed")
