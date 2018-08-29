local emu = require"emu"

-- Print help and exit
local function help()
    io.stderr:write([=[
Usage:
  lua run.lua [options]
where options are:
  --ram-image=<filename>     binary image for RAM
                             (default: "kernel.bin")
  --rom-image=<filename>     binary image for ROM
                             (default: none)
  --root-backing=<filename>  backing storage for root filesystem
                             appears as /dev/mtdblock0
                             (default: "rootfs.bin")
  --root-shared              target modifications to root filesystem
                             modify backing storage as well
  --memory-size=<number>     target memory in MiB
                             (default: 128)
  --extra-backing=<filename> backing storage for extra filesystem
                             appears as /dev/mtdblock1
                             (default: none)
  --extra-shared             target modifications to extra filesystem
                             modify backing storage as well
                             (default: false)
  --cmdline                  pass additional command-line arguments to kernel
  --batch                    run in batch mode
]=])
    os.exit()
end

local root_backing = "rootfs.bin"
local root_shared
local extra_backing
local extra_shared
local ram_image = "kernel.bin"
local rom_image
local cmdline = ""
local memory_size = 128
local batch = false

-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    { "^%-%-help$", function(all)
        if all then
            help()
            return true
        else
            return false
        end
    end },
    { "^%-%-batch$", function(all)
        if not all then return false end
        batch = true
        return true
    end },
    { "^%-%-root%-backing%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        root_backing = o
        return true
    end },
    { "^%-%-extra%-backing%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        extra_backing = o
        return true
    end },
    { "^%-%-extra%-shared$", function(all)
        if not all then return false end
        extra_shared = true
        return true
    end },
    { "^%-%-root%-shared$", function(all)
        if not all then return false end
        root_shared = true
        return true
    end },
    { "^(%-%-memory%-size%=(%d+)(.*))$", function(all, n, e)
        if not n then return false end
        assert(e == "", "invalid option " .. all)
        n = assert(tonumber(n), "invalid option " .. all)
        assert(n >= 16, "invalid option " .. all)
        memory_size = math.ceil(n)
        return true
    end },
    { "^%-%-ram%-image%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        ram_image = o
        return true
    end },
    { "^%-%-rom%-image%=(.*)$", function(o)
print(o)
        if not o or #o < 1 then return false end
        rom_image = o
        return true
    end },
    { "^%-%-cmdline%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        cmdline = o
        return true
    end },
    { ".*", function(all)
        error("unrecognized option " .. all)
    end }
}

-- Process command line options
for i, a in ipairs(arg) do
    for j, option in ipairs(options) do
        if option[2](a:match(option[1])) then
            break
        end
    end
end

local function get_file_size(filename)
    local file = io.open(filename, "rb")
    if not file then return nil end
    local size = file:seek("end")    -- get file size
    file:close()
    return size
end

local function next_power_of_2(value)
    local i = 1
    while i < value do
        i = i*2
    end
    return i
end

local config_meta = {
    __index = {
        version = 1,
        machine = "riscv64",
        interactive = true,
        cmdline = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw",
        flash_base = 1 << 63,
        flash_id = 0,
    }
}

function config_meta.__index:append_drive(t)
    if t.backing then
        local size = assert(get_file_size(
            assert(t.backing, "no backing file specified")),
                "backing file not found")
        size = math.max(next_power_of_2(size), 1024*1024)
        local flash = {
            address = self.flash_base,
            size = size,
            backing = t.backing,
            shared = t.shared,
            label = assert(t.label, "no label specified")
        }
        self["flash" .. self.flash_id] = flash
        self.flash_id = self.flash_id+1
        self.flash_base = self.flash_base+size
    end
    return self
end

function config_meta.__index:append_cmdline(cmdline)
    if cmdline and cmdline ~= "" then
        self.cmdline = self.cmdline .. " " .. cmdline
    end
    return self
end

function config_meta.__index:set_interactive(interactive)
    self.interactive = interactive
    return self
end

function config_meta.__index:set_memory_size(memory_size)
    self.memory_size = memory_size
    return self
end

function config_meta.__index:set_ram_image(ram_image)
    self.ram_image = ram_image
    return self
end

function config_meta.__index:set_rom_image(rom_image)
    self.rom_image = rom_image
    return self
end

local function new_config(t)
    local config = setmetatable({}, config_meta)
    return config:append_drive{
        backing = t.root_backing,
        shared = t.root_shared,
        label = "root"
    }
end

local config = new_config{
    root_backing = root_backing,
    root_shared = root_shared
}:set_ram_image(
    ram_image
):set_rom_image(
    rom_image
):append_drive{
    backing = extra_backing,
    shared = extra_shared,
    label = "extra"
}:set_memory_size(
    memory_size
):append_cmdline(
    cmdline
):set_interactive(
    not batch
)

local machine = emu.create(config)

local step = 500000
local cycles_end = step
local cycles = 0
local not_halted, payload
while true do
    cycles, not_halted, payload = machine:run(cycles_end)
    if not_halted then
        cycles_end = cycles_end + step
    else
        break
    end
end
io.stdout:write("cycles: ", cycles, "\n")
io.stdout:write("payload: ", payload, "\n")
machine:destroy()
os.exit(payload)
