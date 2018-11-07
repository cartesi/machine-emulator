local cartesi = require"cartesi"

-- Print help and exit
local function help()
    io.stderr:write([=[
Usage:
  lua run.lua [options]
where options are:
  --ram-image=<filename>       binary image for RAM
                               (default: "kernel.bin")
  --rom-image=<filename>       binary image for ROM
                               (default: none)
  --memory-size=<number>       target memory in MiB
                               (default: 64)
  --root-backing=<filename>    backing storage for root filesystem
                               corresponding to /dev/mtdblock0 mounted as /
                               (default: rootfs.ext2)
  --<label>-backing=<filename> backing storage for <label> filesystem
                               corresponding to /dev/mtdblock[1-7]
                               and mounted by init as /mnt/<label>
                               (default: none)
  --<label>-shared             target modifications to <label> filesystem
                               modify backing storage as well
                               (default: false)
  --cmdline                    pass additional command-line arguments to kernel
  --batch                      run in batch mode
  --initial-hash               prints initial hash before running
  --final-hash                 prints final hash after running
  --ignore-payload             do not report error on non-zero payload
]=])
    os.exit()
end

local backing = { root = "rootfs.ext2"}
local shared = { }
local ram_image = "kernel.bin"
local rom_image
local cmdline = ""
local memory_size = 64
local batch = false
local initial_hash = false
local final_hash = false
local ignore_payload = false

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
    { "^%-%-(%w+)-backing%=(.+)$", function(d, f)
        if not d or not f then return false end
        backing[d] = f
        return true
    end },
    { "^%-%-ignore%-payload$", function(all)
        if not all then return false end
        ignore_payload = true
        return true
    end },
    { "^%-%-(%w+)%-shared$", function(d)
        if not d then return false end
        shared[d] = true
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
        if not o or #o < 1 then return false end
        rom_image = o
        return true
    end },
    { "^%-%-cmdline%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        cmdline = o
        return true
    end },
    { "^%-%-initial%-hash$", function(all)
        if not all then return false end
        initial_hash = true
        return true
    end },
    { "^%-%-final%-hash$", function(all)
        if not all then return false end
        final_hash = true
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

local function get_file_length(filename)
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
    __index = { }
}

function config_meta.__index:append_drive(t)
    local length = assert(get_file_length(
        assert(t.backing, "no backing file specified")),
            "unable to compute backing file length")
    local flash = {
        start = self._flash_base,
        length = length,
        backing = t.backing,
        shared = t.shared,
        label = assert(t.label, "no label specified")
    }
    self.flash[self._flash_id] = flash
    self._flash_id = self._flash_id+1
    -- make sure flash drives are separated by a power of two and at least 1MB
    self._flash_base = self._flash_base + math.max(next_power_of_2(length), 1024*1024)
    return self
end

function config_meta.__index:append_cmdline(cmdline)
    if cmdline and cmdline ~= "" then
        self.rom.bootargs = self.rom.bootargs .. " " .. cmdline
    end
    return self
end

function config_meta.__index:set_interactive(interactive)
    self.interactive = interactive
    return self
end

function config_meta.__index:set_memory_size(memory_size)
    self.ram.length = memory_size << 20
    return self
end

function config_meta.__index:set_ram_image(ram_image)
    self.ram.backing = ram_image
    return self
end

function config_meta.__index:set_rom_image(rom_image)
    self.rom.backing = rom_image
    return self
end

local function new_config()
    return setmetatable({
        machine = cartesi.get_name(),
        ram = {
            length = 64 << 20
        },
        rom = {
            bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw",
        },
        interactive = true,
        flash = {},
        _flash_base = 1 << 63,
        _flash_id = 1,
    }, config_meta)
end

local config = new_config():append_drive{
    backing = backing.root,
    shared = shared.root,
    label = "root"
}:set_ram_image(
    ram_image
):set_rom_image(
    rom_image
):set_memory_size(
    memory_size
):append_cmdline(
    cmdline
):set_interactive(
    not batch
)

for label, file in pairs(backing) do
    if label ~= "root" then
        config = config:append_drive{
            backing = file,
            shared = shared[label],
            label = label
        }
    end
end

local function print_hash(machine)
    print("Updating merkle tree: please wait")
    machine:update_merkle_tree()
    print((string.gsub(machine:get_merkle_tree_root_hash(), ".", function(c)
        return string.format("%02x", string.byte(c))
    end)))
end

local machine = cartesi.machine(config)

if initial_hash then
    print_hash(machine)
end

local step = 500000
local cycles_end = step
while true do
    machine:run(cycles_end)
    if machine:read_iflags_H() then
        break
    end
    cycles_end = cycles_end + step
end
local payload = (machine:read_tohost() & (~1 >> 16)) >> 1
local cycles = machine:read_mcycle()
io.stdout:write("cycles: ", cycles, "\n")
io.stdout:write("payload: ", payload, "\n")

if final_hash then
    print_hash(machine)
end

machine:destroy() -- redundant: garbage collector would take care of this

os.exit(payload, true)
