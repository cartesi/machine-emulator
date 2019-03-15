#!/usr/local/bin/luapp

local cartesi = require"cartesi"

-- Print help and exit
local function help()
    io.stderr:write([=[
Usage:
  lua run.lua [options]
where options are:
  --ram-image=<filename>       binary image for RAM
                               (default: "kernel.bin")

  --no-ram-image               forget settings for ram-image

  --rom-image=<filename>       binary image for ROM
                               (default: none)

  --memory-size=<number>       target memory in MiB
                               (default: 64)

  --root-backing=<filename>    backing storage for root filesystem
                               corresponding to /dev/mtdblock0 mounted as /
                               (default: rootfs.ext2)

  --no-root-backing            forget (default) backing settings for root

  --<label>-backing=<filename> backing storage for <label> filesystem
                               corresponding to /dev/mtdblock[1-7]
                               and mounted by init as /mnt/<label>
                               (default: none)

  --<label>-shared             target modifications to <label> filesystem
                               modify backing storage as well
                               (default: false)

  --max-mcycle                 stop at a given mcycle

  --step                       run a step after stopping

  --cmdline                    pass additional command-line arguments to kernel

  --batch                      run in batch mode

  --initial-hash               prints initial hash before running

  --final-hash                 prints final hash after running

  --ignore-payload             do not report error on non-zero payload

  --dump                       dump non-pristine pages to disk
]=])
    os.exit()
end

local backing = { root = "rootfs.ext2" }
local backing_order = { "root" }
local shared = { }
local ram_image = "kernel.bin"
local rom_image
local cmdline = ""
local memory_size = 64
local batch = false
local initial_hash = false
local final_hash = false
local ignore_payload = false
local dump = false
local max_mcycle
local step = false

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
		if not backing[d] then
			backing_order[#backing_order+1] = d
		end
        backing[d] = f
        return true
    end },
    { "^%-%-no%-root%-backing$", function(all)
        if not all then return false end
		assert(backing.root and backing_order[1] == "root",
			"no root backing to remove")
		backing.root = nil
		shared.root = nil
		table.remove(backing_order, 1)
        return true
    end },
    { "^%-%-ignore%-payload$", function(all)
        if not all then return false end
        ignore_payload = true
        return true
    end },
    { "^%-%-dump$", function(all)
        if not all then return false end
        dump = true
        return true
    end },
    { "^%-%-step$", function(all)
        if not all then return false end
        step = true
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
        assert(n >= 0, "not enough memory " .. all)
        memory_size = math.ceil(n)
        return true
    end },
    { "^(%-%-max%-mcycle%=(%d+)(.*))$", function(all, n, e)
        if not n then return false end
        assert(e == "", "invalid option " .. all)
        n = assert(tonumber(n), "invalid option " .. all)
        assert(n >= 0, "invalid option " .. all)
        max_mcycle = math.ceil(n)
        return true
    end },
    { "^%-%-ram%-image%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        ram_image = o
        return true
    end },
    { "^%-%-no%-ram%-image$", function(all)
        if not all then return false end
		ram_image = nil
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

local config = new_config(
):set_ram_image(
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

for i, label in ipairs(backing_order) do
    config = config:append_drive{
        backing = backing[label],
        shared = shared[label],
        label = label
    }
end

local function hexhash(hash)
    return (string.gsub(hash, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hexhash8(hash)
    return string.sub(hexhash(hash), 1, 8)
end

local function print_root_hash(machine)
    print("Updating merkle tree: please wait")
    machine:update_merkle_tree()
    print(hexhash(machine:get_root_hash()))
end

local function indentout(level, ...)
    local step = "  "
    io.stdout:write(string.rep(step, level), ...)
end

local function print_log(log)
    local d = 0
    local j = 1
    local i = 1
    while true do
        local bj = log.brackets[j]
        local ai = log.accesses[i]
        if not bj and not ai then break end
        if bj and bj.where <= i then
            if bj.type == "begin" then
                indentout(d, "begin ", bj.text, "\n")
                d = d + 1
            elseif bj.type == "end" then
                d = d - 1
                indentout(d, "end ", bj.text, "\n")
            end
            j = j + 1
        elseif ai then
            local ai = log.accesses[i]
            indentout(d, "hash ", hexhash8(ai.proof.root_hash), "\n")
            if ai.type == "read" then
                indentout(d, "read ", log.notes[i], string.format("@%x",
                    ai.proof.address), ": ", ai.read, "\n")
            else
                assert(ai.type == "write")
                indentout(d, "write ", log.notes[i], string.format("@%x",
                    ai.proof.address), ": ", ai.read, " -> ", ai.written, "\n")
            end
            i = i + 1
        end
    end
end

local machine = cartesi.machine(config)

if dump then
    machine:dump()
end

if initial_hash then
    print_root_hash(machine)
end

if not max_mcycle then
    local mcycle_incr = 500000
    local mcycle_end = mcycle_incr
    while true do
        machine:run(mcycle_end)
        if machine:read_iflags_H() then
            break
        end
        mcycle_end = mcycle_end + mcycle_incr
    end
else
    machine:run(max_mcycle)
end

local payload = 0

if machine:read_iflags_H() then
    payload = (machine:read_tohost() & (~1 >> 16)) >> 1
    io.stderr:write("payload: ", payload, "\n")
elseif step then
    io.stderr:write("Gathering step proof: please wait\n")
    print_log(machine:step())
end

local cycles = machine:read_mcycle()
io.stderr:write("cycles: ", cycles, "\n")

if final_hash then
    print_root_hash(machine)
end

machine:destroy() -- redundant: garbage collector would take care of this

os.exit(payload, true)
