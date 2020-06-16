#!/usr/bin/env luapp5.3

-- Copyright 2019 Cartesi Pte. Ltd.
--
-- This file is part of the machine-emulator. The machine-emulator is free
-- software: you can redistribute it and/or modify it under the terms of the GNU
-- Lesser General Public License as published by the Free Software Foundation,
-- either version 3 of the License, or (at your option) any later version.
--
-- The machine-emulator is distributed in the hope that it will be useful, but
-- WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
-- FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
-- for more details.
--
-- You should have received a copy of the GNU Lesser General Public License
-- along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
--

local cartesi = require"cartesi"
local util = require"cartesi.util"

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

-- Print help and exit
local function help()
    stderr([=[
Usage:

  %s [options] [command] [arguments]

where options are:

  --ram-image=<filename>
    name of file containing RAM image (default: "kernel.bin")

  --no-ram-image
    forget settings for RAM image

  --ram-length=<number>
    set RAM length

  --rom-image=<filename>
    name of file containing ROM image (default: "rom.bin")

  --no-rom-bootargs
    clear default bootargs

  --append-rom-bootargs=<string>
    append <string> to bootargs

  --no-root-flash-drive
    clear default root flash drive and associated bootargs parameters

  --flash-drive=<key>:<value>[,<key>:<value>[,...]...]
    defines a new flash drive, or modify an existing flash drive definition
    flash drives appear as /dev/mtdblock[1-7]

    <key>:<value> is one of
        label:<label>
        filename:<filename>
        start:<number>
        length:<number>
        shared

        label (mandatory)
        identifies the flash drive and init attempts to mount it as /mnt/<label>

        filename (optional)
        gives the name containing the image for the flash drive
        when omitted or set to the empty string, the drive starts filled with 0

        start (optional)
        sets the starting physical memory offset for flash drive in bytes
        when omitted, drives start at 2 << 63 and are spaced by 2 << 60
        if any start offset is set, all of them must be set

        length (optional)
        gives the length of the flash drive in bytes (must be a multiple of 4Ki)
        if omitted, the length is computed from the image in filename
        if length and filename are set, the image file size must match length

        shared (optional)
        target modifications to flash drive modify image file as well
        by default, image files are not modified and changes are lost

    (default: "label:root,filename:rootfs.ext2")

  --max-mcycle=<number>
    stop at a given mcycle (default: 2305843009213693952)

  -i or --htif-console-getchar
    run in interactive mode

  --htif-yield-progress
    honor yield progress requests by target

  --htif-yield-rollup
    honor yield rollup requests by target

  --dump-machine-config
    dump initial machine config to screen

  --load=<directory>
    load prebuilt machine from <directory>

  --store=<directory>
    store machine to <directory>

  --initial-hash
    print initial state hash before running machine

  --final-hash
    print final state hash when done

  --periodic-hashes=<number-period>[,<number-start>]
    prints root hash every <number-period> cycles. If <number-start> is given,
    the periodic hashing will start at that mcycle. This option implies
    --initial-hash and --final-hash.
    (default: none)

  --step
    print step log for 1 additional cycle when done

  --json-steps=<filename>
    output json with step logs for all cycles to <filename>

  --dump-pmas
    dump all PMA ranges to disk when done

and command and arguments:

  command
    the full path to the program inside the target system
    (default: /bin/sh)

  arguments
    the given command arguments

<number> can be specified in decimal (e.g., 16) or hexadeximal (e.g., 0x10),
with a suffix multiplier (i.e., Ki, Mi, Gi for 2^10, 2^20, 2^30, respectively),
or a left shift (e.g., 2 << 20).

]=], arg[0])
    os.exit()
end

local images_path = adjust_images_path(os.getenv('CARTESI_IMAGES_PATH'))
local flash_image_filename = { root = images_path .. "rootfs.ext2" }
local flash_label_order = { "root" }
local flash_shared = { }
local flash_start = { }
local flash_length = { }
local ram_image_filename = images_path .. "kernel.bin"
local ram_length = 64 << 20
local rom_image_filename = images_path .. "rom.bin"
local rom_bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw"
local append_rom_bootargs = ""
local console_get_char = false
local htif_yield_progress = false
local htif_yield_rollup = false
local initial_hash = false
local final_hash = false
local initial_proof = {}
local final_proof = {}
local periodic_hashes_period = math.maxinteger
local periodic_hashes_start = 0
local dump_pmas = false
local dump_config = false
local max_mcycle = math.maxinteger
local json_steps
local step = false
local store_dir = nil
local load_dir = nil
local cmdline_opts_finished = false
local exec_arguments = {}

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
    { "^%-%-rom%-image%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        rom_image_filename = o
        return true
    end },
    { "^%-%-no%-rom%-bootargs$", function(all)
        if not all then return false end
        rom_bootargs = ""
        return true
    end },
    { "^%-%-append%-rom%-bootargs%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        append_rom_bootargs = o
        return true
    end },
    { "^%-%-ram%-length%=(.+)$", function(n)
        if not n then return false end
        ram_length = assert(util.parse_number(n), "invalid RAM length " .. n)
        return true
    end },
    { "^%-%-ram%-image%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        ram_image_filename = o
        return true
    end },
    { "^%-%-no%-ram%-image$", function(all)
        if not all then return false end
        ram_image_filename = ""
        return true
    end },
    { "^%-%-htif%-console-getchar$", function(all)
        if not all then return false end
        htif_console_getchar = true
        return true
    end },
    { "^%-i$", function(all)
        if not all then return false end
        htif_console_getchar = true
        return true
    end },
    { "^%-%-htif%-yield%-progress$", function(all)
        if not all then return false end
        htif_yield_progress = true
        return true
    end },
    { "^%-%-htif%-yield%-rollup$", function(all)
        if not all then return false end
        htif_yield_rollup = true
        return true
    end },
    { "^(%-%-flash%-drive%=(.+))$", function(all, opts)
        if not opts then return false end
        local f = util.parse_options(opts, {
            label = true,
            filename = true,
            shared = true,
            length = true,
            start = true
        })
        assert(f.label, "missing flash drive label in " .. all)
        f.image_filename = f.filename
        f.filename = nil
        if f.image_filename == true then f.image_filename = "" end
        assert(not f.shared or f.shared == true,
            "invalid flash drive shared value in " .. all)
        if f.start then
            f.start = assert(util.parse_number(f.start),
                "invalid flash drive start in " .. all)
        end
        if f.length then
            f.length = assert(util.parse_number(f.length),
                "invalid flash drive length in " .. all)
        end
        local d = f.label
        if not flash_image_filename[d] then
            flash_label_order[#flash_label_order+1] = d
            flash_image_filename[d] = ""
        end
        flash_image_filename[d] = f.image_filename or
            flash_image_filename[d]
        flash_start[d] = f.start or flash_start[d]
        flash_length[d] = f.length or flash_length[d]
        flash_shared[d] = f.shared or flash_shared[d]
        return true
    end },
    { "^(%-%-initial%-proof%=(.+))$", function(all, opts)
        if not opts then return false end
        local p = util.parse_options(opts, {
            address = true,
            log2_size = true,
            filename = true
        })
        p.cmdline = all
        p.address = assert(util.parse_number(p.address),
            "invalid address in " .. all)
        p.log2_size = assert(util.parse_number(p.log2_size),
            "invalid log2_size in " .. all)
        assert(p.log2_size >= 3,
            "log2_size must be at least 3 in " .. all)
        initial_proof[#initial_proof+1] = p
        return true
    end },
    { "^(%-%-final%-proof%=(.+))$", function(all, opts)
        if not opts then return false end
        local p = util.parse_options(opts, {
            address = true,
            log2_size = true,
            filename = true
        })
        p.cmdline = all
        p.address = assert(util.parse_number(p.address),
            "invalid address in " .. all)
        p.log2_size = assert(util.parse_number(p.log2_size),
            "invalid log2_size in " .. all)
        assert(p.log2_size >= 3,
            "log2_size must be at least 3 in " .. all)
        final_proof[#final_proof+1] = p
        return true
    end },
    { "^%-%-no%-root%-flash%-drive$", function(all)
        if not all then return false end
        assert(flash_image_filename.root and flash_label_order[1] == "root",
                 "no root flash drive to remove")
        flash_image_filename.root = nil
        flash_start.root = nil
        flash_length.root = nil
        flash_shared.root = nil
        table.remove(flash_label_order, 1)
        rom_bootargs = "console=hvc0"
        return true
    end },
    { "^%-%-dump%-pmas$", function(all)
        if not all then return false end
        dump_pmas = true
        return true
    end },
    { "^%-%-dump%-machine%-config$", function(all)
        if not all then return false end
        dump_config = true
        return true
    end },
    { "^%-%-step$", function(all)
        if not all then return false end
        step = true
        return true
    end },
    { "^(%-%-max%-mcycle%=(.*))$", function(all, n)
        if not n then return false end
        max_mcycle = assert(util.parse_number(n), "invalid option " .. all)
        return true
    end },
    { "^%-%-load%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        load_dir = o
        return true
    end },
    { "^%-%-store%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        store_dir = o
        return true
    end },
    { "^%-%-json%-steps%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        json_steps = o
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
    { "^(%-%-periodic%-hashes%=(.*))$", function(all, v)
        if not v then return false end
        string.gsub(v, "^([^%,]+),(.+)$", function(p, s)
            periodic_hashes_period = assert(util.parse_number(p),
                "invalid period " .. all)
            periodic_hashes_start = assert(util.parse_number(s),
                "invalid start " .. all)
        end)
        if periodic_hashes_period == math.maxinteger then
            periodic_hashes_period = assert(util.parse_number(v),
                "invalid period " .. all)
            periodic_hashes_start = 0
        end
        initial_hash = true
        final_hash = true
        return true
    end },
    { ".*", function(all)
        if not all then return false end
        local not_option = all:sub(1,1) ~= "-"
        if not_option or all == "--" then
          cmdline_opts_finished = true
          if not_option then exec_arguments = { all } end
          return true
        end
        error("unrecognized option " .. all)
    end }
}

-- Process command line options
for i, a in ipairs(arg) do
    if not cmdline_opts_finished then
      for j, option in ipairs(options) do
          if option[2](a:match(option[1])) then
              break
          end
      end
    else
      exec_arguments[#exec_arguments+1] = a
    end
end

local function get_file_length(filename)
    local file = io.open(filename, "rb")
    if not file then return nil end
    local size = file:seek("end")    -- get file size
    file:close()
    return size
end

local function print_root_hash(cycles, machine)
    machine:update_merkle_tree()
    stderr("%u: %s\n", cycles, util.hexhash(machine:get_root_hash()))
end

local function comment_default(u, v)
    if u ~= v then stderr("\n")
    else stderr(" -- default\n") end
end

local function dump_machine_config(config)
    stderr("machine_config = {\n")
    stderr("  processor = {\n")
    local def = cartesi.machine.DEFAULT_CONFIG
    stderr("    x = {\n")
    local processor = config.processor or { x = {} }
    for i = 1, 31 do
        local xi = processor.x[i] or def.processor.x[i]
        stderr("      0x%x,",  xi)
        comment_default(xi, def.processor.x[i])
    end
    stderr("    },\n")
    local order = {}
    for i,v in pairs(def.processor) do
        if type(v) == "number" then
            order[#order+1] = i
        end
    end
    table.sort(order)
    for i,csr in ipairs(order) do
        local c = processor[csr] or def.processor[csr]
        stderr("    %s = 0x%x,", csr, c)
        comment_default(c,  def.processor[csr])
    end
    stderr("  },\n")
    local ram = config.ram or {}
    stderr("  ram = {\n")
    stderr("    length = 0x%x,", ram.length or def.ram.length)
    comment_default(ram.length, def.ram.length)
    stderr("    image_filename = %q,", ram.image_filename or def.ram.image_filename)
    comment_default(ram.image_filename, def.ram.image_filename)
    stderr("  },\n")
    local rom = config.rom or {}
    stderr("  rom = {\n")
    stderr("    image_filename = %q,", rom.image_filename or def.rom.image_filename)
    comment_default(rom.image_filename, def.rom.image_filename)
    stderr("    bootargs = %q,", rom.bootargs or def.rom.bootargs)
    comment_default(rom.bootargs, def.rom.bootargs)
    stderr("  },\n")
    local htif = config.htif or {}
    stderr("  htif = {\n")
    stderr("    tohost = 0x%x,", htif.tohost or def.htif.tohost)
    comment_default(htif.tohost, def.htif.tohost)
    stderr("    fromhost = 0x%x,", htif.fromhost or def.htif.fromhost)
    comment_default(htif.fromhost, def.htif.fromhost)
    stderr("    console_getchar = %s,", tostring(htif.console_getchar or false))
    comment_default(htif.console_getchar or false, def.htif.console_getchar)
    stderr("    yield_progress = %s,", tostring(htif.yield_progress or false))
    comment_default(htif.yield_progress or false, def.htif.yield_progress)
    stderr("    yield_rollup = %s,", tostring(htif.yield_rollup or false))
    comment_default(htif.yield_rollup or false, def.htif.yield_rollup)
    stderr("  },\n")
    local clint = config.clint or {}
    stderr("  clint = {\n")
    stderr("    mtimecmp = 0x%x,", clint.mtimecmp or def.clint.mtimecmp)
    comment_default(clint.mtimecmp, def.clint.mtimecmp)
    stderr("  },\n")
    stderr("  flash = {\n")
    for i, f in ipairs(config.flash) do
        stderr("    {\n", i)
        stderr("      start = 0x%x,\n", f.start)
        stderr("      length = 0x%x,\n", f.length)
        if f.image_filename and f.image_filename ~= "" then
            stderr("      image_filename = %q,\n", f.image_filename)
        end
        stderr("      shared = %s,", tostring(f.shared or false))
        comment_default(false, f.shared)
        stderr("    },\n")
    end
    stderr("  },\n")
    stderr("}\n")
end

local function resolve_flash_lengths(label_order, image_filename, start, length)
    for i, label in ipairs(label_order) do
        local filename = image_filename[label]
        local len = length[label]
        local filelen
        if filename and filename ~= "" then
            filelen = assert(get_file_length(filename), string.format(
                "unable to find length of flash drive '%s' image file '%s'",
                label, filename))
            if len and len ~= filelen then
                error(string.format("flash drive '%s' length (%u) and image file '%s' length (%u) do not match", label, len, filename, filelen))
            else
                length[label] = filelen
            end
        elseif not len then
            error(string.format(
                "flash drive '%s' nas no length or image file", label))
        end
    end
end

local function resolve_flash_starts(label_order, image_filename, start, length)
    local auto_start = 1<<63
    if next(start) == nil then
        for i, label in ipairs(label_order) do
            start[label] = auto_start
            auto_start = auto_start + (1 << 60)
        end
    else
        local missing = {}
        local found = {}
        for i, label in ipairs(label_order) do
            local quoted = string.format("'%s'", label)
            if start[label] then
                found[#found+1] = quoted
            else
                missing[#missing+1] = quoted
            end
        end
        if #missing > 0 then
            error(string.format("flash drive start set for %s but missing for %s",
                table.concat(found, ", "), table.concat(missing, ", ")))
        end
    end
end

local function dump_value_proofs(machine, desired_proofs, htif_console_getchar)
    if #desired_proofs > 0 then
        assert(not htif_console_getchar,
            "proofs are meaningless in interactive mode")
        machine:update_merkle_tree()
    end
    for i, desired in ipairs(desired_proofs) do
        local proof = machine:get_proof(desired.address, desired.log2_size)
        local out = desired.filename and assert(io.open(desired.filename, "wb"))
            or io.stdout
        out:write("{\n")
        util.dump_json_proof(proof, out, 1)
        out:write("}\n")
    end
end

local machine

local function append(a, b)
    if not a or a == "" then return b
    else return a .. " "  .. b end
end

if load_dir then
    stderr("Loading machine: please wait\n")
    machine = cartesi.machine(load_dir)
else
    -- Resolve all device starts and lengths
    resolve_flash_lengths(flash_label_order, flash_image_filename, flash_start,
        flash_length)
    resolve_flash_starts(flash_label_order, flash_image_filename, flash_start,
        flash_length)

    -- Build machine config
    local config = {
        processor = {
            mvendorid = cartesi.machine.MVENDORID,
            marchid = cartesi.machine.MARCHID,
            mimpid = cartesi.machine.MIMPID
        },
        rom = {
            image_filename = rom_image_filename,
            bootargs = rom_bootargs
        },
        ram = {
            image_filename = ram_image_filename,
            length = ram_length
        },
        htif = {
            console_getchar = htif_console_getchar,
            yield_progress = htif_yield_progress,
            yield_rollup = htif_yield_rollup
        },
        flash = {},
    }

    local mtdparts = {}
    for i, label in ipairs(flash_label_order) do
        config.flash[#config.flash+1] = {
            image_filename = flash_image_filename[label],
            shared = flash_shared[label],
            start = flash_start[label],
            length = flash_length[label]
        }
        mtdparts[#mtdparts+1] = string.format("flash.%d:-(%s)", i-1, label)
    end
    if #mtdparts > 0 then
        config.rom.bootargs = append(config.rom.bootargs, "mtdparts=" ..
            table.concat(mtdparts, ";"))
    end

    config.rom.bootargs = append(config.rom.bootargs, append_rom_bootargs)

    if #exec_arguments > 0 then
        config.rom.bootargs = append(config.rom.bootargs, "-- " ..
            table.concat(exec_arguments, " "))
    end

    stderr("Building machine: please wait\n")
    machine = cartesi.machine(config)
end

if not json_steps then
    if htif_console_getchar then
        stderr("Running in interactive mode!\n")
    end
    if dump_config then
        dump_machine_config(machine:get_initial_config())
    end
    local cycles = machine:read_mcycle()
    if initial_hash then
        assert(not htif_console_getchar,
            "hashes are meaningless in interactive mode")
        print_root_hash(cycles, machine)
    end
    dump_value_proofs(machine, initial_proof, htif_console_getchar)
    local payload = 0
    local next_hash_mcycle
    if periodic_hashes_start ~= 0 then
        next_hash_mcycle = periodic_hashes_start
    else
        next_hash_mcycle = periodic_hashes_period
    end
    while math.ult(cycles, max_mcycle) do
        machine:run(math.min(next_hash_mcycle, max_mcycle))
        cycles = machine:read_mcycle()
        if machine:read_iflags_H() then
            payload = machine:read_htif_tohost_data() >> 1
            stderr("\nHalted with payload: %u\n", payload)
            stderr("Cycles: %u\n", cycles)
            break
        elseif machine:read_iflags_Y() then
            local cmd = machine:read_htif_tohost_cmd()
            local data = machine:read_htif_tohost_data()
            if cmd == cartesi.HTIF_YIELD_PROGRESS then
                stderr("Progress: %6.2f\r", data/10)
            else
                stderr("\nYielded cmd: %u, data: %u\n", cmd, data)
                stderr("Cycles: %u\n", cycles)
            end
        end
        if cycles == next_hash_mcycle then
            print_root_hash(cycles, machine)
            next_hash_mcycle = next_hash_mcycle + periodic_hashes_period
        end
    end
    if not math.ult(cycles, max_mcycle) then
        stderr("\nCycles: %u\n", cycles)
    end
    if step then
        assert(not htif_console_getchar,
            "step proof is meaningless in interactive mode")
        stderr("Gathering step proof: please wait\n")
        util.dump_log(machine:step{ proofs = true, annotations = true },
            io.stderr)
    end
    if dump_pmas then
        machine:dump_pmas()
    end
    if final_hash then
        assert(not htif_console_getchar,
            "hashes are meaningless in interactive mode")
        print_root_hash(cycles, machine)
    end
    dump_value_proofs(machine, final_proof, htif_console_getchar)
    if store_dir then
        assert(not htif_console_getchar,
            "hashes are meaningless in interactive mode")
        stderr("Storing machine: please wait\n")
        machine:store(store_dir)
    end
    os.exit(payload, true)
else
    assert(not htif_console_getchar, "logs are meaningless in interactive mode")
    json_steps = assert(io.open(json_steps, "w"))
    json_steps:write("[\n")
    local log_type = {} -- no proofs or annotations
    for i = 0, max_mcycle do
        if machine:read_iflags_H() then
            break
        end
        local init_cycles = machine:read_mcycle()
        local log = machine:step(log_type)
        local final_cycles = machine:read_mcycle()
        util.dump_json_log(log, init_cycles, final_cycles, json_steps, 1)
        stderr("%u -> %u\n", init_cycles, final_cycles)
        if i ~= max_mcycle then json_steps:write(',\n')
		else json_steps:write('\n') end
    end
    json_steps:write(']\n')
    json_steps:close()
    if store_dir then
        stderr("Storing machine: please wait\n")
        machine:store(store_dir)
    end
end
