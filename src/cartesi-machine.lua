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

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function parse_number(n)
    if not n then return nil end
    local base, rest = string.match(n, "^%s*(0x%x+)%s*(.-)%s*$")
    if not base then
        base, rest = string.match(n, "^%s*(%d+)%s*(.-)%s*$")
    end
    base = tonumber(base)
    if not base then return nil end
    if rest == "Ki" then return base << 10
    elseif rest == "Mi" then return base << 20
    elseif rest == "Gi" then return base << 30
    elseif rest == "" then return base end
    local shift = string.match(rest, "^%s*%<%<%s*(%d+)$")
    if shift then
        shift = tonumber(shift)
        if shift then return base << shift end
    end
    return nil
end

local function parse_flash(s)
    local function escape(v)
        -- replace escaped \, :, and , with something "safe"
        v = string.gsub(v, "%\\%\\", "\0")
        v = string.gsub(v, "%\\%:", "\1")
        return string.gsub(v, "%\\%,", "\2")
    end
    local function unescape(v)
        v = string.gsub(v, "\0", "\\")
        v = string.gsub(v, "\1", ":")
        return string.gsub(v, "\2", ",")
    end
    local keys = {
        label = true,
        filename = true,
        shared = true,
        length = true,
        start = true
    }
    -- split at commas and validate key
    local options = {}
    string.gsub(escape(s) .. ",", "(.-)%,", function(o)
        local k, v = string.match(o, "(.-):(.*)")
        if k and v then
            k = unescape(k)
            v = unescape(v)
        else
            k = unescape(o)
            v = true
        end
        assert(keys[k], string.format("unknown flash drive option '%q'", k))
        options[k] = v
    end)
    options.image_filename = options.filename
    options.filename = nil
    return options
end

-- Print help and exit
local function help()
    stderr([=[
Usage:

  %s [options]

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

    (default: "root:rootfs.ext2")

  --max-mcycle=<number>
    stop at a given mcycle (default: 2305843009213693952)

  -i or --htif-console-getchar
    run in interactive mode

  --htif-yield-progress
    honor yield progress requests by target

  --htif-yield-rollup
    honor yield rollup requests by target

  --dump-config
    dump initial config to screen

  --load=<directory>
    load prebuilt machine from <directory>

  --store=<directory>
    store machine to <directory>

  --initial-hash
    print initial hash before running machine

  --final-hash
    print final hash when done

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

<number> can be specified in decimal (e.g., 16) or hexadeximal (e.g., 0x10),
with a suffix multiplier (i.e., Ki, Mi, Gi for 2^10, 2^20, 2^30, respectively),
or a left shift (e.g., 2 << 20).

]=], arg[0])
    os.exit()
end

local flash_image_filename = { root = "rootfs.ext2" }
local flash_label_order = { "root" }
local flash_shared = { }
local flash_start = { }
local flash_length = { }
local ram_image_filename = "kernel.bin"
local ram_length = 64 << 20
local rom_image_filename = "rom.bin"
local rom_bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw"
local append_rom_bootargs = ""
local console_get_char = false
local htif_yield_progress = false
local htif_yield_rollup = false
local initial_hash = false
local final_hash = false
local periodic_hashes_period = math.maxinteger
local periodic_hashes_start = 0
local dump_pmas = false
local dump_config = false
local max_mcycle = math.maxinteger
local json_steps
local step = false
local store_dir = nil
local load_dir = nil

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
        ram_length = assert(parse_number(n), "invalid RAM length " .. n)
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
        console_getchar = true
        return true
    end },
    { "^%-i$", function(all)
        if not all then return false end
        console_getchar = true
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
    { "^(%-%-flash%-drive%=(.+))$", function(all, f)
        if not f then return false end
        local f = parse_flash(f)
        assert(f.label, "missing flash drive label in " .. all)
        if f.image_filename == true then f.image_filename = "" end
        assert(not f.shared or f.shared == true,
            "invalid flash drive shared value in " .. all)
        if f.start then
            f.start = assert(parse_number(f.start),
                "invalid flash drive start in " .. all)
        end
        if f.length then
            f.length = assert(parse_number(f.length),
                "invalid flash drive length in " .. all)
        end
        local d = f.label
        if not flash_image_filename[d] then
            flash_label_order[#flash_label_order+1] = d
            flash_image_filename[d] = ""
        end
        flash_length[d] = f.length or flash_length[d]
        flash_start[d] = f.start or flash_start[d]
        flash_image_filename[d] = f.image_filename or
            flash_image_filename[d]
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
        max_mcycle = assert(parse_number(n), "invalid option " .. all)
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
            periodic_hashes_period = assert(parse_number(p), "invalid period " .. all)
            periodic_hashes_start = assert(parse_number(s), "invalid start " .. all)
        end)
        if periodic_hashes_period == math.maxinteger then
            periodic_hashes_period = assert(parse_number(v), "invalid period " .. all)
            periodic_hashes_start = 0
        end
        initial_hash = true
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

local config_meta = {
    __index = { }
}

function config_meta.__index:append_flash(t)
    local flash = {
        start = t.start,
        length = t.length,
        image_filename = t.image_filename,
        shared = t.shared
    }
    self.flash[self._flash_id] = flash
    self._flash_id = self._flash_id+1
    return self
end

function config_meta.__index:append_rom_bootargs(rom_bootargs)
    if rom_bootargs and rom_bootargs ~= "" then
        self.rom.bootargs = self.rom.bootargs .. " " .. rom_bootargs
    end
    return self
end

function config_meta.__index:set_console_getchar(console_getchar)
    self.htif = self.htif or {}
    self.htif.console_getchar = console_getchar
    return self
end

function config_meta.__index:set_htif_yield_progress(htif_yield_progress)
    self.htif = self.htif or {}
    self.htif.yield_progress = htif_yield_progress
    return self
end

function config_meta.__index:set_htif_yield_rollup(htif_yield_rollup)
    self.htif = self.htif or {}
    self.htif.yield_rollup = htif_yield_rollup
    return self
end

function config_meta.__index:set_ram_length(length)
    self.ram = self.ram or {}
    self.ram.length = length
    return self
end

function config_meta.__index:set_rom_bootargs(rom_bootargs)
    self.rom = self.rom or {}
    self.rom.bootargs = rom_bootargs
    return self
end

function config_meta.__index:set_ram_image_filename(ram_image_filename)
    self.ram = self.ram or {}
    self.ram.image_filename = ram_image_filename
    return self
end

function config_meta.__index:set_rom_image_filename(rom_image_filename)
    self.rom = self.rom or {}
    self.rom.image_filename = rom_image_filename
    return self
end

local function new_config()
    return setmetatable({
        processor = {
            mvendorid = cartesi.machine.MVENDORID,
            marchid = cartesi.machine.MARCHID,
            mimpid = cartesi.machine.MIMPID
        },
        flash = {},
        _flash_id = 1,
    }, config_meta)
end

local function hexhash(hash)
    return (string.gsub(hash, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hexhash8(hash)
    return string.sub(hexhash(hash), 1, 8)
end

local function print_root_hash(cycles, machine)
    machine:update_merkle_tree()
    stderr("%d: %s\n", cycles, hexhash(machine:get_root_hash()))
end

local function indentout(level, fmt, ...)
    local step = "  "
    io.stderr:write(string.rep(step, level), string.format(fmt, ...))
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
                indentout(d, "begin %s\n", bj.text)
                d = d + 1
            elseif bj.type == "end" then
                d = d - 1
                indentout(d, "end %s\n", bj.text)
            end
            j = j + 1
        elseif ai then
            local ai = log.accesses[i]
            indentout(d, "hash %s\n", hexhash8(ai.proof.root_hash))
            if ai.type == "read" then
                indentout(d, "%d: read %s@0x%x(%u): 0x%x(%u)\n", i,
                    log.notes[i], ai.proof.address, ai.proof.address,
                    ai.read, ai.read)
            else
                assert(ai.type == "write")
                indentout(d, "%d: write %s@0x%x(%u): 0x%x(%u) -> 0x%x(%u)\n", i,
                    log.notes[i], ai.proof.address, ai.proof.address,
                    ai.read, ai.read, ai.written, ai.written)
            end
            i = i + 1
        end
    end
end

local function intstring(v)
    local a = ""
    for i = 0, 7 do
        a = a .. string.format("%02x", (v >> i*8) & 0xff)
    end
    return a
end

local function print_json_log_sibling_hashes(sibling_hashes, log2_size, out, indent)
    out:write('[\n')
    for i, h in ipairs(sibling_hashes) do
        out:write(indent,'"', hexhash(h), '"')
        if sibling_hashes[i+1] then out:write(',\n') end
    end
    out:write(' ]')
end

local function print_json_log_proof(proof, out, indent)
    out:write('{\n')
    out:write(indent, '"address": ', proof.address, ',\n')
    out:write(indent, '"log2_size": ', proof.log2_size, ',\n')
    out:write(indent, '"target_hash": "', hexhash(proof.target_hash), '",\n')
    out:write(indent, '"sibling_hashes": ')
    print_json_log_sibling_hashes(proof.sibling_hashes, proof.log2_size, out,
        indent .. "  ")
    out:write(",\n", indent, '"root_hash": "', hexhash(proof.root_hash), '" }')
end

local function print_json_log_notes(notes, out, indent)
    local indent2 = indent .. "  "
    local n = #notes
    out:write('[\n')
    for i, note in ipairs(notes) do
        out:write(indent2, '"', note, '"')
        if i < n then out:write(',\n') end
    end
    out:write(indent, '],\n')
end

local function print_json_log_brackets(brackets, out, indent)
    local n = #brackets
    out:write('[ ')
    for i, bracket in ipairs(brackets) do
        out:write('{\n')
        out:write(indent, '  "type": "', bracket.type, '",\n')
        out:write(indent, '  "where": ', bracket.where, ',\n')
        out:write(indent, '  "text": "', bracket.text, '"')
        out:write(' }\n')
        if i < n then out:write(', ') end
    end
    out:write(' ]')
end

local function print_json_log_access(access, out, indent)
    out:write('{\n')
    out:write(indent, '"type": "', access.type, '",\n')
    out:write(indent, '"read": "', intstring(access.read), '",\n')
    out:write(indent, '"written": "', intstring(access.written or 0), '",\n')
    out:write(indent, '"proof": ')
    print_json_log_proof(access.proof, out, indent .. "  ")
    out:write(' }')
end

local function print_json_log_accesses(accesses, out, indent)
    local indent2 = indent .. "  "
    local n = #accesses
    out:write('[ ')
    for i, access in ipairs(accesses) do
        print_json_log_access(access, out, indent2)
        if i < n then out:write(',\n', indent) end
    end
    out:write(indent, ' ],\n')
end

local function print_json_log(log, init_cycles, final_cycles, out, indent)
    out:write('{\n')
    out:write(indent, '"init_cycles": ', init_cycles, ',\n')
    out:write(indent, '"final_cycles": ', final_cycles, ',\n')
    out:write(indent, '"accesses": ')
    print_json_log_accesses(log.accesses, out, indent)
    out:write(indent, '"notes": ')
    print_json_log_notes(log.notes, out, indent)
    out:write('  "brackets": ')
    print_json_log_brackets(log.brackets, out, indent)
    out:write(' }')
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
        error(string.format("flash drive start set for %s but missing for %s",
            table.concat(found, ", "), table.concat(missing, ", ")))
    end
end

local machine

if load_dir then
    stderr("Loading machine: please wait\n")
    machine = cartesi.machine(load_dir)
else
    -- Resolve all device starts and lengths
    resolve_flash_lengths(flash_label_order, flash_image_filename, flash_start,
        flash_length)
    resolve_flash_starts(flash_label_order, flash_image_filename, flash_start,
        flash_length)

    local config = new_config(
    ):set_ram_image_filename(
        ram_image_filename
    ):set_ram_length(
        ram_length
    ):set_rom_image_filename(
        rom_image_filename
    ):set_rom_bootargs(
        rom_bootargs
    )

    local mtdparts = {}
    for i, label in ipairs(flash_label_order) do
        config = config:append_flash{
            image_filename = flash_image_filename[label],
            shared = flash_shared[label],
            start = flash_start[label],
            length = flash_length[label]
        }
        mtdparts[#mtdparts+1] = string.format("flash.%d:-(%s)", i-1, label)
    end
    if #mtdparts > 0 then
        config = config:append_rom_bootargs("mtdparts=" ..
            table.concat(mtdparts, ";"))
    end

    config = config:append_rom_bootargs(
        append_rom_bootargs
    ):set_console_getchar(
        console_getchar
    ):set_htif_yield_progress(
        htif_yield_progress
    ):set_htif_yield_rollup(
        htif_yield_rollup
    )

    stderr("Building machine: please wait\n")
    machine = cartesi.machine(config)
end

if not json_steps then
    if console_getchar then
        stderr("Running in interactive mode!\n")
    end
    if dump_config then
        dump_machine_config(machine:get_initial_config())
    end
    local cycles = machine:read_mcycle()
    if initial_hash then
        assert(not console_getchar, "hashes are meaningless in interactive mode")
        print_root_hash(cycles, machine)
    end
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
            payload = machine:read_htif_tohost() << 16 >> 17
            stderr("\nHalted with payload: %u\n", payload)
            stderr("Cycles: %u\n", cycles)
            break
        elseif machine:read_iflags_Y() then
            local tohost = machine:read_htif_tohost()
            local cmd = tohost << 8 >> 56
            local data = tohost << 16 >> 16
            if cmd == 0 then
                stderr("Progress: %6.2f\r", data/100)
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
        assert(not console_getchar, "step proof is meaningless in interactive mode")
        stderr("Gathering step proof: please wait\n")
        print_log(machine:step())
    end
    if dump_pmas then
        machine:dump_pmas()
    end
    if final_hash then
        assert(not console_getchar, "hashes are meaningless in interactive mode")
        print_root_hash(cycles, machine)
    end
    if store_dir then
        assert(not console_getchar, "hashes are meaningless in interactive mode")
        stderr("Storing machine: please wait\n")
        machine:store(store_dir)
    end
    os.exit(payload, true)
else
    assert(not console_getchar, "logs are meaningless in interactive mode")
    json_steps = assert(io.open(json_steps, "w"))
    json_steps:write("[ ")
    for i = 0, max_mcycle do
        if machine:read_iflags_H() then
            break
        end
        local init_cycles = machine:read_mcycle()
        local log = machine:step()
        local final_cycles = machine:read_mcycle()
        print_json_log(log, init_cycles, final_cycles, json_steps, "  ")
        stderr("%u -> %u\n", init_cycles, final_cycles)
        if i ~= max_mcycle then json_steps:write(', ') end
    end
    json_steps:write(' ]\n')
    json_steps:close()
    if store_dir then
        stderr("Storing machine: please wait\n")
        machine:store(store_dir)
    end
end
