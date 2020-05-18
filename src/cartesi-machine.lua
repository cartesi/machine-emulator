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

-- Print help and exit
local function help()
    stderr([=[
Usage:

  %s [options]

where options are:

  --ram-backing=<filename>
    binary image for RAM (default: "kernel.bin")

  --no-ram-image
    forget settings for ram-image

  --ram-length=<number>
    set RAM length

  --rom-backing=<filename>
    binary image for ROM (default: "rom.bin")

  --root-backing=<filename>
    backing storage for root file-system corresponding
    to /dev/mtdblock0 mounted as / (default: rootfs.ext2)

  --no-root-backing
    forget (default) backing settings for root

  --flash-<label>-backing=<filename>
    backing storage for <label> file-system corresponding to /dev/mtdblock[1-7]
    and mounted by init as /mnt/<label> (default: none)

  --flash-<label>-shared
    target modifications to <label> file-system modify backing storage as well
    (default: false)

  --flash-<label>-start=<number>
    set the starting memory position for <label> file-system
    (either set the position for no file-system, or set for all of them)

  --flash-<label>-length=<number>
    set the byte length of the <label> file-system

  --max-mcycle=<number>
    stop at a given mcycle (default: 2305843009213693952)

  --no-rom-bootargs
    clear default bootargs

  --append-rom-bootargs=<string>
    append <string> to bootargs

  -i or --htif-interact
    run in interactive mode

  --htif-yield
    honor yield requests by target

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

local PAGE_SIZE = 4096
local flash_base = 1<<63
local backing = { root = "rootfs.ext2" }
local backing_order = { "root" }
local shared = { }
local start = { }
local length = { }
local ram_image = "kernel.bin"
local rom_image = "rom.bin"
local bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw"
local append_bootargs = ""
local ram_length = 64 << 20
local interact = false
local yield = false
local initial_hash = false
local final_hash = false
local dump_pmas = false
local dump_config = false
local max_mcycle = 2^61
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
    { "^%-%-rom%-backing%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        rom_image = o
        return true
    end },
    { "^%-%-no%-rom%-bootargs$", function(all)
        if not all then return false end
        bootargs = ""
        return true
    end },
    { "^%-%-append%-rom%-bootargs%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        append_bootargs = o
        return true
    end },
    { "^%-%-ram%-length%=(.+)$", function(n)
        if not n then return false end
        n = assert(parse_number(n), "invalid RAM length " .. n)
        ram_length = n
        return true
    end },
    { "^%-%-ram%-backing%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        ram_image = o
        return true
    end },
    { "^%-%-no%-ram%-image$", function(all)
        if not all then return false end
        ram_image = nil
        return true
    end },
    { "^%-%-htif%-interact$", function(all)
        if not all then return false end
        interact = true
        return true
    end },
    { "^%-i$", function(all)
        if not all then return false end
        interact = true
        return true
    end },
    { "^%-%-htif%-yield$", function(all)
        if not all then return false end
        yield = true
        return true
    end },
    { "^%-%-flash%-(%w+)-backing%=(.+)$", function(d, f)
        if not d or not f then return false end
        if not backing[d] then
            backing_order[#backing_order+1] = d
        end
        backing[d] = f
        return true
    end },
    { "^%-%-flash%-(%w+)-start%=(.+)$", function(d, s)
        if not d or not s then return false end
        start[d] = assert(parse_number(s),
          string.format("invalid start '%s' for flash drive '%s'", s, d))
        return true
    end },
    { "^%-%-flash%-(%w+)-length=(.+)$", function(d, l)
        if not d or not l then return false end
        length[d] = assert(parse_number(l),
          string.format("invalid length '%s' for flash drive '%s'", l, d))
        return true
    end },
    { "^%-%-root%-backing%=(.+)$", function(f)
        if not f then return false end
        local d = "root"
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
    { "^%-%-flash%-(%w+)%-shared$", function(d)
        if not d then return false end
        shared[d] = true
        return true
    end },
    { "^(%-%-max%-mcycle%=(%d+)(.*))$", function(all, n, e)
        if not n then return false end
        assert(e == "", "invalid option " .. all)
        n = assert(parse_number(n), "invalid option " .. all)
        assert(n >= 0, "invalid option " .. all)
        max_mcycle = math.ceil(n)
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

function config_meta.__index:append_drive(t)
    local flash = {
        start = t.start,
        length = t.length,
        backing = t.backing,
        shared = t.shared
    }
    self.flash[self._flash_id] = flash
    self._flash_id = self._flash_id+1
    return self
end

function config_meta.__index:append_bootargs(bootargs)
    if bootargs and bootargs ~= "" then
        self.rom.bootargs = self.rom.bootargs .. " " .. bootargs
    end
    return self
end

function config_meta.__index:set_interact(interact)
    self.htif = self.htif or {}
    self.htif.interact = interact
    return self
end

function config_meta.__index:set_yield(yield)
    self.htif = self.htif or {}
    self.htif.yield = yield
    return self
end

function config_meta.__index:set_ram_length(length)
    self.ram.length = length
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
        processor = {
            mvendorid = cartesi.machine.MVENDORID,
            marchid = cartesi.machine.MARCHID,
            mimpid = cartesi.machine.MIMPID
        },
        ram = {
            length = 64 << 20
        },
        rom = {
            bootargs = bootargs
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

local function print_root_hash(machine)
    print("Updating merkle tree: please wait")
    machine:update_merkle_tree()
    print(hexhash(machine:get_root_hash()))
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

local function dump_machine_config(config)
    stderr("machine_config = {\n")
    stderr("  processor = {\n")
    if config.processor then
        if config.processor.x then
            stderr("    x = {\n")
            for i, xi in ipairs(config.processor.x) do
                stderr("      0x%x,\n", xi)
            end
            stderr("    },\n")
        end
        for i,v in pairs(config.processor) do
            if type(v) == "number" then
                stderr("    %s = 0x%x,\n", i, v)
            end
        end
        stderr("  },\n")
    end
    stderr("  ram = {\n")
    stderr("    length = 0x%x,\n", config.ram.length)
    if config.ram.backing and config.ram.backing ~= "" then
        stderr("    backing = %q,\n", config.ram.backing)
    end
    stderr("  },\n")
    stderr("  rom = {\n")
    if config.rom.backing and config.rom.backing ~= "" then
        stderr("    backing = %q,\n", config.rom.backing)
    end
    if config.rom.bootargs and config.rom.bootargs ~= "" then
        stderr("    bootargs = %q,\n", config.rom.bootargs)
    end
    stderr("  },\n")
    stderr("  htif = {\n")
    stderr("    tohost = 0x%x,\n", config.htif.tohost)
    stderr("    fromhost = 0x%x,\n", config.htif.fromhost)
    stderr("    interact = %s,\n", tostring(config.htif.interact))
    stderr("    yield = %s,\n", tostring(config.htif.yield))
    stderr("  },\n")
    stderr("  clint = {\n")
    stderr("    mtimecmp = 0x%x,\n", config.clint.mtimecmp)
    stderr("  },\n")
    stderr("  flash = {\n")
    for i, f in ipairs(config.flash) do
        stderr("    {\n", i)
        stderr("      start = 0x%x,\n", f.start)
        stderr("      length = 0x%x,\n", f.length)
        if f.backing and f.backing ~= "" then
            stderr("      backing = %q,\n", f.backing)
        end
        stderr("      shared = %s,\n", tostring(f.shared))
        stderr("    },\n")
    end
    stderr("  },\n")
    stderr("}\n")
end

local machine

if load_dir then
    stderr("Loading machine: please wait\n")
    machine = cartesi.machine(load_dir)
else
    -- Resolve all device lengths
    for i, label in ipairs(backing_order) do
        local filename = backing[label]
        local len = get_file_length(filename)
        assert(len, "missing backing file '" .. filename .. "' for device '" .. label .. "'")
        if length[label] then
            assert(len == length[label],
                   "Specified length " .. length[label] .. " for device .. '" .. label ..
                   "', but backing file '" .. filename .. "' has " .. len .. " bytes.")
        else
            length[label] = len
        end
    end

    -- Resolve all device starting positions
    if next(start) == nil then
        -- No positions specified. Generate a starting position for all devices.
        for i, label in ipairs(backing_order) do
            start[label] = flash_base
            -- make sure flash drives are separated by a power of two and at least 1MB
            flash_base = flash_base + (1 << 60)
        end
    else
        -- At least one position specified. Must specify a starting position for all devices.
        for i, label in ipairs(backing_order) do
            if not start[label] then
                error("start position not specified for device '" .. label .. "'")
            end
        end
    end

    local config = new_config(
    ):set_ram_image(
        ram_image
    ):set_rom_image(
        rom_image
    ):set_ram_length(
        ram_length
    )

    local mtdparts = {}
    for i, label in ipairs(backing_order) do
        config = config:append_drive{
            backing = backing[label],
            shared = shared[label],
            start = start[label],
            length = length[label]
        }
        mtdparts[#mtdparts+1] = string.format("flash.%d:-(%s)", i-1, label)
    end
    if #mtdparts > 0 then
        config = config:append_bootargs("mtdparts=" ..
            table.concat(mtdparts, ";"))
    end
    config = config:append_bootargs(
        append_bootargs
    ):set_interact(
        interact
    ):set_yield(
        yield
    )

    stderr("Building machine: please wait\n")
    machine = cartesi.machine(config)
end

if not json_steps then
    if interact then
        stderr("Running in interactive mode!\n")
    end
    if dump_config then
        dump_machine_config(machine:get_initial_config())
    end
    if initial_hash then
        assert(not interact, "hashes are meaningless in interactive mode")
        print_root_hash(machine)
    end
    local cycles = 0
    local payload = 0
    while math.ult(cycles, max_mcycle) do
        machine:run(max_mcycle)
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
    end
    if not math.ult(cycles, max_mcycle) then
        stderr("\nCycles: %u\n", cycles)
    end
    if step then
        assert(not interact, "step proof is meaningless in interactive mode")
        stderr("Gathering step proof: please wait\n")
        print_log(machine:step())
    end
    if dump_pmas then
        machine:dump_pmas()
    end
    if final_hash then
        print_root_hash(machine)
    end
    if store_dir then
        assert(not interact, "hashes are meaningless in interactive mode")
        stderr("Storing machine: please wait\n")
        machine:store(store_dir)
    end
    os.exit(payload, true)
else
    assert(not interact, "logs are meaningless in interactive mode")
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
