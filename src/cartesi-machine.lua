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

-- Print help and exit
local function help()
    stderr([=[
Usage:

  %s [options]

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

  --<label>-start=<num|expr>   set the starting memory position for <label>
                               filesystem to a number or a Lua expression
                               (if you set the position for one filesystem,
                               you must set it for all of them)

  --<label>-length=<num|expr>  set the byte length of the <label> filesystem

  --max-mcycle=<number>        stop at a given mcycle
                               (default: 2305843009213693952)

  --step                       run a step after stopping

  --cmdline                    pass additional command-line arguments to kernel

  --batch                      run in non-interactive mode

  --yield                      honor yield requests by target

  --initial-hash               prints initial hash before running

  --final-hash                 prints final hash after running

  --ignore-payload             do not report error on non-zero payload

  --dump                       dump non-pristine pages to disk

  --dump-config                dump machine config to screen

  --json-steps=<filename>      output json file with steps
                               (default: none)

  --load=<directory>           load prebuilt machine from directory

  --store=<directory>          store machine to directory


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
local cmdline = ""
local memory_size = 64
local batch = false
local yield = false
local initial_hash = false
local final_hash = false
local ignore_payload = false
local dump = false
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
    { "^%-%-batch$", function(all)
        if not all then return false end
        batch = true
        return true
    end },
    { "^%-%-yield$", function(all)
        if not all then return false end
        yield = true
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
    { "^%-%-(%w+)-start%=(.+)$", function(d, f)
        if not d or not f then return false end
        local fun = load("return " .. f) -- expr|num string to num
        start[d] = fun and fun()
        assert(start[d], "invalid start position '" .. f ..
               "' for device '" .. d .. "'")
        return true
    end },
    { "^%-%-(%w+)-length=(.+)$", function(d, f)
        if not d or not f then return false end
        local fun = load("return " .. f) -- expr|num string to num
        length[d] = fun and fun()
        assert(length[d] and length[d] > 0,
               "invalid length '" .. f ..
               "' for device '" .. d .. "'")
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
    { "^%-%-dump%-config$", function(all)
        if not all then return false end
        dump_config = true
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

function config_meta.__index:append_cmdline(cmdline)
    if cmdline and cmdline ~= "" then
        self.rom.bootargs = self.rom.bootargs .. " " .. cmdline
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
        processor = {
            mvendorid = cartesi.machine.MVENDORID,
            marchid = cartesi.machine.MARCHID,
            mimpid = cartesi.machine.MIMPID
        },
        ram = {
            length = 64 << 20
        },
        rom = {
            bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw",
        },
        htif = {
            interact = true,
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
    stderr("config = {\n")
    stderr("  processor = {\n")
    stderr("    x = {\n")
    for i, xi in ipairs(config.processor.x) do
        stderr("      0x%x,\n", xi)
    end
    stderr("    },\n")
    for i,v in pairs(config.processor) do
        if type(v) == "number" then
            stderr("    %s = 0x%x,\n", i, v)
        end
    end
    stderr("  },\n")
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
    stderr("  },\n")
    stderr("  clint = {\n")
    stderr("    mtimecmp = 0x%x,\n", config.clint.mtimecmp)
    stderr("  },\n")
    stderr("  flash = {\n")
    for i, f in ipairs(config.flash) do
        stderr("    [%d] = {\n", i)
        stderr("      start = 0x%x,\n", f.start)
        stderr("      length = 0x%x,\n", f.length)
        if f.backing and f.backing ~= "" then
            stderr("      backing = %q,\n", f.backing)
        end
        if f.shared then
            stderr("      shared = true,\n", f.backing)
        end
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
            flash_base = flash_base + math.max(next_power_of_2(length[label]), 1024*1024)
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
    ):set_memory_size(
        memory_size
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

    config = config:append_cmdline(
        "mtdparts=" .. table.concat(mtdparts, ";")
    ):append_cmdline(
        cmdline
    ):set_interact(
        not batch
    ):set_yield(
        yield
    )

    stderr("Building machine: please wait\n")
    machine = cartesi.machine(config)
end

if not json_steps then
    if dump then
        machine:dump()
    end
    if dump_config then
        dump_machine_config(machine:get_initial_config())
    end
    if initial_hash then
        print_root_hash(machine)
    end
    local cycles = 0
    while cycles < max_mcycle do
        machine:run(max_mcycle)
        cycles = machine:read_mcycle()
        if machine:read_iflags_H() then
            local payload = machine:read_htif_tohost() << 16 >> 17
            stderr("\nHalted with payload: %u\n", payload)
            stderr("Cycles: %u\n", cycles)
            break
        elseif machine:read_iflags_Y() then
            local tohost = machine:read_htif_tohost()
            local cmd = tohost << 8 >> 56
            local data = tohost << 16 >> 16
            if cmd == 0 then
                stderr("Progress: %u\n", data)
            else
                stderr("\nYielded cmd: %u, data: %u\n", cmd, data)
                stderr("Cycles: %u\n", cycles)
            end
        end
    end
    if step then
        stderr("Gathering step proof: please wait\n")
        print_log(machine:step())
    end
    if final_hash then
        print_root_hash(machine)
    end
    if store_dir then
        stderr("Storing machine: please wait\n")
        machine:store(store_dir)
    end
    os.exit(payload, true)
else
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
