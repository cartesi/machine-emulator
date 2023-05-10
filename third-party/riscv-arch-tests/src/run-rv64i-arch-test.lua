#!/usr/bin/env lua5.4

-- Copyright 2019-2021 Cartesi Pte. Ltd.
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

local cartesi = require "cartesi"

if  #arg ~= 2 then
  io.stderr:write(string.format([=[
Usage:

  %s <uarch-ram-image> <output-signature-file>

where:
  <uarch-ram-image>
  name of file containing the image of microemulator RAM.

  <output-signature-file>
  name of file to write test signature results
  ]=], arg[0]))
  os.exit(1)
end

local uarch_ram_image_filename = arg[1]
local output_signature_file = arg[2]
local uarch_ram_start = 0x70000000
local uarch_ram_length = 0x1000000
local dummy_rom_filename = os.tmpname()
io.open(dummy_rom_filename, 'w'):close()
local deleter = {}
setmetatable(deleter, { __gc = function() os.remove(dummy_rom_filename) end } )

local config = {
  uarch ={
    ram = {
      image_filename = uarch_ram_image_filename,
      length = uarch_ram_length
    },
  },
  processor = {},
  rom = { image_filename = dummy_rom_filename },
  ram = { length = 0x1000 }
}

local machine = assert(cartesi.machine(config))

-- run microarchitecture
machine:run_uarch()

-- extract test result signature from microarchitecture RAM
local mem = machine:read_memory(uarch_ram_start, uarch_ram_length)
local s1, e1 = string.find(mem, "BEGIN_CTSI_SIGNATURE____")
local s2, e2 = string.find(mem, "END_CTSI_SIGNATURE______")
local sig = string.sub(mem, e1+1, s2-1)

-- write signature to file, in the format expected by the arch test script
local fd = io.open(output_signature_file, "w")
for i=1, #sig, 4 do
  local w = string.reverse(string.sub(sig, i, i+3))
  for j=1,4,1 do
    local b = string.byte(string.sub(w, j))
    fd:write(string.format("%02x", b))
  end
  fd:write("\n")
end

-- pad fill output file
if (#sig % 16) ~= 0 then
  fd:write("00000000\n00000000\n")
end

fd:close()
