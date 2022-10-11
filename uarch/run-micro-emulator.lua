#!/usr/bin/env lua5.3

-- This is a test script
-- Don't bother reviewing it

local cartesi = require "cartesi"
local util = require"cartesi.util"

if  #arg ~= 3 then
  io.stderr:write(string.format([=[
Usage:

  %s <micro-rom-image-filename> <rom-image-filename> <ram-image-filename>

where:

  <micro-rom-image-filename>
  name of file containing the image of microemulator ROM

  <rom-image-filename>
  name of file containing the image of emulator ROM
  
  <ram-image-filename>
  name of file containing the image of emulator RAM

  ]=], arg[0]))
  os.exit(1)
end

local PMA_URAM_START_DEF = 0x70000000
local PMA_URAM_LENGTH_DEF = 0x5001000
local micro_rom_file = arg[1]
local rom_file = arg[2]
local ram_file = arg[3]
local urom_length = 0x4002000
local uram_length = PMA_URAM_LENGTH_DEF
local ram_length = 0x4003000

-- build cartesi machine configuration
local runtime = {}
local config = {
  uarch ={
    rom = {
      image_filename = micro_rom_file,
      length = urom_length      
    },
    ram = {
      length = uram_length
    }
  },
  processor = {
  },
  rom = { 
    image_filename = rom_file,
    bootargs = "console=hvc0 rootfstype=ext2 root=/dev/mtdblock0 rw quiet swiotlb=noforce -- echo opa",
  },
  ram = { 
    image_filename = ram_file,
    length = ram_length
  }  
}
local function new_machine()
  return assert(cartesi.machine(config, runtime))  
end

print(os.date())
machine = new_machine()
ucycle_end = -1
machine:uarch_run(ucycle_end);
--machine:dump_regs()

