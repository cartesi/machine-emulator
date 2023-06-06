#!/usr/bin/env lua5.4

-- Copyright 2023 Cartesi Pte. Ltd.
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

local fs = {}

function fs.adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

function fs.remove_files(filenames)
    for _, filename in pairs(filenames) do
        os.remove(filename)
    end
end

function fs.read_file(filename)
    local file = assert(io.open(filename, "rb"))
    if not file then return nil end
    local contents = file:read("*a")
    file:close()
    return contents
end

function fs.get_file_length(filename)
    local file = io.open(filename, "rb")
    if not file then return nil end
    local size = file:seek("end")
    file:close()
    return size
end

fs.images_path = fs.adjust_images_path(os.getenv("CARTESI_IMAGES_PATH"))
fs.tests_path = fs.adjust_images_path(os.getenv("CARTESI_TESTS_PATH"))
fs.rom_image = fs.images_path .. "rom.bin"
fs.linux_image = fs.images_path .. "linux.bin"
fs.rootfs_image = fs.images_path .. "rootfs.ext2"
fs.uarch_ram_image = fs.images_path .. "uarch-ram.bin"

return fs
