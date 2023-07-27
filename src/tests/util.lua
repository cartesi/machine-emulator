#!/usr/bin/env lua5.4

-- Copyright 2021 Cartesi Pte. Ltd.
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

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

local test_util = {
    images_path = adjust_images_path(os.getenv("CARTESI_IMAGES_PATH")),
    tests_path = adjust_images_path(os.getenv("CARTESI_TESTS_PATH")),
}

function test_util.create_test_uarch_program()
    local file_path = os.tmpname()
    local f = io.open(file_path, "wb")
    f:write(string.pack("I4", 0x07b00513)) --   li	a0,123
    f:write(string.pack("I4", 0x32800293)) --   li t0, UARCH_HALT_FLAG_SHADDOW_ADDR_DEF (0x328)
    f:write(string.pack("I4", 0x00100313)) --   li	t1,1           UARCH_MMIO_HALT_VALUE_DEF
    f:write(string.pack("I4", 0x0062b023)) --   sd	t1,0(t0)       Halt uarch
    f:close()
    return file_path
end

function test_util.make_do_test(build_machine, type, config)
    return function(description, f)
        io.write("  " .. description .. "...\n")
        local machine <close> = build_machine(type, config)
        f(machine)
        print("<<<<<<<<<<<<<<<< passed >>>>>>>>>>>>>>>")
    end
end

function test_util.disabled_test(description) print("Disabled test - " .. description) end

function test_util.file_exists(name)
    local f = io.open(name, "r")
    if f ~= nil then
        io.close(f)
        return true
    else
        return false
    end
end

function test_util.fromhex(str)
    return (str:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

function test_util.tohex(str)
    return (str:gsub(".", function(c) return string.format("%02X", string.byte(c)) end))
end

function test_util.split_string(inputstr, sep)
    if sep == nil then sep = "%s" end
    local t = {}
    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end
    return t
end

function test_util.align(v, el) return (v >> el << el) end

return test_util
