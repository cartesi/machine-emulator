#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0

--[[
Writes uarch-pristine-ram.c and uarch-pristine-hash.c for a custom pristine uarch image, in the format
that the uarch build generates for the stock image, so src/Makefile custom-uarch-pristine-cartesi.so
can embed it.

Usage: custom-uarch-pristine-sources.lua <uarch-image> <output-dir>
]]

local cartesi = require("cartesi")
local filesystem = require("cartesi.filesystem")

local image_path, output_dir = ...
assert(image_path and output_dir, "usage: custom-uarch-pristine-sources.lua <uarch-image> <output-dir>")

local image = filesystem.read_file(image_path)

-- The pristine hash covers the uarch state of a machine whose uarch RAM holds the image
local machine <close> = cartesi.machine({
    ram = { length = 4096 },
    uarch = { ram = { backing_store = { data_filename = image_path } } },
})
local hash = machine:get_node_hash(cartesi.UARCH_STATE_START_ADDRESS, cartesi.UARCH_STATE_LOG2_SIZE)

local function c_bytes(data)
    local lines = {}
    for i = 1, #data, 12 do
        local line = {}
        for j = i, math.min(i + 11, #data) do
            line[#line + 1] = string.format("0x%02x", data:byte(j))
        end
        lines[#lines + 1] = "  " .. table.concat(line, ", ")
    end
    return table.concat(lines, ",\n")
end

filesystem.write_file(
    table.concat({
        "// This file is auto-generated and should not be modified",
        "#include <stddef.h>",
        "unsigned char uarch_pristine_ram[] = {",
        c_bytes(image),
        "};",
        string.format("unsigned int uarch_pristine_ram_len = %d;", #image),
        "",
    }, "\n"),
    output_dir .. "/uarch-pristine-ram.c"
)

filesystem.write_file(
    table.concat({
        "// This file is auto-generated and should not be modified",
        "const unsigned char uarch_pristine_hash[] = {",
        c_bytes(hash),
        "};",
        string.format("const unsigned int uarch_pristine_hash_len = %d;", #hash),
        "",
    }, "\n"),
    output_dir .. "/uarch-pristine-hash.c"
)
