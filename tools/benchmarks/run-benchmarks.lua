#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later
--
-- This program is free software: you can redistribute it and/or modify it under
-- the terms of the GNU Lesser General Public License as published by the Free
-- Software Foundation, either version 3 of the License, or (at your option) any
-- later version.
--
-- This program is distributed in the hope that it will be useful, but WITHOUT ANY
-- WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
-- PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
--
-- You should have received a copy of the GNU Lesser General Public License along
-- with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
--

local socket = require("socket")
local cartesi = require("cartesi")

-- Number of times each benchmark is measured
local N_RUNS = 5

local PRINT_STDDEV = true

local MAX_MCYCLE = -1

local function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

local IMAGES_PATH = adjust_images_path(os.getenv("CARTESI_IMAGES_PATH"))
print("IMAGES_PATH = " .. IMAGES_PATH)

local benchmarks = {
    {
        name = "boot",
        exec_format = "exit %s",
        params = { 0 },
    },
    {
        name = "dhrystone",
        exec_format = "echo %d | /usr/bin/dhrystone",
        params = { 100000, 500000, 1000000 },
    },
    {
        name = "whetstone",
        exec_format = "/usr/bin/whetstone %d",
        params = { 100, 250, 500 },
    },
    {
        name = "tinymembench",
        exec_format = "/usr/bin/tinymembench",
        params = {},
    },
    {
        name = "ramspeed",
        exec_format = "/usr/bin/ramspeed -b %d -g 1",
        params = { 1, 2, 3, 4, 5, 6 },
    },
    {
        name = "iozone",
        exec_format = "/usr/bin/iozone -a -s 65536 -r %d",
        params = { 64, 512, 2048 },
    },
    {
        name = "dieharder",
        exec_format = "/usr/bin/dieharder -d %d",
        params = { 0, 1, 2 },
    },
    {
        name = "bonnie++",
        exec_format = "/usr/sbin/bonnie++ -d $(mktemp -d) -u root",
        params = { 0, 1, 2 },
    },
}

local function build_machine(exec_args)
    local ram_image_filename = IMAGES_PATH .. "linux.bin"
    local flash_image_filename = IMAGES_PATH .. "rootfs.ext2"

    local config = {
        processor = {
            -- Request automatic default values for versioning CSRs
            mimpid = -1,
            marchid = -1,
            mvendorid = -1,
        },
        dtb = {
            bootargs = (
                "console=hvc0 rootfstype=ext2 root=/dev/pmem0 rw quiet -- " .. exec_args
            ),
        },
        ram = {
            image_filename = ram_image_filename,
            length = 64 << 20,
        },
        flash_drive = {
            {
                start = 0x80000000000000,
                length = 0x40000000,
                image_filename = flash_image_filename,
            },
        },
    }

    return cartesi.machine(config)
end

local function measure(exec_args)
    local results = {}
    for _ = 1, N_RUNS do
        local machine <close> = build_machine(exec_args)
        local start = socket.gettime()
        repeat
            machine:run(MAX_MCYCLE)
        until machine:read_iflags_H() or machine:read_mcycle() < MAX_MCYCLE
        local elapsed = socket.gettime() - start
        table.insert(results, elapsed)
    end
    return results
end

local function measure_all()
    local results = {}
    for _, benchmark in ipairs(benchmarks) do
        for _, param in ipairs(benchmark.params) do
            local exec_args = string.format(benchmark.exec_format, param)
            local times = measure(exec_args)
            table.insert(results, {
                name = benchmark.name,
                param = param,
                times = times,
            })
        end
    end
    return results
end

local function average(arr)
    local avg = 0.0
    for _, value in ipairs(arr) do
        avg = avg + value
    end
    return avg / #arr
end

local function stddev(arr)
    local std2 = 0.0
    local avg = average(arr)
    for _, value in ipairs(arr) do
        std2 = std2 + (value - avg) ^ 2
    end
    return math.sqrt(std2 / #arr)
end

local function print_results(results)
    for _, result in ipairs(results) do
        local label = result.name .. "[" .. result.param .. "]"
        io.write("|")
        io.write(string.format("%-24s", label))
        io.write("|")
        io.write(string.format("%7.3f", average(result.times)))
        if PRINT_STDDEV then io.write(string.format(" +-%.3f", stddev(result.times))) end
        io.write("|\n")
    end
end

print_results(measure_all())
