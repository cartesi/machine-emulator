#!/usr/bin/env lua5.4

-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: Apache-2.0
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--

-- Step log utility for Cartesi Machine RISC0 workflows.
--
-- Reads and analyzes step log binary files. Supports both header-only
-- extraction (for Makefile pipelines) and full structural analysis
-- (for investigating step log sizes and page access patterns).
--
-- Usage:
--   step-log-util.lua info <step-log>              Human-readable header
--   step-log-util.lua stats <step-log>             Full statistics (pages, siblings, sizes)
--   step-log-util.lua stats <step-log> ...         Stats for multiple files
--   step-log-util.lua batch-stats <dir>             Stats for all step logs in a directory
--   step-log-util.lua pages <step-log>             List page indices and addresses
--   step-log-util.lua root-hash-before <step-log>  Hex hash (no newline)
--   step-log-util.lua mcycle-count <step-log>       Decimal (no newline)
--   step-log-util.lua root-hash-after <step-log>   Hex hash (no newline)
--   step-log-util.lua hex-encode <string>           Hex-encode (no newline)

local cartesi = require("cartesi")
local util = require("cartesi.util")

local HASH_SIZE = cartesi.HASH_SIZE
local PAGE_LOG2_SIZE = cartesi.HASH_TREE_LOG2_PAGE_SIZE
local PAGE_DATA_SIZE = 1 << PAGE_LOG2_SIZE
local HEADER_SIZE = 72 -- root_hash_before(32) + mcycle_count(8) + root_hash_after(32)
local METADATA_SIZE = 16 -- hash_function(8) + page_count(8)
local PAGE_ENTRY_SIZE = 8 + PAGE_DATA_SIZE + HASH_SIZE -- page_index(8) + data(4096) + scratch(32)

local REGIONS = {
    { name = "shadow_regs",  start = 0x0,                                    length = 0x1000 },
    { name = "shadow_tlb",   start = cartesi.AR_SHADOW_TLB_START,            length = cartesi.AR_SHADOW_TLB_LENGTH },
    { name = "shadow_pma",   start = 0x10000,                                length = 0x1000 },
    { name = "shadow_uarch", start = cartesi.UARCH_SHADOW_START_ADDRESS,     length = cartesi.UARCH_SHADOW_LENGTH },
    { name = "uarch_ram",    start = cartesi.UARCH_RAM_START_ADDRESS,        length = cartesi.UARCH_RAM_LENGTH },
    { name = "clint",        start = 0x2000000,                              length = 0xC0000 },
    { name = "htif",         start = 0x40008000,                             length = 0x1000 },
    { name = "plic",         start = 0x40100000,                             length = 0x400000 },
    { name = "cmio_rx",      start = cartesi.AR_CMIO_RX_BUFFER_START,       length = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE },
    { name = "cmio_tx",      start = cartesi.AR_CMIO_TX_BUFFER_START,       length = 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE },
    { name = "dtb",          start = 0x7FF00000,                             length = 0x100000 },
    { name = "ram",          start = cartesi.AR_RAM_START,                   length = 0x100000000 }, -- 4 GB max
    { name = "flash",        start = 0x80000000000000,                       length = 0x100000000000000 },
}

local hexstring = util.hexstring

local function classify_address(addr)
    for _, r in ipairs(REGIONS) do
        if addr >= r.start and addr < r.start + r.length then
            return r.name
        end
    end
    return "unknown"
end

local function format_size(bytes)
    if bytes < 1024 then
        return string.format("%d B", bytes)
    elseif bytes < 1024 * 1024 then
        return string.format("%.1f KB", bytes / 1024)
    else
        return string.format("%.1f MB", bytes / (1024 * 1024))
    end
end

local function read_header(path)
    local f, err = io.open(path, "rb")
    if not f then
        io.stderr:write("error: " .. err .. "\n")
        os.exit(1)
    end
    local data = f:read(HEADER_SIZE)
    f:close()
    if not data or #data < HEADER_SIZE then
        io.stderr:write(string.format("error: step log too small (got %d bytes, need %d)\n",
            data and #data or 0, HEADER_SIZE))
        os.exit(1)
    end
    local root_hash_before = hexstring(data:sub(1, 32))
    local mcycle_count = string.unpack("<I8", data, 33)
    local root_hash_after = hexstring(data:sub(41, 72))
    return root_hash_before, mcycle_count, root_hash_after
end

local function read_full(path)
    local f, err = io.open(path, "rb")
    if not f then
        io.stderr:write("error: " .. err .. "\n")
        os.exit(1)
    end
    local file_size = f:seek("end")
    f:seek("set", 0)

    local header_data = f:read(HEADER_SIZE)
    if not header_data or #header_data < HEADER_SIZE then
        f:close()
        io.stderr:write(string.format("error: step log too small (got %d bytes, need %d)\n",
            header_data and #header_data or 0, HEADER_SIZE))
        os.exit(1)
    end
    local root_hash_before = hexstring(header_data:sub(1, 32))
    local mcycle_count = string.unpack("<I8", header_data, 33)
    local root_hash_after = hexstring(header_data:sub(41, 72))

    local meta_data = f:read(METADATA_SIZE)
    if not meta_data or #meta_data < METADATA_SIZE then
        f:close()
        io.stderr:write("error: step log missing metadata\n")
        os.exit(1)
    end
    local hash_function = string.unpack("<I8", meta_data, 1)
    local page_count = string.unpack("<I8", meta_data, 9)

    local page_indices = {}
    for i = 1, page_count do
        local idx_data = f:read(8)
        if not idx_data or #idx_data < 8 then
            f:close()
            io.stderr:write(string.format("error: step log truncated at page %d/%d\n", i, page_count))
            os.exit(1)
        end
        local page_index = string.unpack("<I8", idx_data)
        page_indices[i] = page_index
        f:seek("cur", PAGE_DATA_SIZE + HASH_SIZE)
    end

    local sc_data = f:read(8)
    local sibling_count = 0
    if sc_data and #sc_data == 8 then
        sibling_count = string.unpack("<I8", sc_data)
    end

    f:close()

    local header_bytes = HEADER_SIZE + METADATA_SIZE
    local pages_bytes = page_count * PAGE_ENTRY_SIZE
    local siblings_bytes = 8 + sibling_count * HASH_SIZE

    return {
        path = path,
        file_size = file_size,
        root_hash_before = root_hash_before,
        mcycle_count = mcycle_count,
        root_hash_after = root_hash_after,
        hash_function = hash_function,
        page_count = page_count,
        page_indices = page_indices,
        sibling_count = sibling_count,
        header_bytes = header_bytes,
        pages_bytes = pages_bytes,
        siblings_bytes = siblings_bytes,
    }
end

local commands = {}

local HASH_FUNCTION_NAMES = { [0] = "keccak256", [1] = "sha256" }

local function print_stats(info)
    local hash_fn_name = HASH_FUNCTION_NAMES[info.hash_function] or ("unknown(" .. info.hash_function .. ")")
    print(string.format("Step log: %s", info.path))
    print(string.format("  root_hash_before: %s", info.root_hash_before))
    print(string.format("  mcycle_count:     %d", info.mcycle_count))
    print(string.format("  root_hash_after:  %s", info.root_hash_after))
    print(string.format("  hash_function:    %s", hash_fn_name))
    print(string.format("  page_count:       %d", info.page_count))
    print(string.format("  sibling_count:    %d", info.sibling_count))
    print(string.format("  file_size:        %s (%d bytes)", format_size(info.file_size), info.file_size))
    print(string.format("  breakdown:        header=%s  pages=%s  siblings=%s",
        format_size(info.header_bytes), format_size(info.pages_bytes), format_size(info.siblings_bytes)))
    local region_counts = {}
    for _, idx in ipairs(info.page_indices) do
        local addr = idx << PAGE_LOG2_SIZE
        local region = classify_address(addr)
        region_counts[region] = (region_counts[region] or 0) + 1
    end
    local region_list = {}
    for name, count in pairs(region_counts) do
        region_list[#region_list + 1] = { name = name, count = count }
    end
    table.sort(region_list, function(a, b) return a.count > b.count end)
    local parts = {}
    for _, r in ipairs(region_list) do
        parts[#parts + 1] = string.format("%s=%d", r.name, r.count)
    end
    print(string.format("  page_regions:     %s", table.concat(parts, "  ")))
end

local function print_stats_row(info)
    print(string.format("%-12d %-6d %-8d %-12s %s",
        info.mcycle_count, info.page_count, info.sibling_count,
        format_size(info.file_size), info.path))
end

function commands.info(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua info <step-log>\n")
        os.exit(1)
    end
    local hash_before, mcycle, hash_after = read_header(path)
    print("Step log: " .. path)
    print("  root_hash_before: " .. hash_before)
    print("  mcycle_count:     " .. mcycle)
    print("  root_hash_after:  " .. hash_after)
end

commands["root-hash-before"] = function(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua root-hash-before <step-log>\n")
        os.exit(1)
    end
    local hash_before = read_header(path)
    io.write(hash_before)
end

commands["mcycle-count"] = function(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua mcycle-count <step-log>\n")
        os.exit(1)
    end
    local _, mcycle = read_header(path)
    io.write(tostring(mcycle))
end

commands["root-hash-after"] = function(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua root-hash-after <step-log>\n")
        os.exit(1)
    end
    local _, _, hash_after = read_header(path)
    io.write(hash_after)
end

function commands.stats(args)
    if #args == 0 then
        io.stderr:write("usage: step-log-util.lua stats <step-log> [step-log ...]\n")
        os.exit(1)
    end
    for i, path in ipairs(args) do
        local info = read_full(path)
        print_stats(info)
        if i < #args then print() end
    end
end

commands["batch-stats"] = function(args)
    local dir = args[1]
    if not dir then
        io.stderr:write("usage: step-log-util.lua batch-stats <dir>\n")
        os.exit(1)
    end
    local files = {}
    local pipe = io.popen(string.format('ls -1 "%s"/*.log 2>/dev/null', dir))
    if pipe then
        for line in pipe:lines() do
            files[#files + 1] = line
        end
        pipe:close()
    end
    if #files == 0 then
        io.stderr:write("error: no .log files found in " .. dir .. "\n")
        os.exit(1)
    end
    table.sort(files)

    print(string.format("%-12s %-6s %-8s %-12s %s", "mcycles", "pages", "siblings", "size", "path"))
    print(string.rep("-", 80))

    local total_pages, total_siblings, total_size = 0, 0, 0
    local max_pages, max_siblings, max_size = 0, 0, 0
    local max_pages_file, max_siblings_file, max_size_file = "", "", ""

    for _, path in ipairs(files) do
        local ok, info = pcall(read_full, path)
        if ok then
            print_stats_row(info)
            total_pages = total_pages + info.page_count
            total_siblings = total_siblings + info.sibling_count
            total_size = total_size + info.file_size
            if info.page_count > max_pages then
                max_pages = info.page_count
                max_pages_file = path
            end
            if info.sibling_count > max_siblings then
                max_siblings = info.sibling_count
                max_siblings_file = path
            end
            if info.file_size > max_size then
                max_size = info.file_size
                max_size_file = path
            end
        else
            io.stderr:write(string.format("warning: skipping %s: %s\n", path, tostring(info)))
        end
    end

    print(string.rep("-", 80))
    print(string.format("Files: %d", #files))
    print(string.format("Avg pages: %.1f   Avg siblings: %.1f   Avg size: %s",
        total_pages / #files, total_siblings / #files, format_size(total_size // #files)))
    print(string.format("Max pages: %d (%s)", max_pages, max_pages_file))
    print(string.format("Max siblings: %d (%s)", max_siblings, max_siblings_file))
    print(string.format("Max size: %s (%s)", format_size(max_size), max_size_file))
end

function commands.pages(args)
    local path = args[1]
    if not path then
        io.stderr:write("usage: step-log-util.lua pages <step-log>\n")
        os.exit(1)
    end
    local info = read_full(path)
    print(string.format("%-8s %-18s %s", "index", "address", "region"))
    print(string.rep("-", 50))
    for _, idx in ipairs(info.page_indices) do
        local addr = idx << PAGE_LOG2_SIZE
        local region = classify_address(addr)
        print(string.format("%-8d 0x%016x %s", idx, addr, region))
    end
end

commands["hex-encode"] = function(args)
    local s = args[1]
    if not s then
        io.stderr:write("usage: step-log-util.lua hex-encode <string>\n")
        os.exit(1)
    end
    io.write(hexstring(s))
end

local cmd_name = arg[1]
if not cmd_name or not commands[cmd_name] then
    io.stderr:write("usage: step-log-util.lua <command> [args...]\n")
    io.stderr:write("\nCommands:\n")
    io.stderr:write("  info <step-log>              Print step log header fields\n")
    io.stderr:write("  stats <step-log> [...]       Full statistics (pages, siblings, sizes)\n")
    io.stderr:write("  batch-stats <dir>            Stats table for all .log files in a directory\n")
    io.stderr:write("  pages <step-log>             List page indices, addresses, and regions\n")
    io.stderr:write("  root-hash-before <step-log>  Print root hash before (hex)\n")
    io.stderr:write("  mcycle-count <step-log>       Print mcycle count (decimal)\n")
    io.stderr:write("  root-hash-after <step-log>   Print root hash after (hex)\n")
    io.stderr:write("  hex-encode <string>           Hex-encode a string\n")
    os.exit(1)
end

local cmd_args = {}
for i = 2, #arg do
    cmd_args[i - 1] = arg[i]
end

commands[cmd_name](cmd_args)
