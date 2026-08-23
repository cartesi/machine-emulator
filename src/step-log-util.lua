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

local cartesi
local cartesi_util
do
    local ok, mod = pcall(require, "cartesi")
    if ok then cartesi = mod end
    local ok_u, util = pcall(require, "cartesi.util")
    if ok_u then cartesi_util = util end
end

local HASH_SIZE = cartesi and cartesi.HASH_SIZE or 32
local PAGE_LOG2_SIZE = cartesi and cartesi.HASH_TREE_LOG2_PAGE_SIZE or 12
local PAGE_DATA_SIZE = 1 << PAGE_LOG2_SIZE
local STEP_LOG_SIGNATURE = cartesi and cartesi.STEP_LOG_SIGNATURE or "CTSI\x03\x00\x00\x00"
local SIGNATURE_SIZE = #STEP_LOG_SIGNATURE

-- step_log_header layout (see src/step-log.hpp):
--   signature(8) + root_hash_before(32) + requested_cycle_count(8) + root_hash_after(32)
--   + hash_function(8) + page_count(8) + node_count(8) + sibling_count(8)
local HEADER_SIZE = SIGNATURE_SIZE + 2 * HASH_SIZE + 5 * 8
local PAGE_ENTRY_SIZE = 8 + PAGE_DATA_SIZE + HASH_SIZE
local NODE_ENTRY_SIZE = 8 + 8 + 2 * HASH_SIZE
local SIBLING_SIZE = HASH_SIZE

local HASH_FUNCTION_NAMES = {
    [cartesi and cartesi.HASH_FUNCTION_KECCAK256 or 0] = "keccak256",
    [cartesi and cartesi.HASH_FUNCTION_SHA256 or 1] = "sha256",
}

local hexstring = (cartesi_util and cartesi_util.hexstring)
    or function(s)
        return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
    end

local REGIONS
if cartesi then
    REGIONS = {
        { name = "shadow_state", start = cartesi.AR_SHADOW_STATE_START, length = cartesi.AR_SHADOW_STATE_LENGTH },
        { name = "shadow_tlb", start = cartesi.AR_SHADOW_TLB_START, length = cartesi.AR_SHADOW_TLB_LENGTH },
        { name = "shadow_pmas", start = cartesi.AR_PMAS_START, length = cartesi.AR_PMAS_LENGTH },
        { name = "shadow_uarch", start = cartesi.UARCH_SHADOW_START_ADDRESS, length = cartesi.UARCH_SHADOW_LENGTH },
        { name = "uarch_ram", start = cartesi.UARCH_RAM_START_ADDRESS, length = cartesi.UARCH_RAM_LENGTH },
        {
            name = "cmio_rx",
            start = cartesi.AR_CMIO_RX_BUFFER_START,
            length = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE,
        },
        {
            name = "cmio_tx",
            start = cartesi.AR_CMIO_TX_BUFFER_START,
            length = 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE,
        },
        { name = "dtb", start = cartesi.AR_DTB_START, length = cartesi.AR_DTB_LENGTH },
        { name = "ram", start = cartesi.AR_RAM_START, length = 0x100000000 },
    }
end

local function classify_address(addr)
    if not REGIONS then return "unknown" end
    for _, r in ipairs(REGIONS) do
        if addr >= r.start and addr < r.start + r.length then return r.name end
    end
    -- Flash drives are placed past RAM, so anything above the RAM window that
    -- matched no device region is drive-backed memory.
    if addr >= cartesi.AR_RAM_START then return "flash" end
    return "unknown"
end

local function format_size(bytes)
    if bytes < 1024 then return string.format("%d B", bytes) end
    if bytes < 1024 * 1024 then return string.format("%.1f KB", bytes / 1024) end
    return string.format("%.1f MB", bytes / (1024 * 1024))
end

local function hash_function_name(code) return HASH_FUNCTION_NAMES[code] or string.format("unknown(%d)", code) end

local function parse_header(data)
    assert(#data >= HEADER_SIZE, string.format("step log header too small (got %d bytes, need %d)", #data, HEADER_SIZE))
    assert(data:sub(1, SIGNATURE_SIZE) == STEP_LOG_SIGNATURE, "invalid step log signature")
    local off = SIGNATURE_SIZE + 1
    local hdr = {}
    hdr.root_hash_before = data:sub(off, off + HASH_SIZE - 1)
    off = off + HASH_SIZE
    hdr.requested_cycle_count = string.unpack("<I8", data, off)
    off = off + 8
    hdr.root_hash_after = data:sub(off, off + HASH_SIZE - 1)
    off = off + HASH_SIZE
    hdr.hash_function = string.unpack("<I8", data, off)
    off = off + 8
    hdr.page_count = string.unpack("<I8", data, off)
    off = off + 8
    hdr.node_count = string.unpack("<I8", data, off)
    off = off + 8
    hdr.sibling_count = string.unpack("<I8", data, off)
    return hdr
end

local function read_header(path)
    local f <close> = assert(io.open(path, "rb"))
    local data = f:read(HEADER_SIZE)
    assert(data, "step log is empty: " .. path)
    local hdr = parse_header(data)
    hdr.path = path
    return hdr
end

-- Reads page indices but skips page bodies + scratch hashes to keep memory bounded.
local function read_full(path)
    local f <close> = assert(io.open(path, "rb"))
    local file_size = assert(f:seek("end"))
    f:seek("set", 0)

    local hdr_bytes = f:read(HEADER_SIZE)
    assert(hdr_bytes, "step log is empty: " .. path)
    local info = parse_header(hdr_bytes)
    info.path = path
    info.file_size = file_size

    info.page_indices = {}
    for i = 1, info.page_count do
        local idx_bytes = f:read(8)
        assert(idx_bytes and #idx_bytes == 8, string.format("step log truncated at page %d/%d", i, info.page_count))
        info.page_indices[i] = string.unpack("<I8", idx_bytes)
        f:seek("cur", PAGE_DATA_SIZE + HASH_SIZE)
    end

    info.nodes = {}
    for i = 1, info.node_count do
        local node_bytes = f:read(NODE_ENTRY_SIZE)
        assert(
            node_bytes and #node_bytes == NODE_ENTRY_SIZE,
            string.format("step log truncated at node %d/%d", i, info.node_count)
        )
        info.nodes[i] = {
            address = string.unpack("<I8", node_bytes, 1),
            log2_size = string.unpack("<I8", node_bytes, 9),
            hash_before = node_bytes:sub(17, 17 + HASH_SIZE - 1),
            hash_after = node_bytes:sub(17 + HASH_SIZE, 17 + 2 * HASH_SIZE - 1),
        }
    end

    info.header_bytes = HEADER_SIZE
    info.pages_bytes = info.page_count * PAGE_ENTRY_SIZE
    info.nodes_bytes = info.node_count * NODE_ENTRY_SIZE
    info.siblings_bytes = info.sibling_count * SIBLING_SIZE
    return info
end

local function print_header(info)
    print("Step log: " .. info.path)
    print("  root_hash_before: " .. hexstring(info.root_hash_before))
    print("  requested_cycle_count: " .. info.requested_cycle_count)
    print("  root_hash_after:  " .. hexstring(info.root_hash_after))
    print("  hash_function:    " .. hash_function_name(info.hash_function))
    print("  page_count:       " .. info.page_count)
    print("  node_count:       " .. info.node_count)
    print("  sibling_count:    " .. info.sibling_count)
end

local function print_stats(info)
    print_header(info)
    print(string.format("  file_size:        %s (%d bytes)", format_size(info.file_size), info.file_size))
    print(
        string.format(
            "  breakdown:        header=%s  pages=%s  nodes=%s  siblings=%s",
            format_size(info.header_bytes),
            format_size(info.pages_bytes),
            format_size(info.nodes_bytes),
            format_size(info.siblings_bytes)
        )
    )
    if REGIONS and info.page_count > 0 then
        local region_counts = {}
        for _, idx in ipairs(info.page_indices) do
            local region = classify_address(idx << PAGE_LOG2_SIZE)
            region_counts[region] = (region_counts[region] or 0) + 1
        end
        local sorted = {}
        for name, count in pairs(region_counts) do
            sorted[#sorted + 1] = { name, count }
        end
        table.sort(sorted, function(a, b) return a[2] > b[2] end)
        local parts = {}
        for _, r in ipairs(sorted) do
            parts[#parts + 1] = string.format("%s=%d", r[1], r[2])
        end
        print(string.format("  page_regions:     %s", table.concat(parts, "  ")))
    end
end

local function print_stats_row(info)
    print(
        string.format(
            "%-12d %-6d %-6d %-8d %-12s %s",
            info.requested_cycle_count,
            info.page_count,
            info.node_count,
            info.sibling_count,
            format_size(info.file_size),
            info.path
        )
    )
end

local commands = {}

function commands.info(args)
    local path = assert(args[1], "usage: step-log-util.lua info <step-log>")
    print_header(read_header(path))
end

commands["root-hash-before"] = function(args)
    local path = assert(args[1], "usage: step-log-util.lua root-hash-before <step-log>")
    io.write(hexstring(read_header(path).root_hash_before))
end

commands["root-hash-after"] = function(args)
    local path = assert(args[1], "usage: step-log-util.lua root-hash-after <step-log>")
    io.write(hexstring(read_header(path).root_hash_after))
end

commands["requested-cycle-count"] = function(args)
    local path = assert(args[1], "usage: step-log-util.lua requested-cycle-count <step-log>")
    io.write(tostring(read_header(path).requested_cycle_count))
end

function commands.signature(args)
    local path = assert(args[1], "usage: step-log-util.lua signature <step-log>")
    local f <close> = assert(io.open(path, "rb"))
    local sig = f:read(SIGNATURE_SIZE)
    if sig == STEP_LOG_SIGNATURE then
        io.write("ok\n")
    else
        io.write(
            string.format(
                "mismatch: got %s, expected %s\n",
                sig and hexstring(sig) or "<short read>",
                hexstring(STEP_LOG_SIGNATURE)
            )
        )
        os.exit(1)
    end
end

function commands.stats(args)
    assert(args[1], "usage: step-log-util.lua stats <step-log> [step-log ...]")
    for i, path in ipairs(args) do
        print_stats(read_full(path))
        if i < #args then print() end
    end
end

commands["batch-stats"] = function(args)
    local dir = assert(args[1], "usage: step-log-util.lua batch-stats <dir>")
    local files = {}
    local pipe = assert(io.popen(string.format('ls -1 "%s"/*.log 2>/dev/null', dir)))
    for line in pipe:lines() do
        files[#files + 1] = line
    end
    pipe:close()
    assert(#files > 0, "no .log files found in " .. dir)
    table.sort(files)

    print(string.format("%-12s %-6s %-6s %-8s %-12s %s", "cycles", "pages", "nodes", "siblings", "size", "path"))
    print(string.rep("-", 80))

    local total = { page = 0, node = 0, sibling = 0, size = 0 }
    local max = { page = 0, node = 0, sibling = 0, size = 0 }
    local max_path = { page = "", node = "", sibling = "", size = "" }
    for _, path in ipairs(files) do
        local ok, info = pcall(read_full, path)
        if ok then
            print_stats_row(info)
            total.page = total.page + info.page_count
            total.node = total.node + info.node_count
            total.sibling = total.sibling + info.sibling_count
            total.size = total.size + info.file_size
            if info.page_count > max.page then
                max.page = info.page_count
                max_path.page = path
            end
            if info.node_count > max.node then
                max.node = info.node_count
                max_path.node = path
            end
            if info.sibling_count > max.sibling then
                max.sibling = info.sibling_count
                max_path.sibling = path
            end
            if info.file_size > max.size then
                max.size = info.file_size
                max_path.size = path
            end
        else
            io.stderr:write(string.format("warning: skipping %s: %s\n", path, tostring(info)))
        end
    end

    print(string.rep("-", 80))
    print(string.format("Files: %d", #files))
    print(
        string.format(
            "Avg pages: %.1f   Avg nodes: %.1f   Avg siblings: %.1f   Avg size: %s",
            total.page / #files,
            total.node / #files,
            total.sibling / #files,
            format_size(total.size // #files)
        )
    )
    print(string.format("Max pages: %d (%s)", max.page, max_path.page))
    print(string.format("Max nodes: %d (%s)", max.node, max_path.node))
    print(string.format("Max siblings: %d (%s)", max.sibling, max_path.sibling))
    print(string.format("Max size: %s (%s)", format_size(max.size), max_path.size))
end

function commands.pages(args)
    local path = assert(args[1], "usage: step-log-util.lua pages <step-log>")
    local info = read_full(path)
    print(string.format("%-8s %-18s %s", "index", "address", "region"))
    print(string.rep("-", 50))
    for _, idx in ipairs(info.page_indices) do
        local addr = idx << PAGE_LOG2_SIZE
        print(string.format("%-8d 0x%016x %s", idx, addr, classify_address(addr)))
    end
end

function commands.nodes(args)
    local path = assert(args[1], "usage: step-log-util.lua nodes <step-log>")
    local info = read_full(path)
    if info.node_count == 0 then
        print("No nodes recorded in " .. path)
        return
    end
    print(string.format("%-18s %-9s %-64s %-64s %s", "address", "log2_size", "hash_before", "hash_after", "region"))
    print(string.rep("-", 170))
    for _, n in ipairs(info.nodes) do
        print(
            string.format(
                "0x%016x %-9d %s %s %s",
                n.address,
                n.log2_size,
                hexstring(n.hash_before),
                hexstring(n.hash_after),
                classify_address(n.address)
            )
        )
    end
end

local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s <command> [args...]

Commands:

  info <step-log>              Human-readable header summary
  signature <step-log>         Verify the step log signature (exit non-zero on mismatch)
  root-hash-before <step-log>  Print root hash before (hex, no newline)
  requested-cycle-count <step-log>
                               Print requested_cycle_count from header (decimal, no newline)
  root-hash-after <step-log>   Print root hash after (hex, no newline)
  stats <step-log> [...]       Full structural breakdown (sizes, regions)
  batch-stats <dir>            Aggregate stats table for all .log files in <dir>
  pages <step-log>             List page indices, addresses, regions
  nodes <step-log>             List logged subtree-write nodes

Region classification needs the cartesi shared library; if not available,
the region column degrades to "unknown".

]=],
        arg[0]
    ))
    os.exit()
end

local options = {
    {
        "^%-h$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then return false end
            help()
        end,
    },
    {
        ".*",
        function(all) error("unrecognized option " .. all) end,
    },
}

local values = {}
for _, argument in ipairs(arg) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then break end
        end
    else
        values[#values + 1] = argument
    end
end

if not values[1] then help() end
local cmd_name = values[1]
assert(commands[cmd_name], "unknown command '" .. cmd_name .. "', use --help for usage")

local cmd_args = {}
for i = 2, #values do
    cmd_args[i - 1] = values[i]
end

commands[cmd_name](cmd_args)
