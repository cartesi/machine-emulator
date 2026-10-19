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

local cartesi = require("cartesi")
local util = require("cartesi.util")
local hash_tree = require("cartesi.hash-tree")

local ROOT_LOG2_SIZE = 64
local PAGE_LOG2_SIZE = 12
local PAGE_SIZE = 1 << PAGE_LOG2_SIZE
local WORD_LOG2_SIZE = 5
local PAGE_LOG2_WORD_COUNT = PAGE_LOG2_SIZE - WORD_LOG2_SIZE
local ZERO_PAGE = string.rep("\0", PAGE_SIZE)

local function adjust_path(path)
    return string.gsub(path or ".", "/*$", "") .. "/"
end

local has_posix_stdlib, posix_stdlib = pcall(require, "posix.stdlib")

-- Returns the directory absolute path at level `dirlevel` for the calling script at level `calllevel`.
local function get_script_path(dirlevel, calllevel)
    local info = debug.getinfo(calllevel or 1, "S")
    local path = info and info.source and info.source:match("^@([^\n\r]+)")
    assert(path, "could not retrieve calling script path")
    if has_posix_stdlib then
        path = posix_stdlib.realpath(path)
    end
    if dirlevel and dirlevel > 0 then
        local segments = {}
        for segment in path:gmatch("[^/]+") do
            table.insert(segments, segment)
        end
        return "/" .. table.concat(segments, "/", 1, #segments - dirlevel)
    end
    return path
end

local tests_util = {
    images_path = adjust_path(os.getenv("CARTESI_IMAGES_PATH") or get_script_path(5) .. "/src"),
    tests_path = adjust_path(os.getenv("CARTESI_TESTS_PATH") or get_script_path(4) .. "/build/machine"),
    cmio_path = adjust_path(os.getenv("CARTESI_CMIO_PATH") or get_script_path(4) .. "/build/cmio"),
    step_logs_path = adjust_path(os.getenv("CARTESI_STEP_LOGS_PATH") or get_script_path(4) .. "/build/step-logs"),
    tests_uarch_path = adjust_path(os.getenv("CARTESI_TESTS_UARCH_PATH") or get_script_path(4) .. "/build/uarch"),
    reject_fixtures_path = adjust_path(
        os.getenv("CARTESI_REJECT_STEP_FIXTURES_PATH") or get_script_path(4) .. "/build/reject-step-fixtures"
    ),
}

local function compute_zero_hash_table(hash_fn)
    local zero_hash_table = {
        "",
        "",
    }
    local hash = cartesi[hash_fn](string.rep("\0", 1 << WORD_LOG2_SIZE))
    for i = WORD_LOG2_SIZE, ROOT_LOG2_SIZE - 1 do
        zero_hash_table[i] = hash
        hash = cartesi[hash_fn](hash, hash)
    end
    return zero_hash_table
end

local zero_hash_tables = {
    keccak256 = compute_zero_hash_table("keccak256"),
    sha256 = compute_zero_hash_table("sha256"),
}

local function append_page(frontier, page, pristine_page_hash, hash_fn)
    local page_hash = page == ZERO_PAGE and pristine_page_hash
        or hash_tree.get_data_root_hash(page, PAGE_LOG2_SIZE, hash_fn)
    hash_tree.frontier_push_back(frontier, page_hash, PAGE_LOG2_WORD_COUNT)
end

tests_util.uarch_programs = {
    halt = {
        (cartesi.UARCH_ECALL_FN_HALT << 20) | 0x00893, -- li a7,halt
        0x00000073, -- ecall
    },
}

tests_util.uarch_programs.default = {
    0x07b00513, --   li	a0,123
    table.unpack(tests_util.uarch_programs.halt),
}

function tests_util.create_test_uarch_program(instructions)
    assert(instructions, "missing instructions")
    local file_path = os.tmpname()
    local f <close> = assert(io.open(file_path, "wb"))
    for _, insn in pairs(instructions) do
        f:write(string.pack("I4", insn))
    end
    return file_path
end

function tests_util.make_do_test(build_machine, type, config, runtime_config)
    return function(description, f)
        io.write("  " .. description .. "...\n")
        local machine <close> = build_machine(type, config, runtime_config)
        f(machine)
        print("<<<<<<<<<<<<<<<< passed >>>>>>>>>>>>>>>")
    end
end

function tests_util.disabled_test(description)
    print("Disabled test - " .. description)
end

function tests_util.file_exists(name)
    local f <close> = io.open(name, "r")
    return f ~= nil
end

-- Create a fixture output directory and require it to be empty before the caller writes into it.
-- Deliberately non-destructive: it never deletes; clearing stale fixtures is the Makefile's job.
function tests_util.prepare_empty_output_dir(dir)
    assert(type(dir) == "string" and #dir > 0, "output dir must be a non-empty string")
    assert(not dir:match("^/+$"), "refusing to use the filesystem root as an output dir")
    assert(not dir:find("'", 1, true), "output dir must not contain a single quote: " .. dir)
    assert(os.execute("mkdir -p '" .. dir .. "'"))
    for _, entry in ipairs(require("posix.dirent").dir(dir)) do
        if entry ~= "." and entry ~= ".." then
            error("output dir is not empty: " .. dir .. "\nremove it or clean the fixture root before recording")
        end
    end
end

local function merkle_hash(data, start, log2_size, hash_fn)
    assert(hash_fn, "hash_fn is nil")
    local zero_hash_table = zero_hash_tables[hash_fn]
    if log2_size == PAGE_LOG2_SIZE and data:sub(start + 1, start + PAGE_SIZE) == ZERO_PAGE then
        return zero_hash_table[PAGE_LOG2_SIZE]
    elseif log2_size > WORD_LOG2_SIZE then
        local child_log2_size = log2_size - 1
        local left = merkle_hash(data, start, child_log2_size, hash_fn)
        local right = merkle_hash(data, start + (1 << child_log2_size), child_log2_size, hash_fn)
        return cartesi[hash_fn](left, right)
    else
        return cartesi[hash_fn](data:sub(start + 1, start + (1 << WORD_LOG2_SIZE)), nil)
    end
end

tests_util.merkle_hash = merkle_hash

function tests_util.split_string(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end
    local t = {}
    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end
    return t
end

function tests_util.slice_proof(proof, new_log2_root_size, new_log2_target_size, hash_fn)
    assert(hash_fn, "hash_fn is nil")
    assert(new_log2_root_size <= proof.log2_root_size, "log2_root_size is too large")
    assert(new_log2_target_size >= proof.log2_target_size, "log2_target_size is too small")
    assert(new_log2_target_size <= new_log2_root_size, "log2_target_size > log2_root_size")
    -- Bubble up from original target to new target size
    local hash = proof.target_hash
    for log2_size = proof.log2_target_size, new_log2_target_size - 1 do
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = proof.sibling_hashes[log2_size - proof.log2_target_size + 1], hash
        else
            first, second = hash, proof.sibling_hashes[log2_size - proof.log2_target_size + 1]
        end
        hash = cartesi[hash_fn](first, second)
    end
    local sliced = {
        log2_root_size = new_log2_root_size,
        log2_target_size = new_log2_target_size,
        target_hash = hash,
        target_address = (proof.target_address >> new_log2_target_size) << new_log2_target_size,
        sibling_hashes = {},
    }
    -- Copy sibling hashes and continue bubbling up to compute root hash
    for log2_size = new_log2_target_size, new_log2_root_size - 1 do
        local sibling = proof.sibling_hashes[log2_size - proof.log2_target_size + 1]
        sliced.sibling_hashes[log2_size - new_log2_target_size + 1] = sibling
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = sibling, hash
        else
            first, second = hash, sibling
        end
        hash = cartesi[hash_fn](first, second)
    end
    sliced.root_hash = hash
    hash_tree.verify_slice(sliced, hash_fn)
    return sliced
end

function tests_util.align(v, el)
    return (v >> el << el)
end

-- Take data from dumped memory files
-- and calculate root hash of the machine
function tests_util.calculate_emulator_hash(machine, hash_fn)
    hash_fn = hash_fn or machine:get_initial_config().hash_tree.hash_function
    local frontier = hash_tree.frontier(ROOT_LOG2_SIZE - WORD_LOG2_SIZE, hash_fn)
    local pristine_page_hash = zero_hash_tables[hash_fn][PAGE_LOG2_SIZE]
    local last = 0
    for _, v in ipairs(machine:get_address_ranges()) do
        hash_tree.frontier_pad_back(
            frontier,
            pristine_page_hash,
            (v.start - last) >> PAGE_LOG2_SIZE,
            PAGE_LOG2_WORD_COUNT
        )
        local finish = v.start + v.length
        for j = v.start, finish - 1, PAGE_SIZE do
            append_page(frontier, machine:read_memory(j, PAGE_SIZE), pristine_page_hash, hash_fn)
        end
        last = finish
    end
    return hash_tree.frontier_get_root_hash(frontier, pristine_page_hash, PAGE_LOG2_WORD_COUNT)
end

-- Read memory from given machine and calculate uarch state hash
function tests_util.calculate_uarch_state_hash(machine)
    local hash_fn = machine:get_initial_config().hash_tree.hash_function
    local shadow_data = machine:read_memory(cartesi.UARCH_SHADOW_START_ADDRESS, cartesi.UARCH_SHADOW_LENGTH)
    local ram_data = machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, cartesi.UARCH_RAM_LENGTH)
    local frontier = hash_tree.frontier(cartesi.UARCH_STATE_LOG2_SIZE - WORD_LOG2_SIZE, hash_fn)
    local pristine_page_hash = zero_hash_tables[hash_fn][PAGE_LOG2_SIZE]
    for j = 0, #shadow_data - 1, PAGE_SIZE do
        append_page(frontier, shadow_data:sub(j + 1, j + PAGE_SIZE), pristine_page_hash, hash_fn)
    end
    -- pad the region between the end of shadow data and start of ram
    hash_tree.frontier_pad_back(
        frontier,
        pristine_page_hash,
        (cartesi.UARCH_RAM_START_ADDRESS - cartesi.UARCH_SHADOW_START_ADDRESS - #shadow_data) >> PAGE_LOG2_SIZE,
        PAGE_LOG2_WORD_COUNT
    )
    for j = 0, #ram_data - 1, PAGE_SIZE do
        append_page(frontier, ram_data:sub(j + 1, j + PAGE_SIZE), pristine_page_hash, hash_fn)
    end
    return hash_tree.frontier_get_root_hash(frontier, pristine_page_hash, PAGE_LOG2_WORD_COUNT)
end

-- Executes a function and asserts that it throws an error and that the error message matches the expected pattern
function tests_util.assert_error(expected_error_text_pattern, fn)
    local status, actual_error_text = pcall(fn)
    assert(status == false, "Expected error to be thrown, but it was not")
    assert(
        actual_error_text:match(expected_error_text_pattern),
        string.format("Expected error to match '%s', but it was '%s'", expected_error_text_pattern, actual_error_text)
    )
end

-- temporary file
local temp_file_meta = { __index = {} }

function temp_file_meta.__index:write(...)
    self.file:write(...)
end

function temp_file_meta.__index:read_all()
    self.file:seek("set", 0)
    return self.file:read("*all")
end

function temp_file_meta.__index:close()
    self.file:close()
    os.remove(self.file_name)
end

function temp_file_meta:__close()
    self:close()
end

function tests_util.new_temp_file()
    local self = {}
    self.file_name = os.tmpname()
    self.file = io.open(self.file_name, "w+")
    return setmetatable(self, temp_file_meta)
end

-- Binary step log helpers. Layout: see step_log_header in src/step-log.hpp.

function tests_util.parse_step_log(log)
    local pos = 1
    local function take(n)
        local s = log:sub(pos, pos + n - 1)
        assert(#s == n, "truncated step log")
        pos = pos + n
        return s
    end
    local function u64()
        return (string.unpack("<I8", take(8)))
    end
    local parsed = {
        signature = take(8),
        hash_function = u64(),
        pages = {},
        nodes = {},
        siblings = {},
    }
    local page_count = u64()
    local node_count = u64()
    local sibling_count = u64()
    for i = 1, page_count do
        local address, log2_size = u64(), u64()
        parsed.pages[i] = {
            index = address >> PAGE_LOG2_SIZE,
            offset = address & (PAGE_SIZE - 1),
            log2_size = log2_size,
            data = take(1 << log2_size),
            scratch_hash = take(32),
        }
    end
    for i = 1, node_count do
        parsed.nodes[i] = {
            address = u64(),
            log2_size = u64(),
            hash = take(32),
        }
    end
    for i = 1, sibling_count do
        parsed.siblings[i] = take(32)
    end
    return parsed
end

-- override_{page,node,sibling}_count lets a test fake a header count that
-- diverges from the actual entry array length (to exercise overflow checks).
function tests_util.serialize_step_log(logdata)
    local parts = {
        logdata.signature,
        string.pack("<I8", logdata.hash_function),
        string.pack("<I8", logdata.override_page_count or #logdata.pages),
        string.pack("<I8", logdata.override_node_count or #logdata.nodes),
        string.pack("<I8", logdata.override_sibling_count or #logdata.siblings),
    }
    for _, page in ipairs(logdata.pages) do
        parts[#parts + 1] =
            string.pack("<I8I8", (page.index << PAGE_LOG2_SIZE) | (page.offset or 0), page.log2_size or PAGE_LOG2_SIZE)
        parts[#parts + 1] = page.data
        parts[#parts + 1] = page.scratch_hash
    end
    for _, node in ipairs(logdata.nodes) do
        parts[#parts + 1] = string.pack("<I8", node.address)
        parts[#parts + 1] = string.pack("<I8", node.log2_size)
        parts[#parts + 1] = node.hash
    end
    for _, sibling in ipairs(logdata.siblings) do
        parts[#parts + 1] = sibling
    end
    return table.concat(parts)
end

-- Parse a step log, hand it to callback for mutation, and serialize it back.
function tests_util.mutate_step_log(log, callback)
    local log_data = tests_util.parse_step_log(log)
    callback(log_data)
    return tests_util.serialize_step_log(log_data)
end

function tests_util.read_step_log_file(filename)
    return tests_util.parse_step_log(util.read_file(filename))
end

function tests_util.write_step_log_file(logdata, filename)
    util.write_file(tests_util.serialize_step_log(logdata), filename)
end

-- Turn one sibling subtree into an unchanged node carrying the same hash. The pre-state
-- root is identical, and a node no write touches folds into the post-state root as an
-- unchanged region, so the transformed log must still verify.
--
-- Mirrors the replayer's three-cursor walk (pages, nodes, siblings) to locate the first
-- sibling spanning more than one page (node sizes must exceed a page), then moves that
-- sibling's hash into log.nodes. Works on logs that already carry a node (reset/cmio).
local function walk_step_log(log, sibling_fn, slice_fn, node_fn, parent_fn)
    local next_page, next_node, next_sibling = 1, 1, 1
    local function walk(first_leaf, log2_leaves)
        local end_leaf = first_leaf + (1 << log2_leaves)
        local page = log.pages[next_page]
        local node = log.nodes[next_node]
        local page_leaf = page and (((page.index << PAGE_LOG2_SIZE) | (page.offset or 0)) >> WORD_LOG2_SIZE)
        local page_in = page_leaf and page_leaf < end_leaf
        local node_in = node and (node.address >> WORD_LOG2_SIZE) < end_leaf
        local address, log2_size = first_leaf << WORD_LOG2_SIZE, log2_leaves + WORD_LOG2_SIZE
        if not page_in and not node_in then
            local i = next_sibling
            next_sibling = i + 1
            return sibling_fn(log.siblings[i], address, log2_size, i)
        end
        if node_in and node.address == address and node.log2_size == log2_size then
            next_node = next_node + 1
            return node_fn(node)
        end
        if page_in and page_leaf == first_leaf and (page.log2_size or PAGE_LOG2_SIZE) == log2_size then
            next_page = next_page + 1
            return slice_fn(page)
        end
        assert(log2_leaves > 0, "invalid slice geometry")
        local left = walk(first_leaf, log2_leaves - 1)
        local right = walk(first_leaf + (1 << (log2_leaves - 1)), log2_leaves - 1)
        return parent_fn(left, right, address, log2_size)
    end
    local root = walk(0, ROOT_LOG2_SIZE - WORD_LOG2_SIZE)
    assert(next_page == #log.pages + 1 and next_node == #log.nodes + 1 and next_sibling == #log.siblings + 1)
    return root
end

tests_util.walk_step_log = walk_step_log

function tests_util.inject_unchanged_node(log)
    local target
    local function sibling(hash, address, log2_size, index)
        if not target and log2_size > PAGE_LOG2_SIZE then
            target = { address = address, log2_size = log2_size, hash = hash, index = index }
        end
    end
    local function noop() end
    walk_step_log(log, sibling, noop, noop, noop)
    assert(target, "no multi-page sibling subtree available to convert into a node")
    table.remove(log.siblings, target.index)
    target.index = nil
    table.insert(log.nodes, target)
    table.sort(log.nodes, function(a, b)
        return (a.address >> WORD_LOG2_SIZE) < (b.address >> WORD_LOG2_SIZE)
    end)
    return log
end

-- Recompute the root without trusting the scratch hashes.
function tests_util.recompute_step_log_root(log, hash_fn)
    hash_fn = hash_fn or "keccak256"
    return walk_step_log(log, function(hash)
        return assert(hash, "missing sibling")
    end, function(page)
        return merkle_hash(page.data, 0, page.log2_size or PAGE_LOG2_SIZE, hash_fn)
    end, function(node)
        return node.hash
    end, function(left, right)
        return cartesi[hash_fn](left, right)
    end)
end

-- Restrict an existing slice and move its omitted bytes into sibling hashes. The
-- pre-state root stays identical: useful for proving that replay checks access bounds.
function tests_util.restrict_step_log_slice(log, page_index, offset, log2_size)
    local hash_fn = log.hash_function == 0 and "keccak256" or "sha256"
    local target
    local hashes = {}
    local function key(address, size)
        return string.format("%x:%d", address, size)
    end
    local function remember(hash, address, size)
        hashes[key(address, size)] = hash
    end
    local function split(data, address, size)
        local hash
        if size == WORD_LOG2_SIZE then
            hash = cartesi[hash_fn](data)
        else
            local half = 1 << (size - 1)
            hash = cartesi[hash_fn](
                split(data:sub(1, half), address, size - 1),
                split(data:sub(half + 1), address + half, size - 1)
            )
        end
        remember(hash, address, size)
        return hash
    end
    local function slice(page)
        if page.index == page_index then
            target = page
            split(page.data, (page.index << PAGE_LOG2_SIZE) | page.offset, page.log2_size)
        end
    end
    local function noop() end
    walk_step_log(log, remember, slice, noop, noop)
    assert(target, "slice to restrict was not found")
    local count = 1 << log2_size
    local relative = offset - target.offset
    assert(log2_size >= WORD_LOG2_SIZE and log2_size <= target.log2_size and offset & (count - 1) == 0)
    assert(relative >= 0 and relative + count <= #target.data)
    target.data = target.data:sub(relative + 1, relative + count)
    target.offset, target.log2_size = offset, log2_size
    log.siblings = {}
    walk_step_log(log, function(_, address, size)
        log.siblings[#log.siblings + 1] = assert(hashes[key(address, size)], "missing restricted-slice sibling")
    end, noop, noop, noop)
    return log
end

-- Executes a callback when the scope exits.
-- REMARKS: Use <close> on its returned value to make it behave deterministically.
function tests_util.scope_exit(callback)
    local function do_callback()
        if callback then
            callback()
            callback = nil
        end
    end
    return setmetatable({}, { __gc = do_callback, __close = do_callback })
end

return tests_util
