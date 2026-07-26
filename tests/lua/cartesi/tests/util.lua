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
    local page_hash = page == ZERO_PAGE and pristine_page_hash or hash_tree.get_root_hash(page, PAGE_LOG2_SIZE, hash_fn)
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
-- Deliberately non-destructive: it never deletes. Clearing stale fixtures is the job of a visible
-- Makefile/CI target (e.g. solidity-step's fixtures-clean), not of a recorder. The only shell call
-- is mkdir -p (creation, never deletion); the path is single-quoted and a literal quote rejected.
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

function tests_util.tohex(str)
    return (str:gsub(".", function(c)
        return string.format("%02X", string.byte(c))
    end))
end

function tests_util.fromhex(str)
    return (str:gsub("..", function(cc)
        return string.char(tonumber(cc, 16))
    end))
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

function tests_util.read_step_log_file(filename)
    local file <close> = assert(io.open(filename, "rb"))
    local signature = file:read(8)
    local root_hash_before = file:read(32)
    local requested_cycle_count = string.unpack("<I8", file:read(8))
    local root_hash_after = file:read(32)
    local hash_function = string.unpack("<I8", file:read(8))
    local page_count = string.unpack("<I8", file:read(8))
    local node_count = string.unpack("<I8", file:read(8))
    local sibling_count = string.unpack("<I8", file:read(8))
    local log = {
        signature = signature,
        root_hash_before = root_hash_before,
        requested_cycle_count = requested_cycle_count,
        root_hash_after = root_hash_after,
        hash_function = hash_function,
        pages = {},
        nodes = {},
        siblings = {},
    }
    for i = 1, page_count do
        log.pages[i] = {
            index = string.unpack("<I8", file:read(8)),
            data = file:read(PAGE_SIZE),
            scratch_hash = file:read(32),
        }
    end
    for i = 1, node_count do
        log.nodes[i] = {
            address = string.unpack("<I8", file:read(8)),
            log2_size = string.unpack("<I8", file:read(8)),
            hash_before = file:read(32),
            hash_after = file:read(32),
        }
    end
    for i = 1, sibling_count do
        log.siblings[i] = file:read(32)
    end
    return log
end

-- override_{page,node,sibling}_count lets a test fake a header count that
-- diverges from the actual entry array length (to exercise overflow checks).
function tests_util.write_step_log_file(logdata, filename)
    local file <close> = assert(io.open(filename, "wb"))
    local page_count = logdata.override_page_count or #logdata.pages
    local node_count = logdata.override_node_count or #logdata.nodes
    local sibling_count = logdata.override_sibling_count or #logdata.siblings
    file:write(logdata.signature)
    file:write(logdata.root_hash_before)
    file:write(string.pack("<I8", logdata.requested_cycle_count))
    file:write(logdata.root_hash_after)
    file:write(string.pack("<I8", logdata.hash_function))
    file:write(string.pack("<I8", page_count))
    file:write(string.pack("<I8", node_count))
    file:write(string.pack("<I8", sibling_count))
    for _, page in ipairs(logdata.pages) do
        file:write(string.pack("<I8", page.index))
        file:write(page.data)
        file:write(page.scratch_hash)
    end
    for _, node in ipairs(logdata.nodes) do
        file:write(string.pack("<I8", node.address))
        file:write(string.pack("<I8", node.log2_size))
        file:write(node.hash_before)
        file:write(node.hash_after)
    end
    for _, sibling in ipairs(logdata.siblings) do
        file:write(sibling)
    end
end

-- Read a step log file, hand it to callback for mutation, write it to a new file.
function tests_util.copy_step_log(original_filename, new_filename, callback)
    local log_data = tests_util.read_step_log_file(original_filename)
    callback(log_data)
    os.remove(new_filename)
    tests_util.write_step_log_file(log_data, new_filename)
end

-- Turn one sibling subtree into an unchanged node carrying the same hash, leaving the
-- pre-state root identical but adding a node no semantic write consumes. Exercises the
-- replayer's unconsumed-node rejection: every node's hash_after is folded into the
-- post-state root verbatim, so a node must be produced by an actual write.
--
-- Mirrors the replayer's three-cursor walk (pages, nodes, siblings) to locate the first
-- sibling spanning more than one page (node sizes must exceed a page), then moves that
-- sibling's hash into log.nodes. Works on logs that already carry a node (reset/cmio).
function tests_util.inject_unconsumed_node(log)
    local pages = {}
    for i, p in ipairs(log.pages) do
        pages[i] = p.index
    end
    table.sort(pages)
    local nodes = log.nodes or {}
    local next_page, next_node, next_sibling = 1, 1, 1
    local target

    local function walk(first_page_index, log2_page_count)
        local end_page_index = first_page_index + (1 << log2_page_count)
        local page_in = next_page <= #pages and pages[next_page] < end_page_index
        local node_in = next_node <= #nodes and (nodes[next_node].address >> PAGE_LOG2_SIZE) < end_page_index
        if not page_in and not node_in then
            if not target and log2_page_count > 0 then
                target = {
                    sibling_index = next_sibling,
                    address = first_page_index << PAGE_LOG2_SIZE,
                    log2_size = log2_page_count + PAGE_LOG2_SIZE,
                }
            end
            next_sibling = next_sibling + 1
            return
        end
        if
            node_in
            and nodes[next_node].address == (first_page_index << PAGE_LOG2_SIZE)
            and nodes[next_node].log2_size == (log2_page_count + PAGE_LOG2_SIZE)
        then
            next_node = next_node + 1
            return
        end
        if log2_page_count > 0 then
            walk(first_page_index, log2_page_count - 1)
            walk(first_page_index + (1 << (log2_page_count - 1)), log2_page_count - 1)
        else
            next_page = next_page + 1
        end
    end

    walk(0, ROOT_LOG2_SIZE - PAGE_LOG2_SIZE)
    assert(target, "no multi-page sibling subtree available to convert into a node")
    local hash = log.siblings[target.sibling_index]
    table.remove(log.siblings, target.sibling_index)
    log.nodes = nodes
    table.insert(log.nodes, {
        address = target.address,
        log2_size = target.log2_size,
        hash_before = hash,
        hash_after = hash,
    })
    table.sort(log.nodes, function(a, b)
        return a.address < b.address
    end)
    return log
end

-- Recompute a parsed step log's root by folding pages, nodes, and siblings over the
-- full address space, mirroring the replayer's compute_root_hash. `use_after` selects a
-- node's hash_after (post-state) over hash_before. Lets a generator tamper a page or node
-- and re-derive the matching root so the log still decodes. Same three-cursor walk as
-- inject_unconsumed_node, but returning each subtree's hash instead of locating a target.
function tests_util.recompute_step_log_root(log, use_after, hash_fn)
    hash_fn = hash_fn or "keccak256"
    local pages = {}
    for _, p in ipairs(log.pages) do
        pages[#pages + 1] = p
    end
    table.sort(pages, function(a, b)
        return a.index < b.index
    end)
    local nodes = {}
    for _, n in ipairs(log.nodes) do
        nodes[#nodes + 1] = n
    end
    table.sort(nodes, function(a, b)
        return a.address < b.address
    end)
    local next_page, next_node, next_sibling = 1, 1, 1

    local function walk(first_page_index, log2_page_count)
        local end_page_index = first_page_index + (1 << log2_page_count)
        local page_in = next_page <= #pages and pages[next_page].index < end_page_index
        local node_in = next_node <= #nodes and (nodes[next_node].address >> PAGE_LOG2_SIZE) < end_page_index
        if not page_in and not node_in then
            local sibling = log.siblings[next_sibling]
            next_sibling = next_sibling + 1
            return sibling
        end
        if
            node_in
            and nodes[next_node].address == (first_page_index << PAGE_LOG2_SIZE)
            and nodes[next_node].log2_size == (log2_page_count + PAGE_LOG2_SIZE)
        then
            local node = nodes[next_node]
            next_node = next_node + 1
            return use_after and node.hash_after or node.hash_before
        end
        if log2_page_count > 0 then
            local left = walk(first_page_index, log2_page_count - 1)
            local right = walk(first_page_index + (1 << (log2_page_count - 1)), log2_page_count - 1)
            return cartesi[hash_fn](left, right)
        end
        local page = pages[next_page]
        next_page = next_page + 1
        return merkle_hash(page.data, 0, PAGE_LOG2_SIZE, hash_fn)
    end

    return walk(0, ROOT_LOG2_SIZE - PAGE_LOG2_SIZE)
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
