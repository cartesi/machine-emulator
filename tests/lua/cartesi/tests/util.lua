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

local ROOT_LOG2_SIZE = 64
local PAGE_LOG2_SIZE = 12
local PAGE_SIZE = 1 << PAGE_LOG2_SIZE
local WORD_LOG2_SIZE = 5

local function adjust_path(path) return string.gsub(path or ".", "/*$", "") .. "/" end

local test_util = {
    images_path = adjust_path(assert(os.getenv("CARTESI_IMAGES_PATH"))),
    tests_path = adjust_path(assert(os.getenv("CARTESI_TESTS_PATH"))),
    cmio_path = adjust_path(assert(os.getenv("CARTESI_CMIO_PATH"))),
    tests_uarch_path = adjust_path(assert(os.getenv("CARTESI_TESTS_UARCH_PATH"))),
}

local zero_keccak_hash_table = {
    "",
    "",
}

do
    local hash = cartesi.keccak(string.rep("\0", 1 << WORD_LOG2_SIZE))
    for i = WORD_LOG2_SIZE, ROOT_LOG2_SIZE - 1 do
        zero_keccak_hash_table[i] = hash
        hash = cartesi.keccak(hash, hash)
    end
end

local ZERO_PAGE = string.rep("\x00", PAGE_SIZE)

test_util.uarch_programs = {
    halt = {
        (cartesi.UARCH_ECALL_FN_HALT << 20) | 0x00893, -- li a7,halt
        0x00000073, -- ecall
    },
}

test_util.uarch_programs.default = {
    0x07b00513, --   li	a0,123
    table.unpack(test_util.uarch_programs.halt),
}

function test_util.create_test_uarch_program(instructions)
    if not instructions then instructions = test_util.uarch_programs.default end
    local file_path = os.tmpname()
    local f <close> = io.open(file_path, "wb")
    for _, insn in pairs(instructions) do
        f:write(string.pack("I4", insn))
    end
    return file_path
end

function test_util.make_do_test(build_machine, type, config, runtime_config)
    return function(description, f)
        io.write("  " .. description .. "...\n")
        local machine <close> = build_machine(type, config, runtime_config)
        f(machine)
        print("<<<<<<<<<<<<<<<< passed >>>>>>>>>>>>>>>")
    end
end

function test_util.disabled_test(description) print("Disabled test - " .. description) end

local back_merkle_tree_meta = { __index = {} }

function back_merkle_tree_meta.__index:push_back(new_leaf_hash)
    local right = new_leaf_hash
    assert(self.m_leaf_count < self.m_max_leaves, "too many leaves")
    local depth = self.m_log2_root_size - self.m_log2_leaf_size
    for i = 0, depth do
        if self.m_leaf_count & (0x01 << i) ~= 0x0 then
            local left = self.m_context[i]
            right = cartesi.keccak(left, right)
        else
            self.m_context[i] = right
            break
        end
    end
    self.m_leaf_count = self.m_leaf_count + 1
end

function back_merkle_tree_meta.__index:pad_back(new_leaf_count)
    assert(
        new_leaf_count <= self.m_max_leaves and self.m_leaf_count + new_leaf_count <= self.m_max_leaves,
        "too many leaves"
    )
    local depth = self.m_log2_root_size - self.m_log2_leaf_size
    -- pad with progressively larger trees until our smallest tree has more leaves than the leaf count left
    local j = 0
    while j <= depth do
        local j_span = 0x1 << j
        if j_span > new_leaf_count then break end
        -- is our smallest tree at depth j?
        if (self.m_leaf_count & j_span) ~= 0x0 then
            -- if so, we can add 2^j pristine leaves directly
            local right = zero_keccak_hash_table[self.m_log2_leaf_size + j]
            for i = j, depth do
                local i_span = 0x1 << i
                if (self.m_leaf_count & i_span) ~= 0x0 then
                    local left = self.m_context[i]
                    right = cartesi.keccak(left, right)
                else
                    self.m_context[i] = right
                    -- next outer loop starts again from where inner loop left off
                    j = i
                    break
                end
            end
            new_leaf_count = new_leaf_count - j_span
            self.m_leaf_count = self.m_leaf_count + j_span
        else
            j = j + 1
        end
    end
    -- now add the rest of the padding directly to the context
    for i = 0, depth do
        local i_span = 0x1 << i
        if (new_leaf_count & i_span) ~= 0x0 then
            self.m_context[i] = zero_keccak_hash_table[self.m_log2_leaf_size + i]
            new_leaf_count = new_leaf_count - i_span
            self.m_leaf_count = self.m_leaf_count + i_span
        end
    end
end

function back_merkle_tree_meta.__index:get_root_hash()
    assert(self.m_leaf_count <= self.m_max_leaves, "too many leaves")
    local depth = self.m_log2_root_size - self.m_log2_leaf_size
    if self.m_leaf_count < self.m_max_leaves then
        local root = zero_keccak_hash_table[self.m_log2_leaf_size]
        for i = 0, depth - 1 do
            if (self.m_leaf_count & (0x01 << i)) ~= 0 then
                local left = self.m_context[i]
                root = cartesi.keccak(left, root)
            else
                local right = zero_keccak_hash_table[self.m_log2_leaf_size + i]
                root = cartesi.keccak(root, right)
            end
        end
        return root
    else
        return self.m_context[depth]
    end
end

function test_util.new_back_merkle_tree(log2_root_size, log2_leaf_size)
    local self = {}
    self.m_context = {}
    self.m_log2_leaf_size = log2_leaf_size
    self.m_log2_root_size = log2_root_size
    self.m_leaf_count = 0
    self.m_max_leaves = 0x01 << (log2_root_size - log2_leaf_size)
    return setmetatable(self, back_merkle_tree_meta)
end

function test_util.file_exists(name)
    local f <close> = io.open(name, "r")
    return f ~= nil
end

function test_util.tohex(str)
    return (str:gsub(".", function(c) return string.format("%02X", string.byte(c)) end))
end

function test_util.fromhex(str)
    return (str:gsub("..", function(cc) return string.char(tonumber(cc, 16)) end))
end

function test_util.split_string(inputstr, sep)
    if sep == nil then sep = "%s" end
    local t = {}
    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end
    return t
end

function test_util.check_proof(proof)
    local hash = proof.target_hash
    for log2_size = proof.log2_target_size, proof.log2_root_size - 1 do
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = proof.sibling_hashes[log2_size - proof.log2_target_size + 1], hash
        else
            first, second = hash, proof.sibling_hashes[log2_size - proof.log2_target_size + 1]
        end
        hash = cartesi.keccak(first, second)
    end
    return hash == proof.root_hash
end

function test_util.align(v, el) return (v >> el << el) end

function test_util.load_file(filename)
    local fd <close> = assert(io.open(filename, "rb"))
    local data = assert(fd:read("*all"))
    return data
end

local function merkle_hash(data, start, log2_size)
    if log2_size == PAGE_LOG2_SIZE and data:sub(start + 1, start + PAGE_SIZE) == ZERO_PAGE then
        return zero_keccak_hash_table[PAGE_LOG2_SIZE]
    elseif log2_size > WORD_LOG2_SIZE then
        local child_log2_size = log2_size - 1
        local left = merkle_hash(data, start, child_log2_size)
        local right = merkle_hash(data, start + (1 << child_log2_size), child_log2_size)
        return cartesi.keccak(left, right)
    else
        return cartesi.keccak(data:sub(start + 1, start + (1 << WORD_LOG2_SIZE)))
    end
end

test_util.merkle_hash = merkle_hash

-- Take data from dumped memory files
-- and calculate root hash of the machine
function test_util.calculate_emulator_hash(machine)
    local tree = test_util.new_back_merkle_tree(64, PAGE_LOG2_SIZE)
    local last = 0
    for _, v in ipairs(machine:get_memory_ranges()) do
        tree:pad_back((v.start - last) >> PAGE_LOG2_SIZE)
        local finish = v.start + v.length
        for j = v.start, finish - 1, PAGE_SIZE do
            local page_hash = merkle_hash(machine:read_memory(j, PAGE_SIZE), 0, PAGE_LOG2_SIZE)
            tree:push_back(page_hash)
        end
        last = finish
    end
    return tree:get_root_hash()
end

-- Read memory from given machine and calculate uarch state hash
function test_util.calculate_uarch_state_hash(machine)
    local shadow_data = machine:read_memory(cartesi.UARCH_SHADOW_START_ADDRESS, cartesi.UARCH_SHADOW_LENGTH)
    local ram_data = machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, cartesi.UARCH_RAM_LENGTH)
    local tree = test_util.new_back_merkle_tree(cartesi.UARCH_STATE_LOG2_SIZE, PAGE_LOG2_SIZE)
    for j = 0, #shadow_data - 1, PAGE_SIZE do
        local page_hash = merkle_hash(shadow_data, j, PAGE_LOG2_SIZE)
        tree:push_back(page_hash)
    end
    -- pad the region between the end of shadow data and start of ram
    tree:pad_back(
        (cartesi.UARCH_RAM_START_ADDRESS - cartesi.UARCH_SHADOW_START_ADDRESS - #shadow_data) >> PAGE_LOG2_SIZE
    )
    for j = 0, #ram_data - 1, PAGE_SIZE do
        local page_hash = merkle_hash(ram_data, j, PAGE_LOG2_SIZE)
        tree:push_back(page_hash)
    end
    return tree:get_root_hash()
end

-- Executes a function and asserts that it throws an error and that the error message matches the expected pattern
function test_util.assert_error(expected_error_text_pattern, fn)
    local status, actual_error_text = pcall(fn)
    assert(status == false, "Expected error to be thrown, but it was not")
    assert(
        actual_error_text:match(expected_error_text_pattern),
        string.format("Expected error to match '%s', but it was '%s'", expected_error_text_pattern, actual_error_text)
    )
end

-- temporary file
local temp_file_meta = { __index = {} }

function temp_file_meta.__index:write(...) self.file:write(...) end

function temp_file_meta.__index:read_all()
    self.file:seek("set", 0)
    return self.file:read("*all")
end

function temp_file_meta.__index:close()
    self.file:close()
    os.remove(self.file_name)
end

function temp_file_meta:__close() self:close() end

function test_util.new_temp_file()
    local self = {}
    self.file_name = os.tmpname()
    self.file = io.open(self.file_name, "w+")
    return setmetatable(self, temp_file_meta)
end

return test_util
