#!/usr/bin/env luapp5.3

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


local cartesi = require "cartesi"
local test_data = require "tests.data"

function adjust_images_path(path)
    if not path then return "" end
    return string.gsub(path, "/*$", "") .. "/"
end

local test_util = {
    incremental_merkle_tree_of_pages = {
        m_context = {},
        m_page_log2_size = 0,
        m_tree_log2_size = 0,
        m_page_count = 0,
        m_max_pages = 0
    },
    hash = {LOG2_WORD_SIZE = 3},
    images_path = adjust_images_path(os.getenv('CARTESI_IMAGES_PATH')),
    tests_path = adjust_images_path(os.getenv("CARTESI_TESTS_PATH"))
    
}


function test_util.make_do_test(build_machine, type)
    return function(description, f)
        io.write("  " .. description .. "...\n")
        local machine = build_machine(type)
        f(machine)
        machine:destroy()
        print("<<<<<<<<<<<<<<<< passed >>>>>>>>>>>>>>>")
    end
end



function test_util.incremental_merkle_tree_of_pages:new(o, page_log2_size,
                                                         tree_log2_size)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    self.m_context = {}
    self.m_page_log2_size = page_log2_size
    self.m_tree_log2_size = tree_log2_size
    self.m_page_count = 0
    self.m_max_pages = 0x01 << (tree_log2_size - page_log2_size)
    return o
end

function test_util.incremental_merkle_tree_of_pages:add_page(new_page_hash)
    local right = new_page_hash
    assert(self.m_page_count < self.m_max_pages,
           "Page count must be smaller than max pages")
    local depth = self.m_tree_log2_size - self.m_page_log2_size
    for i = 0, depth do
        if (self.m_page_count & (0x01 << i) ~= 0x0) then
            local left = self.m_context[i]
            right = cartesi.keccak(left, right)
        else
            self.m_context[i] = right
            break
        end
    end
    self.m_page_count = self.m_page_count + 1
end

function test_util.incremental_merkle_tree_of_pages:get_root_hash()
    assert(self.m_page_count <= self.m_max_pages,
           "Page count must be smaller or equal than max pages")
    local depth = self.m_tree_log2_size - self.m_page_log2_size
    if self.m_page_count < self.m_max_pages then
        local root = test_util.fromhex(
                         test_data.zero_keccak_hash_table[self.m_page_log2_size])
        for i = 0, depth - 1 do
            if (self.m_page_count & (0x01 << i)) then
                local left = self.m_context[i]
                root = cartesi.keccak(left, root)
            else
                local right =
                    test_data.zero_keccak_hash_table[self.m_page_log2_size + i]
                root = cartesi.keccak(root, right)
            end
        end
        return root
    else
        return self.m_context[depth]
    end

end

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
    return
        (str:gsub('..', function(cc) return string.char(tonumber(cc, 16)) end))
end

function test_util.tohex(str)
    return (str:gsub('.', function(c)
        return string.format('%02X', string.byte(c))
    end))
end

function test_util.split_string(inputstr, sep)
    if sep == nil then sep = "%s" end
    local t = {}
    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end
    return t
end

function  test_util.check_proof(proof)
    local hash = proof.target_hash
    for log2_size = proof.log2_target_size, proof.log2_root_size-1 do
        local bit = (proof.target_address & (1 << log2_size)) ~= 0
        local first, second
        if bit then
            first, second = proof.sibling_hashes[proof.log2_root_size-log2_size], hash
        else
            first, second = hash, proof.sibling_hashes[proof.log2_root_size-log2_size]
        end
        hash = cartesi.keccak(first, second)
    end
    return hash == proof.root_hash
end

function test_util.align(v, el) return (v >> el << el) end


-- Calculate root hash for data buffer of log2_size
function test_util.calculate_root_hash(data, log2_size)
    if log2_size < test_util.hash.LOG2_WORD_SIZE then
        error("Wrong data size", 2)
    elseif log2_size > test_util.hash.LOG2_WORD_SIZE then
        log2_size = log2_size - 1
        local sz = math.ceil(data:len() / 2)
        local child1 =
            test_util.calculate_root_hash(data:sub(1, sz), log2_size)
        local child2 = test_util.calculate_root_hash(data:sub(sz + 1,
                                                               data:len()),
                                                      log2_size)
        local hash = cartesi.keccak(child1, child2)
        return hash
    else
        local hash = cartesi.keccak(data)
        return hash
    end
end

-- Taking memory region in buffer data_buffer, and occuping data_number_of_pages
-- of page size page_log2_size
-- calculate merke hash for region of up to tree_log2_size,
-- using zero sibling hashes where needed
function test_util.calculate_region_hash(data_buffer, data_number_of_pages,
                                          page_log2_size, tree_log2_size)

    local page_size = 2 ^ page_log2_size

    local incremental_tree = test_util.incremental_merkle_tree_of_pages:new({},
                                                                             page_log2_size,
                                                                             tree_log2_size)

    for i = 0, data_number_of_pages - 1 do
        local current_page_data = data_buffer:sub(i * page_size + 1,
                                                  (i + 1) * page_size)
        local current_page_hash = test_util.calculate_root_hash(
                                      current_page_data, page_log2_size)
        incremental_tree:add_page(current_page_hash)
    end

    local root_hash = incremental_tree:get_root_hash()

    return root_hash
end

-- Take data hash of some region and extend it with pristine space
-- up to tree_log2_size, calculating target hash
function test_util.extend_region_hash(data_hash, data_address, data_log2_size,
                                       tree_log2_size)

    local result_hash = data_hash
    local result_address = data_address
    for n = data_log2_size + 1, tree_log2_size do
        if result_address % (2 ^ n) == 0 then
            local child1 = result_hash
            local child2 = test_util.fromhex(
                               test_data.zero_keccak_hash_table[n - 1])
            result_hash = cartesi.keccak(child1, child2)
        else
            local child1 = test_util.fromhex(
                               test_data.zero_keccak_hash_table[n - 1])
            local child2 = result_hash
            result_hash = cartesi.keccak(child1, child2)
            result_address = result_address & (~0x01 << (n - 1))
            -- print("calculated level: ",n," value: ", test_util.tohex(result_hash))
        end
    end

    return result_hash
end

-- Taking memory region with starting data_address and log2_data_size
-- calculate merke hash for region of up to log2_result_address_space,
-- using zero sibling hashes where needed. Data_address may not be aligned
-- to the beginning of the log2_result_address_space
function test_util.calculate_region_hash_2(data_address, data_buffer,
                                            log2_data_size,
                                            log2_result_address_space)

    data_address = data_address & (~0x01 << (log2_data_size - 1))

    local data_hash =
        test_util.calculate_root_hash(data_buffer, log2_data_size)

    local result_hash = data_hash
    local result_address = data_address
    for n = log2_data_size + 1, log2_result_address_space do
        if result_address % (2 ^ n) == 0 then
            local child1 = result_hash
            local child2 = test_util.fromhex(
                               test_data.zero_keccak_hash_table[n - 1])
            result_hash = cartesi.keccak(child1, child2)
        else
            local child1 = test_util.fromhex(
                               test_data.zero_keccak_hash_table[n - 1])
            local child2 = result_hash
            result_hash = cartesi.keccak(child1, child2)
            result_address = result_address & (~0x01 << (n - 1))
        end
    end

    return result_hash

end

return test_util
