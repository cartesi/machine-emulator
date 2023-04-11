#!/usr/bin/env lua5.3

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

local zero_keccak_hash_table = {
    "",
    "",
    "011b4d03dd8c01f1049143cf9c4c817e4b167f1d1b83e5c6f0f10d89ba1e7bce", -- 3
    "4d9470a821fbe90117ec357e30bad9305732fb19ddf54a07dd3e29f440619254", -- 4
    "ae39ce8537aca75e2eff3e38c98011dfe934e700a0967732fc07b430dd656a23", -- 5
    "3fc9a15f5b4869c872f81087bb6104b7d63e6f9ab47f2c43f3535eae7172aa7f", -- 6
    "17d2dd614cddaa4d879276b11e0672c9560033d3e8453a1d045339d34ba601b9", -- 7
    "c37b8b13ca95166fb7af16988a70fcc90f38bf9126fd833da710a47fb37a55e6", -- 8
    "8e7a427fa943d9966b389f4f257173676090c6e95f43e2cb6d65f8758111e309", -- 9
    "30b0b9deb73e155c59740bacf14a6ff04b64bb8e201a506409c3fe381ca4ea90", -- 10
    "cd5deac729d0fdaccc441d09d7325f41586ba13c801b7eccae0f95d8f3933efe", -- 11
    "d8b96e5b7f6f459e9cb6a2f41bf276c7b85c10cd4662c04cbbb365434726c0a0", -- 12
    "c9695393027fb106a8153109ac516288a88b28a93817899460d6310b71cf1e61", -- 13
    "63e8806fa0d4b197a259e8c3ac28864268159d0ac85f8581ca28fa7d2c0c03eb", -- 14
    "91e3eee5ca7a3da2b3053c9770db73599fb149f620e3facef95e947c0ee860b7", -- 15
    "2122e31e4bbd2b7c783d79cc30f60c6238651da7f0726f767d22747264fdb046", -- 16
    "f7549f26cc70ed5e18baeb6c81bb0625cb95bb4019aeecd40774ee87ae29ec51", -- 17
    "7a71f6ee264c5d761379b3d7d617ca83677374b49d10aec50505ac087408ca89", -- 18
    "2b573c267a712a52e1d06421fe276a03efb1889f337201110fdc32a81f8e1524", -- 19
    "99af665835aabfdc6740c7e2c3791a31c3cdc9f5ab962f681b12fc092816a62f", -- 20
    "27d86025599a41233848702f0cfc0437b445682df51147a632a0a083d2d38b5e", -- 21
    "13e466a8935afff58bb533b3ef5d27fba63ee6b0fd9e67ff20af9d50deee3f8b", -- 22
    "f065ec220c1fd4ba57e341261d55997f85d66d32152526736872693d2b437a23", -- 23
    "3e2337b715f6ac9a6a272622fdc2d67fcfe1da3459f8dab4ed7e40a657a54c36", -- 24
    "766c5e8ac9a88b35b05c34747e6507f6b044ab66180dc76ac1a696de03189593", -- 25
    "fedc0d0dbbd855c8ead673544899b0960e4a5a7ca43b4ef90afe607de7698cae", -- 26
    "fdc242788f654b57a4fb32a71b335ef6ff9a4cc118b282b53bdd6d6192b7a82c", -- 27
    "3c5126b9c7e33c8e5a5ac9738b8bd31247fb7402054f97b573e8abb9faad219f", -- 28
    "4fd085aceaa7f542d787ee4196d365f3cc566e7bbcfbfd451230c48d804c017d", -- 29
    "21e2d8fa914e2559bb72bf0ab78c8ab92f00ef0d0d576eccdd486b64138a4172", -- 30
    "674857e543d1d5b639058dd908186597e366ad5f3d9c7ceaff44d04d1550b8d3", -- 31
    "3abc751df07437834ba5acb32328a396994aebb3c40f759c2d6d7a3cb5377e55", -- 32
    "d5d218ef5a296dda8ddc355f3f50c3d0b660a51dfa4d98a6a5a33564556cf83c", -- 33
    "1373a814641d6a1dcef97b883fee61bb84fe60a3409340217e629cc7e4dcc93b", -- 34
    "85d8820921ff5826148b60e6939acd7838e1d7f20562bff8ee4b5ec4a05ad997", -- 35
    "a57b9796fdcb2eda87883c2640b072b140b946bfdf6575cacc066fdae04f6951", -- 36
    "e63624cbd316a677cad529bbe4e97b9144e4bc06c4afd1de55dd3e1175f90423", -- 37
    "847a230d34dfb71ed56f2965a7f6c72e6aa33c24c303fd67745d632656c5ef90", -- 38
    "bec80f4f5d1daa251988826cef375c81c36bf457e09687056f924677cb0bccf9", -- 39
    "8dff81e014ce25f2d132497923e267363963cdf4302c5049d63131dc03fd95f6", -- 40
    "5d8b6aa5934f817252c028c90f56d413b9d5d10d89790707dae2fabb249f6499", -- 41
    "29927c21dd71e3f656826de5451c5da375aadecbd59d5ebf3a31fae65ac1b316", -- 42
    "a1611f1b276b26530f58d7247df459ce1f86db1d734f6f811932f042cee45d0e", -- 43
    "455306d01081bc3384f82c5fb2aacaa19d89cdfa46cc916eac61121475ba2e61", -- 44
    "91b4feecbe1789717021a158ace5d06744b40f551076b67cd63af60007f8c998", -- 45
    "76e1424883a45ec49d497ddaf808a5521ca74a999ab0b3c7aa9c80f85e93977e", -- 46
    "c61ce68b20307a1a81f71ca645b568fcd319ccbb5f651e87b707d37c39e15f94", -- 47
    "5ea69e2f7c7d2ccc85b7e654c07e96f0636ae4044fe0e38590b431795ad0f864", -- 48
    "7bdd613713ada493cc17efd313206380e6a685b8198475bbd021c6e9d94daab2", -- 49
    "214947127506073e44d5408ba166c512a0b86805d07f5a44d3c41706be2bc15e", -- 50
    "712e55805248b92e8677d90f6d284d1d6ffaff2c430657042a0e82624fa3717b", -- 51
    "06cc0a6fd12230ea586dae83019fb9e06034ed2803c98d554b93c9a52348caff", -- 52
    "f75c40174a91f9ae6b8647854a156029f0b88b83316663ce574a4978277bb6bb", -- 53
    "27a31085634b6ec78864b6d8201c7e93903d75815067e378289a3d072ae172da", -- 54
    "fa6a452470f8d645bebfad9779594fc0784bb764a22e3a8181d93db7bf97893c", -- 55
    "414217a618ccb14caa9e92e8c61673afc9583662e812adba1f87a9c68202d60e", -- 56
    "909efab43c42c0cb00695fc7f1ffe67c75ca894c3c51e1e5e731360199e600f6", -- 57
    "ced9a87b2a6a87e70bf251bb5075ab222138288164b2eda727515ea7de12e249", -- 58
    "6d4fe42ea8d1a120c03cf9c50622c2afe4acb0dad98fd62d07ab4e828a94495f", -- 59
    "6d1ab973982c7ccbe6c1fae02788e4422ae22282fa49cbdb04ba54a7a238c6fc", -- 60
    "41187451383460762c06d1c8a72b9cd718866ad4b689e10c9a8c38fe5ef045bd", -- 61
    "785b01e980fc82c7e3532ce81876b778dd9f1ceeba4478e86411fb6fdd790683", -- 62
    "916ca832592485093644e8760cd7b4c01dba1ccc82b661bf13f0e3f34acd6b88" -- 63
}

local function adjust_images_path(path)
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

function test_util.create_test_uarch_program() 
    local file_path = os.tmpname()
    local f = io.open(file_path, 'wb')
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
        local machine = build_machine(type, config)
        f(machine)
        machine:destroy()
        print("<<<<<<<<<<<<<<<< passed >>>>>>>>>>>>>>>")
    end
end

function test_util.disabled_test(description, f)
    print("Disabled test - "..description)
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
            zero_keccak_hash_table[self.m_page_log2_size])
        for i = 0, depth - 1 do
            if (self.m_page_count & (0x01 << i)) ~= 0 then
                local left = self.m_context[i]
                root = cartesi.keccak(left, root)
            else
                local right = test_util.fromhex(zero_keccak_hash_table[self.m_page_log2_size + i])
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

    local page_size = 1 << page_log2_size

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
        if result_address & ((1 << n)-1) == 0 then
            local child1 = result_hash
            local child2 = test_util.fromhex(zero_keccak_hash_table[n - 1])
            result_hash = cartesi.keccak(child1, child2)
        else
            local child1 = test_util.fromhex(zero_keccak_hash_table[n - 1])
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
        if result_address & ((1 << n)-1) == 0 then
            local child1 = result_hash
            local child2 = test_util.fromhex(zero_keccak_hash_table[n - 1])
            result_hash = cartesi.keccak(child1, child2)
        else
            local child1 = test_util.fromhex(zero_keccak_hash_table[n - 1])
            local child2 = result_hash
            result_hash = cartesi.keccak(child1, child2)
            result_address = result_address & (~0x01 << (n - 1))
        end
    end

    return result_hash

end

function test_util.parse_pma_file(filename)
    local fd = io.open(filename, "rb")
    if not fd then
        return ""
    end
    local data_size = fd:seek("end")
    fd:seek("set")
    local data = fd:read(data_size)
    fd:close(filename)
    return data
end

-- PMA defs
local PMA_SHADOW_STATE_LENGTH = 0x1000
local PMA_SHADOW_PMAS_LENGTH = 0x1000
local PMA_ROM_LENGTH = 0xF000
local PMA_SHADOW_TLB_START = 0x20000
local PMA_SHADOW_TLB_LENGTH = 0x6000
local PMA_CLINT_START = 0x2000000
local PMA_CLINT_LENGTH = 0xC0000
local PMA_HTIF_START = 0x40008000
local PMA_UARCH_RAM_START = 0x70000000
local PMA_RAM_START = 0x80000000
local PMA_PAGE_SIZE_LOG2 = 12
local PMA_PAGE_SIZE = 1 << PMA_PAGE_SIZE_LOG2

local function ceil_log2(x)
    return math.ceil(math.log(x, 2)) // 1
end

local extend_region_hash = test_util.extend_region_hash
local calculate_region_hash = test_util.calculate_region_hash
local calculate_region_hash_2 = test_util.calculate_region_hash_2

-- Take data from dumped memory files
-- and calculate root hash of the machine
function test_util.calculate_emulator_hash(test_path, pmas_files)
    local shadow_state = test_util.parse_pma_file(test_path .. pmas_files[1])
    local rom = test_util.parse_pma_file(test_path .. pmas_files[2])
    local shadow_pmas = test_util.parse_pma_file(test_path .. pmas_files[3])
    local shadow_tlb = test_util.parse_pma_file(test_path .. pmas_files[4])
    local clint = test_util.parse_pma_file(test_path .. pmas_files[5])
    local htif = test_util.parse_pma_file(test_path .. pmas_files[6])
    local ram = test_util.parse_pma_file(test_path .. pmas_files[7])
    local uarch_ram = ""
    if pmas_files[8] then
        uarch_ram = test_util.parse_pma_file(test_path .. pmas_files[8])
    end

    local shadow_rom = shadow_state .. rom .. shadow_pmas

    local shadow_rom_hash_size_log2 = ceil_log2(PMA_SHADOW_STATE_LENGTH + PMA_ROM_LENGTH + PMA_SHADOW_PMAS_LENGTH)
    local shadow_rom_space_hash = calculate_region_hash(shadow_rom,
        (#shadow_rom + PMA_PAGE_SIZE - 1) // PMA_PAGE_SIZE, PMA_PAGE_SIZE_LOG2, shadow_rom_hash_size_log2)
    shadow_rom_space_hash = extend_region_hash(shadow_rom_space_hash, 0, shadow_rom_hash_size_log2, 17)

    local tlb_size_log2 = ceil_log2(PMA_SHADOW_TLB_LENGTH)
    local tlb_space_hash =
        calculate_region_hash(shadow_tlb, (#shadow_tlb + PMA_PAGE_SIZE - 1) // PMA_PAGE_SIZE, PMA_PAGE_SIZE_LOG2, tlb_size_log2)
    tlb_space_hash = extend_region_hash(tlb_space_hash, PMA_SHADOW_TLB_START, tlb_size_log2, 17)

    local shadow_rom_tlb_space_hash = cartesi.keccak(shadow_rom_space_hash, tlb_space_hash) -- 18
    shadow_rom_tlb_space_hash =
        extend_region_hash(shadow_rom_tlb_space_hash, 0, 18, 25)

    local clint_size_log2 = ceil_log2(PMA_CLINT_LENGTH)
    local clint_space_hash =
        calculate_region_hash(clint, (#clint + PMA_PAGE_SIZE - 1) // PMA_PAGE_SIZE, PMA_PAGE_SIZE_LOG2, clint_size_log2)
    clint_space_hash = extend_region_hash(clint_space_hash, PMA_CLINT_START, clint_size_log2, 25)

    local shadow_rom_tlb_clint_hash = cartesi.keccak(shadow_rom_tlb_space_hash, clint_space_hash) -- 26
    shadow_rom_tlb_clint_hash = extend_region_hash(shadow_rom_tlb_clint_hash, 0, 26, 29)

    local htif_size_log2 = ceil_log2(#htif)
    local htif_space_hash = calculate_region_hash_2(PMA_HTIF_START, htif, htif_size_log2, 29)
    local left = cartesi.keccak(shadow_rom_tlb_clint_hash, htif_space_hash) -- 30
    local uarch_ram_space_hash = test_util.fromhex(zero_keccak_hash_table[30])
    if #uarch_ram > 0 then
        local uarch_ram_size_log2 = ceil_log2(#uarch_ram)
        uarch_ram_space_hash = calculate_region_hash(uarch_ram, (#uarch_ram + PMA_PAGE_SIZE - 1) // PMA_PAGE_SIZE, PMA_PAGE_SIZE_LOG2, uarch_ram_size_log2)
        uarch_ram_space_hash = extend_region_hash(uarch_ram_space_hash, PMA_UARCH_RAM_START, uarch_ram_size_log2, 30)
    end
    left = cartesi.keccak(left, uarch_ram_space_hash) -- 31

    local ram_size_log2 = ceil_log2(#ram)
    local ram_space_hash = calculate_region_hash_2(PMA_RAM_START, ram, ram_size_log2, 31)
    local used_space_hash = cartesi.keccak(left, ram_space_hash) -- 32

    return test_util.extend_region_hash(used_space_hash, 0, 32, 64)
end

return test_util
