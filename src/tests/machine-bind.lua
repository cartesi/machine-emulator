#!/usr/bin/env luapp5.3

-- Copyright 2019 Cartesi Pte. Ltd.
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
local cartesi_util = require "cartesi.util"
local test_utils = require "tests.utils"
local test_data = require "tests.data"


print("Testing machine bindings")

local pmas_file_names = {}
pmas_file_names["0000000000000000--0000000000001000.bin"] = 4096
pmas_file_names["0000000000001000--000000000000f000.bin"] = 61440
pmas_file_names["0000000002000000--00000000000c0000.bin"] = 12288
pmas_file_names["0000000040008000--0000000000001000.bin"] = 4096
pmas_file_names["0000000080000000--0000000000100000.bin"] = 1048576



local function build_machine()
    -- Create new machine

    local cpu_addr = test_data.get_cpu_addr()
    local cpu_addr_x = test_data.get_cpu_addrx()
    cpu_addr.x = cpu_addr_x

    local machine = cartesi.machine {
        processor = cpu_addr,
        ram = {length = 1 << 20},
        rom = {image_filename = test_utils.images_path .. "rom.bin"}
    }

    cpu_addr.x = nil
    cpu_addr.mvendorid = nil
    cpu_addr.marchid = nil
    cpu_addr.mimpid = nil
    return machine
end

local do_test = test_utils.make_do_test(build_machine)

print("\n\ntesting machine initial flags")
do_test("machine should not have halt and yield initial flags set",
        function(machine)

    -- Check machine is not halted
    assert(not machine:read_iflags_H(), "machine shouldn't be halted")

    -- Check machine is not yielded
    assert(not machine:read_iflags_Y(), "machine shouldn't be yielded")

end)

print("\n\ntesting machine register initial flag values ")
do_test("machine should have default config shadow register values",
        function(machine)

    local cpu_addr = test_data.get_cpu_addr()
    local cpu_addr_x = test_data.get_cpu_addrx()
    cpu_addr.x = nil
    cpu_addr.mvendorid = nil
    cpu_addr.marchid = nil
    cpu_addr.mimpid = nil

    -- Check initialization and shadow reads
    for _, v in pairs(cpu_addr) do
        local r = machine:read_word(v)
        assert(v == r)
    end

    for _, v in pairs(cpu_addr_x) do
        local r = machine:read_word(v)
        assert(v == r)
    end

end)

print("\n\ntesting merkle tree get_proof for values for registers")
do_test("should provide proof for values in registers", function(machine)

    -- Update merkle tree
    machine:update_merkle_tree()

    local cpu_addr = test_data.get_cpu_addr()
    local cpu_addr_x = test_data.get_cpu_addrx()
    cpu_addr.x = nil
    cpu_addr.mvendorid = nil
    cpu_addr.marchid = nil
    cpu_addr.mimpid = nil

    -- Check proofs
    for _, v in pairs(cpu_addr) do
        for el = 3, 63 do
            local a = test_utils.align(v, el)
            assert(test_utils.check_proof(assert(machine:get_proof(a, el)),
                                          "no proof"), "proof failed")
        end
    end

    for _, v in pairs(cpu_addr_x) do
        for el = 3, 63 do
            local a = test_utils.align(v, el)
            assert(test_utils.check_proof(
                       assert(machine:get_proof(a, el), "no proof")),
                   "proof failed")
        end
    end
end)

print("\n\ntesting get_csr_address function binding")
do_test("should return address value for csr register", function(machine)

    -- Check CSR address
    for _, v in pairs(test_data.get_cpu_reg_names()) do
        print(v)
        assert(cartesi.machine.get_csr_address(v), "missing " .. v)
    end
end)

print("\n\n test verifying integrity of the merkle tree")
do_test("verify_merkle_tree should return true", function(machine)
    -- Update merkle tree
    machine:update_merkle_tree()
    -- Verify starting merkle tree
    assert(machine:verify_merkle_tree(), "error, non consistent merkle tree")

end)

print("\n\n test calculation of initial root hash")
do_test("should return expected value", function(machine)
    -- Update merkle tree
    machine:update_merkle_tree()

    -- Get starting root hash
    local root_hash = machine:get_root_hash()
    print("Root hash: ", test_utils.tohex(root_hash))
    assert(test_utils.tohex(root_hash) ==
               "64E1EB3696A5E3D340D86BECD97A43831FC6CFB2E104F1C4CE8D597DC18A4348",
           "initial root hash does not match")

end)

print("\n\n test get_initial_config")
do_test("should have expected values", function(machine)

    -- Check initial config
    local initial_config = machine:get_initial_config()
    assert(initial_config.processor.pc == 0x100,
           "wrong pc reg initial config value")
    assert(initial_config.processor.ilrsc == 0x1c8,
           "wrong ilrsc reg initial config value")
    assert(initial_config.processor.mstatus == 0x130,
           "wrong mstatus reg initial config value")
    assert(initial_config.clint.mtimecmp == 0,
           "wrong clint mtimecmp initial config value")
    assert(initial_config.htif.fromhost == 0,
           "wrong htif fromhost initial config value")
    assert(initial_config.htif.tohost == 0,
           "wrong htif tohost initial config value")
    assert(initial_config.htif.yield_progress == false,
           "wrong htif yield progress initial config value")
    assert(initial_config.rom.image_filename == test_utils.images_path .. "rom.bin",
           "wrong initial config image path name")

end)

print("\n\n test read_csr")
do_test("should return expected values", function(machine)

    local cpu_addr = test_data.get_cpu_addr()
    cpu_addr.mvendorid = 0x6361727465736920
    cpu_addr.marchid = 0x7
    cpu_addr.mimpid = 0x1
    cpu_addr.htif_tohost = 0x0
    cpu_addr.htif_fromhost = 0x0
    cpu_addr.htif_ihalt = 0x0
    cpu_addr.htif_iconsole = 0x0
    cpu_addr.htif_iyield = 0x0
    cpu_addr.dhd_tstart = 0x0
    cpu_addr.dhd_tlength = 0x0
    cpu_addr.dhd_dlength = 0x0
    cpu_addr.dhd_hlength = 0x0

    -- Check csr register read
    local to_ignore = {
        iflags = true,
        clint_mtimecmp = true,
        htif_ihalt = true,
        htif_iconsole = true
    }
    for k, v in pairs(test_data.get_cpu_reg_names()) do
        if not to_ignore[v] then
            local method_name = "read_" .. v
            local value = machine[method_name](machine)
            -- print("Reading k=",k, " value=", value, " v=",v, " expected value:",cpu_addr[v])
            assert(machine[method_name](machine) == cpu_addr[v],
                   "wrong " .. v .. " value")
        end
    end

end)

print("\n\n dump pmas to files")
do_test("there should exist dumped files of expected size", function(machine)

    -- Dump pmas to files
    machine:dump_pmas()

    for file_name, file_size in pairs(pmas_file_names) do

        local fd = io.open(file_name, "rb")
        local real_file_size = fd:seek("end")
        fd:close(file_name)

        assert(real_file_size == file_size,
               "unexpected pmas file size" .. file_name)

        assert(test_utils.file_exists(file_name),
               "dumping pmas to file failed " .. file_name)

        os.remove(file_name)
    end

end)

print("\n\n read and write x registers")
do_test("writen and expected register values should match", function(machine)

    local cpu_addr_x = test_data.get_cpu_addrx()
    -- Write/Read X registers
    local x1_initial_value = machine:read_x(1)
    assert(x1_initial_value == cpu_addr_x[1], "error reading x1 register")
    machine:write_x(1, 0x1122)
    assert(machine:read_x(1) == 0x1122, "error with writing to x1 register")
    machine:write_x(1, x1_initial_value)
    assert(machine:read_x(1) == x1_initial_value)

    -- Read unexsisting register
    local status_invalid_reg, retval = pcall(machine.read_x, machine, 1000)
    assert(status_invalid_reg == false, "no error reading invalid x register")

end)

print("\n\n read and write csr registers")
do_test("writen and expected register values should match", function(machine)

    -- Check csr register write
    local sscratch_initial_value = machine:read_csr('sscratch')
    assert(machine:read_sscratch() == sscratch_initial_value,
           "error reading csr sscratch")
    machine:write_csr('sscratch', 0x1122)
    assert(machine:read_csr('sscratch') == 0x1122)
    machine:write_csr('sscratch', sscratch_initial_value)

    -- Read unexsisting register
    local status_invalid_reg, retval = pcall(machine.read_csr, machine, "invalidreg")
    assert(status_invalid_reg == false, "no error reading invalid csr register")
end)

print("\n\n perform step and check mcycle register")
do_test("mcycle value should match", function(machine)

    local log_type = {}
    local mcycle_initial_value = machine:read_csr('mcycle')

    machine:step(log_type)

    -- Check mcycle increment
    local mcycle_current_value = machine:read_csr('mcycle')
    assert(mcycle_current_value == mcycle_initial_value + 1,
           "wrong mcycle value")
end)

print("\n\n run machine to 1000 mcycle")
do_test("mcycle value should be 1000 after execution", function(machine)

    -- Run machine
    machine:write_csr('mcycle', 0)
    assert(machine:read_csr('mcycle') == 0)

    local test = machine:read_mcycle()
    while test < 1000 do
        machine:run(1000)
        test = machine:read_mcycle()
    end

    assert(machine:read_csr('mcycle') == 1000)

end)

print("\n\n check reading and writing htif registers")
do_test("htif register values should match", function(machine)

    -- Check HTIF interface bindings
    assert(machine:read_htif_tohost(), "error reading htif tohost")
    assert(machine:read_htif_tohost_dev(), "error reading htif tohost dev")
    assert(machine:read_htif_tohost_cmd(), "error reading htif tohost cmd")
    assert(machine:read_htif_tohost_data(), "error reading htif tohost data")
    assert(machine:read_htif_fromhost(), "error reading htif fromhost")

    machine:write_htif_tohost(0x123456)
    assert(machine:read_htif_tohost() == 0x123456, "error writing htif tohost")

    machine:write_htif_fromhost(0x12345678)
    assert(machine:read_htif_fromhost() == 0x12345678,
           "error writing htif fromhost")

    machine:write_htif_fromhost_data(0x123456789A)

    assert(machine:read_htif_ihalt(), "error reading htif ihalt")
    assert(machine:read_htif_iyield(), "error reading htif yield")

end)

print("\n\n check memory reading/writing")
do_test("written and read values should match", function(machine)

    -- Check mem write and mem read
    local memory_read = machine:read_memory(0x80000000, 0x8)
    machine:write_memory(0x800000FF, "mydataol12345678", 0x10)
    memory_read = machine:read_memory(0x800000FF, 0x10)
    assert(memory_read == "mydataol12345678")

end)

print("\n\n dump register values to console")
do_test("dumped register values should match", function(machine)

    -- Dump regs and check values
    local p = io.popen([[/opt/cartesi/bin/luapp5.3 -e "
    local cartesi = require 'cartesi'
    test_utils = require 'tests.utils'

    local cpu_addr = {}

    local machine = cartesi.machine {
       processor = cpu_addr,
       ram = {length = 1 << 20},
       rom = {image_filename = test_utils.images_path .. 'rom.bin'} 
    }
    machine:dump_regs()
    " 2>&1]])
    local output = p:read(2000)
    p:close()

    print("Output of dump registers:")
    print("--------------------------")
    print(output)
    print("--------------------------")
    assert((output:find "mcycle = 0"),
           "Cound not find mcycle register value in output")
    assert((output:find "marchid = 7"),
           "Cound not find marchid register value in output")
    assert((output:find "clint_mtimecmp = 0"),
           "Cound not find clint_mtimecmp register value in output")

end)

print("\n\n dump log  to console")
do_test("dumped log content should match", function(machine)

    -- Dump log and check values
    local p = io.popen([[/opt/cartesi/bin/luapp5.3 -e "
    local cartesi = require 'cartesi'
    test_utils = require 'tests.utils'
    cartesi_util = require 'cartesi.util'

    local cpu_addr = {}

    local machine = cartesi.machine {
       processor = cpu_addr,
       ram = {length = 1 << 20},
       rom = {image_filename = test_utils.images_path .. 'rom.bin'} 
    }
    local log_type = {}
    local log = machine:step(log_type)
    cartesi_util.dump_log(log, io.stdout)
    " 2>&1]])
    local output = p:read(2000)
    p:close()

    print("Output of dump log:")
    print("--------------------------")
    print(output)
    print("--------------------------")
    assert((output:find "1: read @0x120%(288%)"), "Cound not find step 1 ")
    assert((output:find "12: read @0x810%(2064%): 0x1069%(4201%)"),
           "Cound not find step 12")
    assert((output:find "20: write @0x120%(288%): 0x0%(0%) %-> 0x1%(1%)"),
           "Cound not find step 20")

end)

print("\n\nAll machine binding tests passed")

