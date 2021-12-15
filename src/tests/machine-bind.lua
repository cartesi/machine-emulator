#!/usr/bin/env lua5.3

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
--
-- Note: for grpc machine test to work, remote-cartesi-machine must run on
-- same computer and remote-cartesi-machine execution path must be provided

local cartesi = require "cartesi"
local cartesi_util = require "cartesi.util"
local test_util = require "tests.util"
local test_data = require "tests.data"


local remote_address = nil
local checkin_address = nil
local test_path = "./"
local cleanup = {}

local lua_cmd = arg[-1] .. " -e "

-- Print help and exit
local function help()
    io.stderr:write(string.format([=[
Usage:

  %s <machine_type> [options]

where options are:

  --remote-address=<address>
    run tests on a remote cartesi machine (when machine type is grpc).
    (requires --checkin-address)

  --checkin-address=<address>
    address of the local checkin server to run

  --test-path=<dir>
    path to test execution folder. In case of grpc tests, path must be
    working directory of remote-cartesi-machine and must be locally readable
    (default: "./")

<address> is one of the following formats:
  <host>:<port>
   unix:<path>

<host> can be a host name, IPv4 or IPv6 address.
]=], arg[0]))
    os.exit()
end


local options = {
    { "^%-%-h$", function(all)
        if not all then return false end
        help()
    end },
    { "^%-%-help$", function(all)
        if not all then return false end
        help()
    end },
    { "^%-%-remote%-address%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        remote_address = o
        return true
    end },
    { "^%-%-checkin%-address%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        checkin_address = o
        return true
    end },
    { "^%-%-test%-path%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        test_path = o
        return true
    end },
    { ".*", function(all)
        error("unrecognized option " .. all)
    end }
}

-- Process command line options
local arguments = {}
for i, argument in ipairs({...}) do
    if argument:sub(1,1) == "-" then
        for j, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        arguments[#arguments+1] = argument
    end
end

local machine_type = assert(arguments[1], "missing machine type")
assert(machine_type == "local" or machine_type == "grpc", "unknown machine type, should be 'local' or 'grpc'")
if (machine_type == "grpc") then
    assert(remote_address ~= nil, "remote cartesi machine address is missing")
    assert(test_path ~= nil, "test path must be provided and must be working directory of remote cartesi machine")
end
if remote_address then
    assert(checkin_address, "missing checkin address")
    cartesi.grpc = require("cartesi.grpc")
end

local function connect()
    local remote = cartesi.grpc.stub(remote_address, checkin_address)
    local version = assert(remote.get_version(),
        "could not connect to remote cartesi machine at " .. remote_address)
    local shutdown = function() remote.shutdown() end
    local mt = { __gc = function() pcall(shutdown) end}
    setmetatable(cleanup, mt)
    return remote, version
end

local pmas_file_names = {}
pmas_file_names["0000000000000000--0000000000001000.bin"] = 4096
pmas_file_names["0000000000001000--000000000000f000.bin"] = 61440
pmas_file_names["0000000002000000--00000000000c0000.bin"] = 12288
pmas_file_names["0000000040008000--0000000000001000.bin"] = 4096
pmas_file_names["0000000080000000--0000000000100000.bin"] = 1048576

local function build_machine(type)
    -- Create new machine
    local concurrency_update_merkle_tree = 0
    local initial_csr_values = test_data.get_cpu_csr_test_values()
    local initial_xreg_values = test_data.get_cpu_xreg_test_values()
    initial_csr_values.x = initial_xreg_values

    local config = {
        processor = initial_csr_values,
        rom = {image_filename = test_util.images_path .. "rom.bin"},
        ram = {length = 1 << 20},
    }
    local runtime = {
        concurrency = {
            update_merkle_tree = concurrency_update_merkle_tree
        }
    }

    local new_machine = nil
    if (type == "grpc") then
        if not remote then remote = connect() end
        new_machine = assert(remote.machine(config, runtime))
    else
        new_machine = assert(cartesi.machine(config, runtime))
    end

    initial_csr_values.x = nil
    initial_csr_values.mvendorid = nil
    initial_csr_values.marchid = nil
    initial_csr_values.mimpid = nil
    return new_machine
end

local do_test = test_util.make_do_test(build_machine, machine_type)

print("Testing machine bindings for type " .. machine_type)

print("\n\ntesting machine initial flags")
do_test("machine should not have halt and yield initial flags set",
    function(machine)
        -- Check machine is not halted
        assert(not machine:read_iflags_H(), "machine shouldn't be halted")
        -- Check machine is not yielded
        assert(not machine:read_iflags_Y(), "machine shouldn't be yielded")
    end
)

print("\n\ntesting machine register initial flag values ")
do_test("machine should have default config shadow register values",
    function(machine)
        local initial_csr_values = test_data.get_cpu_csr_test_values()
        local initial_xreg_values = test_data.get_cpu_xreg_test_values()
        initial_csr_values.x = nil
        initial_csr_values.mvendorid = nil
        initial_csr_values.marchid = nil
        initial_csr_values.mimpid = nil
        -- Check initialization and shadow reads
        for _, v in pairs(initial_csr_values) do
            local r = machine:read_word(v)
            assert(v == r)
        end
        for _, v in pairs(initial_xreg_values) do
            local r = machine:read_word(v)
            assert(v == r)
        end
    end
)

print("\n\ntesting merkle tree get_proof for values for registers")
do_test("should provide proof for values in registers", 
    function(machine)
        -- Update merkle tree
        machine:update_merkle_tree()

        local initial_csr_values = test_data.get_cpu_csr_test_values()
        local initial_xreg_values = test_data.get_cpu_xreg_test_values()
        initial_csr_values.x = nil
        initial_csr_values.mvendorid = nil
        initial_csr_values.marchid = nil
        initial_csr_values.mimpid = nil

        -- Check proofs
        for _, v in pairs(initial_csr_values) do
            for el = 3, 63 do
                local a = test_util.align(v, el)
                assert(test_util.check_proof(assert(machine:get_proof(a, el)),
                                            "no proof"), "proof failed")
            end
        end

        for _, v in pairs(initial_xreg_values) do
            for el = 3, 63 do
                local a = test_util.align(v, el)
                assert(test_util.check_proof(
                        assert(machine:get_proof(a, el), "no proof")),
                    "proof failed")
            end
        end
    end
)

print("\n\ntesting get_csr_address function binding")
do_test("should return address value for csr register", 
    function(machine)
        -- Check CSR address
        for _, v in pairs(test_data.get_cpu_csr_names()) do
            print(v)
            assert(cartesi.machine.get_csr_address(v), "missing " .. v)
        end
    end
)

print("\n\n test verifying integrity of the merkle tree")
do_test("verify_merkle_tree should return true", 
    function(machine)
        -- Update merkle tree
        machine:update_merkle_tree()
        -- Verify starting merkle tree
        assert(machine:verify_merkle_tree(), "error, non consistent merkle tree")
    end
)

print("\n\n test calculation of initial root hash")
do_test("should return expected value",
    function(machine)
        -- Update merkle tree
        machine:update_merkle_tree()
        -- Get starting root hash
        local root_hash = machine:get_root_hash()
        print("Root hash: ", test_util.tohex(root_hash))
        assert(test_util.tohex(root_hash) ==
                "38CCB889CD4148A4A154755DE8EDBD7C0B2219F880A7B5687AD957F96BD51DDB",
            "initial root hash does not match")
    end
)

print("\n\n test get_initial_config")
do_test("should have expected values",
    function(machine)
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
        assert(initial_config.htif.yield_automatic == false,
            "wrong htif yield automatic initial config value")
        assert(initial_config.htif.yield_manual == false,
            "wrong htif yield manual initial config value")
        assert(initial_config.rom.image_filename == test_util.images_path .. "rom.bin",
            "wrong initial config image path name")
    end
)

print("\n\n test read_csr")
do_test("should return expected values",
    function(machine)
        local initial_csr_values = test_data.get_cpu_csr_test_values()
        initial_csr_values.mvendorid = 0x6361727465736920
        initial_csr_values.marchid = 0x9
        initial_csr_values.mimpid = 0x1
        initial_csr_values.htif_tohost = 0x0
        initial_csr_values.htif_fromhost = 0x0
        initial_csr_values.htif_ihalt = 0x0
        initial_csr_values.htif_iconsole = 0x0
        initial_csr_values.htif_iyield = 0x0
        initial_csr_values.dhd_tstart = 0x0
        initial_csr_values.dhd_tlength = 0x0
        initial_csr_values.dhd_dlength = 0x0
        initial_csr_values.dhd_hlength = 0x0

        -- Check csr register read
        local to_ignore = {
            iflags = true,
            clint_mtimecmp = true,
            htif_ihalt = true,
            htif_iconsole = true
        }
        for k, v in pairs(test_data.get_cpu_csr_names()) do
            if not to_ignore[v] then
                local method_name = "read_" .. v
                local value = machine[method_name](machine)
                -- print("Reading k=",k, " value=", value, " v=",v, " expected value:",initial_csr_values[v])
                assert(machine[method_name](machine) == initial_csr_values[v],
                    "wrong " .. v .. " value")
            end
        end
    end
)

print("\n\n dump pmas to files")
do_test("there should exist dumped files of expected size", 
    function(machine)
        -- Dump pmas to files
        machine:dump_pmas()

        for file_name, file_size in pairs(pmas_file_names) do
            local dumped_file = test_path .. file_name
            local fd = io.open(dumped_file, "rb")
            local real_file_size = fd:seek("end")
            fd:close(dumped_file)

            assert(real_file_size == file_size,
                "unexpected pmas file size" .. dumped_file)

            assert(test_util.file_exists(dumped_file),
                "dumping pmas to file failed " .. dumped_file)

            os.remove(dumped_file)
        end
    end
)


print("\n\n read and write x registers")
do_test("writen and expected register values should match", 
    function(machine)
        local initial_xreg_values = test_data.get_cpu_xreg_test_values()
        -- Write/Read X registers
        local x1_initial_value = machine:read_x(1)
        assert(x1_initial_value == initial_xreg_values[1], "error reading x1 register")
        machine:write_x(1, 0x1122)
        assert(machine:read_x(1) == 0x1122, "error with writing to x1 register")
        machine:write_x(1, x1_initial_value)
        assert(machine:read_x(1) == x1_initial_value)
        -- Read unexsisting register
        local status_invalid_reg, retval = pcall(machine.read_x, machine, 1000)
        assert(status_invalid_reg == false, "no error reading invalid x register")
    end
)

print("\n\n read and write csr registers")
do_test("writen and expected register values should match", 
    function(machine)
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
    end
)

print("\n\n perform step and check mcycle register")
do_test("mcycle value should match", 
    function(machine)
        local log_type = {}
        local mcycle_initial_value = machine:read_csr('mcycle')

        machine:step(log_type)

        -- Check mcycle increment
        local mcycle_current_value = machine:read_csr('mcycle')
        assert(mcycle_current_value == mcycle_initial_value + 1,
            "wrong mcycle value")
    end
)

print("\n\n run machine to 1000 mcycle")
do_test("mcycle value should be 1000 after execution", 
    function(machine)
        -- Run machine
        machine:write_csr('mcycle', 0)
        assert(machine:read_csr('mcycle') == 0)

        local test = machine:read_mcycle()
        while test < 1000 do
            machine:run(1000)
            test = machine:read_mcycle()
        end
        assert(machine:read_csr('mcycle') == 1000)
    end
)

print("\n\n check reading and writing htif registers")
do_test("htif register values should match", 
    function(machine)
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
    end
)

print("\n\n check memory reading/writing")
do_test("written and read values should match", 
    function(machine)
        -- Check mem write and mem read
        local memory_read = machine:read_memory(0x80000000, 0x8)
        machine:write_memory(0x800000FF, "mydataol12345678", 0x10)
        memory_read = machine:read_memory(0x800000FF, 0x10)
        assert(memory_read == "mydataol12345678")

    end
)

print("\n\n dump register values to console")
do_test("dumped register values should match", 
    function(machine)
        -- Dump regs and check values
        local lua_code = [[ "local cartesi = require 'cartesi'
                                 test_util = require 'tests.util'

                                 local initial_csr_values = {}

                                 local machine = cartesi.machine {
                                 processor = initial_csr_values,
                                 ram = {length = 1 << 20},
                                 rom = {image_filename = test_util.images_path .. 'rom.bin'}
                                 }
                                 machine:dump_regs()
                                 " 2>&1]]
        local p = io.popen(lua_cmd .. lua_code)
        local output = p:read(2000)
        p:close()

        print("Output of dump registers:")
        print("--------------------------")
        print(output)
        print("--------------------------")
        assert((output:find "mcycle = 0"),
            "Cound not find mcycle register value in output")
        assert((output:find "marchid = 9"),
            "Cound not find marchid register value in output")
        assert((output:find "clint_mtimecmp = 0"),
            "Cound not find clint_mtimecmp register value in output")
    end
)

print("\n\n dump log  to console")
do_test("dumped log content should match", 
    function(machine)
        -- Dump log and check values
        local lua_code = [[ "
                                 local cartesi = require 'cartesi'
                                 test_util = require 'tests.util'
                                 cartesi_util = require 'cartesi.util'

                                 local initial_csr_values = {}

                                 local machine = cartesi.machine {
                                 processor = initial_csr_values,
                                 ram = {length = 1 << 20},
                                 rom = {image_filename = test_util.images_path .. 'rom.bin'}
                                 }
                                 local log_type = {}
                                 local log = machine:step(log_type)
                                 cartesi_util.dump_log(log, io.stdout)
                                 " 2>&1]]
        local p = io.popen(lua_cmd .. lua_code)
        local output = p:read(2000)
        p:close()

        print("Output of dump log:")
        print("--------------------------")
        print(output)
        print("--------------------------")
        assert((output:find "1: read @0x120%(288%)"), "Cound not find step 1 ")
        assert((output:find "14: read @0x810%(2064%): 0x1069%(4201%)"),
            "Cound not find step 14")
        assert((output:find "22: write @0x120%(288%): 0x0%(0%) %-> 0x1%(1%)"),
            "Cound not find step 20")
    end
)

print("\n\nAll machine binding tests for type " .. machine_type .. " passed")

