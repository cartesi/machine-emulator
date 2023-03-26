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

local SHADOW_BASE = 0x0

local cpu_x_addr = {}
local cpu_f_addr = {}
for i=0,31 do
    cpu_x_addr[i] = i * 8
    cpu_f_addr[i] = 0x100 + i * 8
end

local function get_cpu_xreg_test_values()
    local values = {}
    for i=0,31 do
        values[i] = i * 8
    end
    return values
end

local cpu_csr_addr = {
    pc = 512,
    fcsr = 520,
    mvendorid = 528,
    marchid = 536,
    mimpid = 544,
    mcycle = 552,
    icycleinstret = 560,
    mstatus = 568,
    mtvec = 576,
    mscratch = 584,
    mepc = 592,
    mcause = 600,
    mtval = 608,
    misa = 616,
    mie = 624,
    mip = 632,
    medeleg = 640,
    mideleg = 648,
    mcounteren = 656,
    menvcfg = 664,
    stvec = 672,
    sscratch = 680,
    sepc = 688,
    scause = 696,
    stval = 704,
    satp = 712,
    scounteren = 720,
    senvcfg = 728,
    ilrsc = 736,
    iflags = 744,
    clint_mtimecmp = 752,
    htif_tohost = 760,
    htif_fromhost = 768,
    htif_ihalt = 776,
    htif_iconsole = 784,
    htif_iyield = 792,
}

local function get_cpu_csr_test_values()
    return {
        pc = 0x200,
        mvendorid = -1,
        marchid = -1,
        mimpid = -1,
        mcycle = 0x220,
        icycleinstret = 0x228,
        mstatus = 0x230,
        mtvec = 0x238,
        mscratch = 0x240,
        mepc = 0x248,
        mcause = 0x250,
        mtval = 0x258,
        misa = 0x260,
        mie = 0x268,
        mip = 0x270,
        medeleg = 0x278,
        mideleg = 0x280,
        mcounteren = 0x288,
        menvcfg = 0x290,
        stvec = 0x298,
        sscratch = 0x2a0,
        sepc = 0x2a8,
        scause = 0x2b0,
        stval = 0x2b8,
        satp = 0x2c0,
        scounteren = 0x2c8,
        senvcfg = 0x2d0,
        fcsr = 0x61,
        ilrsc = 0x2e0,
    }
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

local pmas_file_names = {
    "0000000000000000--0000000000001000.bin", -- shadow state
    "0000000000001000--000000000000f000.bin", -- rom
    "0000000000010000--0000000000001000.bin", -- shadow pmas
    "0000000000020000--0000000000006000.bin", -- shadow tlb
    "0000000002000000--00000000000c0000.bin", -- clint
    "0000000040008000--0000000000001000.bin", -- htif
    "0000000080000000--0000000000100000.bin", -- ram
    "0000000070000000--0000000000010000.bin"  -- uarch ram
}
local pmas_sizes = { 4096, 61440, 4096, 24576, 786432, 4096, 1048576, 65536, 65536}

local function build_machine(type)
    -- Create new machine
    local concurrency_update_merkle_tree = 0
    local initial_csr_values = get_cpu_csr_test_values()
    local initial_xreg_values = get_cpu_xreg_test_values()
    initial_csr_values.x = initial_xreg_values
    local config = {
        processor = initial_csr_values,
        rom = {image_filename = test_util.images_path .. "rom.bin"},
        ram = {length = 1 << 20},
        uarch = { 
            ram = { length = 1 << 16, image_filename = test_util.create_test_uarch_program() },
        }
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
    os.remove(config.uarch.ram.image_filename)
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
        local initial_csr_values = get_cpu_csr_test_values()
        local initial_xreg_values = get_cpu_xreg_test_values()
        initial_csr_values.x = nil
        initial_csr_values.mvendorid = nil
        initial_csr_values.marchid = nil
        initial_csr_values.mimpid = nil
        -- Check initialization and shadow reads
        for k, v in pairs(initial_csr_values) do
            local r = machine:read_word(cpu_csr_addr[k])
            assert(v == r)
        end
        for k, v in pairs(initial_xreg_values) do
            local r = machine:read_word(cpu_x_addr[k])
            assert(v == r)
        end
    end
)

print("\n\ntesting merkle tree get_proof for values for registers")
do_test("should provide proof for values in registers",
    function(machine)
        local initial_csr_values = get_cpu_csr_test_values()
        local initial_xreg_values = get_cpu_xreg_test_values()
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
        local module = cartesi
        if (type == "grpc") then
            if not remote then remote = connect() end
            module = remote
        end
        -- Check CSR address
        for k, v in pairs(cpu_csr_addr) do
            local u = module.machine.get_csr_address(k)
            assert(u == v, "invalid return for " .. v)
        end
    end
)

print("\n\ntesting get_x_address function binding")
do_test("should return address value for x registers",
    function(machine)
        local module = cartesi
        if (type == "grpc") then
            if not remote then remote = connect() end
            module = remote
        end
        -- Check x address
        for i = 0,31 do
            assert(module.machine.get_x_address(i) == SHADOW_BASE+i*8, "invalid return for x"..i)
        end
    end
)

local function test_config_memory_range(range, name)
    assert(type(range.length) == "number", "invalid "..name..".length")
    assert(type(range.start) == "number", "invalid "..name..".start")
    assert(range.shared == nil or type(range.shared) == "boolean", "invalid "..name..".shared")
    assert(range.image_filename == nil or type(range.image_filename) == "string", "invalid "..name..".image_filename")
end

local function test_config(config)
    assert(type(config) == "table", "config not a table")
    for _, field in ipairs{"processor", "htif", "clint", "flash_drive", "ram", "rom"} do
        assert(config[field] and type(config[field]) == 'table', "invalid field " .. field)
    end
    local processor = config.processor
    for i = 1, 31 do
        assert(type(config.processor.x[i]) == "number", "x"..i.." is not a number")
    end
    local htif = config.htif
    for _, field in ipairs{"console_getchar", "yield_manual", "yield_automatic"} do
        assert(htif[field] == nil or type(htif[field]) == "boolean", "invalid htif."..field)
    end
    assert(type(htif.tohost) == "number", "invalid htif.tohost")
    assert(type(htif.fromhost) == "number", "invalid htif.fromhost")
    local clint = config.clint
    assert(type(clint.mtimecmp) == "number", "invalid clint.mtimecmp")
    local ram = config.ram
    assert(type(ram.length) == "number", "invalid ram.length")
    assert(ram.image_filename == nil or type(ram.image_filename) == "string", "invalid ram.image_filename")
    local rom = config.rom
    assert(rom.image_filename == nil or type(rom.image_filename) == "string", "invalid rom.image_filename")
    assert(rom.bootargs == nil or type(rom.bootargs) == "string", "invalid rom.bootargs")
    local tlb = config.tlb
    assert(tlb.image_filename == nil or type(tlb.image_filename) == "string", "invalid tlb.image_filename")
    for i, f in ipairs(config.flash_drive) do
        test_config_memory_range(f)
    end
    local rollup = config.rollup
    if config.rollup then
        test_config_memory_range(rollup.rx_buffer)
        test_config_memory_range(rollup.tx_buffer)
        test_config_memory_range(rollup.input_metadata)
        test_config_memory_range(rollup.voucher_hashes)
        test_config_memory_range(rollup.notice_hashes)
    end
end

print("\n\ntesting get_default_config function binding")
do_test("should return default machine config",
    function(machine)
        local module = cartesi
        if (type == "grpc") then
            if not remote then remote = connect() end
            module = remote
        end
        test_config(module.machine.get_default_config())
    end
)

print("\n\n test verifying integrity of the merkle tree")
do_test("verify_merkle_tree should return true",
    function(machine)
        -- Verify starting merkle tree
        assert(machine:verify_merkle_tree(), "error, non consistent merkle tree")
    end
)

print("\n\n test calculation of initial root hash")
do_test("should return expected value",
    function(machine)
        -- Get starting root hash
        local root_hash = machine:get_root_hash()
        print("Root hash: ", test_util.tohex(root_hash))

        machine:dump_pmas()
        local calculated_root_hash = test_util.calculate_emulator_hash(test_path,
                                                pmas_file_names, machine)
        for _, file_name in pairs(pmas_file_names) do
            os.remove(test_path .. file_name)
        end

        assert(test_util.tohex(root_hash) == test_util.tohex(calculated_root_hash),
            "initial root hash does not match")
    end
)

print("\n\n test get_initial_config")
do_test("should have expected values",
    function(machine)
        -- Check initial config
        local initial_config = machine:get_initial_config()
        test_config(initial_config)
        assert(initial_config.processor.pc == 0x200,
            "wrong pc reg initial config value")
        assert(initial_config.processor.ilrsc == 0x2e0,
            "wrong ilrsc reg initial config value")
        assert(initial_config.processor.mstatus == 0x230,
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
        local initial_csr_values = get_cpu_csr_test_values()
        initial_csr_values.mvendorid = 0x6361727465736920
        initial_csr_values.marchid = 0xe
        initial_csr_values.mimpid = 0x1
        initial_csr_values.htif_tohost = 0x0
        initial_csr_values.htif_fromhost = 0x0
        initial_csr_values.htif_ihalt = 0x0
        initial_csr_values.htif_iconsole = 0x0
        initial_csr_values.htif_iyield = 0x0

        -- Check csr register read
        local to_ignore = {
            iflags = true,
            clint_mtimecmp = true,
            htif_ihalt = true,
            htif_iconsole = true,
        }
        for k in pairs(cpu_csr_addr) do
            if not to_ignore[k] then
                local method_name = "read_" .. k
                assert(machine[method_name](machine) == initial_csr_values[k],
                    "wrong " .. k .. " value")
            end
        end
    end
)

print("\n\n dump pmas to files")
do_test("there should exist dumped files of expected size",
    function(machine)
        -- Dump pmas to files
        machine:dump_pmas()

        for i = 1, #pmas_file_names do
            local dumped_file = test_path .. pmas_file_names[i]
            local fd = assert(io.open(dumped_file, "rb"))
            local real_file_size = fd:seek("end")
            fd:close(dumped_file)

            assert(real_file_size == pmas_sizes[i],
                "unexpected pmas file size " .. dumped_file)

            assert(test_util.file_exists(dumped_file),
                "dumping pmas to file failed " .. dumped_file)

            os.remove(dumped_file)
        end
    end
)


print("\n\n read and write x registers")
do_test("writen and expected register values should match",
    function(machine)
        local initial_xreg_values = get_cpu_xreg_test_values()
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
        local uarch_cycle_initial_value = machine:read_csr('uarch_cycle')

        machine:uarch_step(log_type)

        -- Check mcycle increment
        local uarch_cycle_current_value = machine:read_csr('uarch_cycle')
        assert(uarch_cycle_current_value == uarch_cycle_initial_value + 1,
            "wrong uarch_cycle value")
    end
)

print("\n\n uarch_run tests")
do_test("advance one micro cycle without halting",
    function(machine)
        assert(machine:read_uarch_cycle() == 0, "uarch cycle should be 0")
        assert(machine:read_uarch_halt_flag() == false, "machine should not be halted")
        local status = machine:uarch_run(1)
        assert(status == cartesi.UARCH_REACHED_TARGET_CYCLE)
        assert(machine:read_uarch_cycle() == 1, "uarch cycle should be 1")
        assert(machine:read_uarch_halt_flag() == false, "machine should not be halted")
    end
)

do_test("advance micro cycles until halt",
    function(machine)
        assert(machine:read_uarch_cycle() == 0, "uarch cycle should be 0")
        assert(machine:read_uarch_halt_flag() == false, "machine should not be halted")
        local status = machine:uarch_run(100)
        assert(status == cartesi.UARCH_HALTED)
        assert(machine:read_uarch_cycle() == 5, "uarch cycle should be 5")
        assert(machine:read_uarch_halt_flag() == true, "machine should be halted")
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
        assert((output:find "marchid = e"),
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
                                 local uarch_ram_path = test_util.create_test_uarch_program()
                                 local machine = cartesi.machine {
                                 processor = initial_csr_values,
                                 ram = {length = 1 << 20},
                                 rom = {image_filename = test_util.images_path .. 'rom.bin'},
                                 uarch = { 
                                    ram = { length = 1 << 16, image_filename = uarch_ram_path }
                                 }
                                 }
                                 os.remove(uarch_ram_path)
                                 local log_type = {proofs = false, annotations = true}
                                 local log = machine:uarch_step(log_type)
                                 cartesi_util.dump_log(log, io.stdout)
                                 " 2>&1]]
        local p = io.popen(lua_cmd .. lua_code)
        local output = p:read(2000)
        p:close()
        local expected_output = 
            "begin step\n" ..
            "  1: read uarch.cycle@0x320(800): 0x0(0)\n" ..
            "  2: read uarch.halt_flag@0x328(808): 0x0(0)\n" ..
            "  3: read uarch.pc@0x330(816): 0x70000000(1879048192)\n" ..
            "  4: read memory@0x70000000(1879048192): 0x7ffff2b707b00513(9223357429799978259)\n" ..
            "  begin addi\n" ..
            "    5: read uarch.x@0x340(832): 0x0(0)\n" ..
            "    6: write uarch.x@0x390(912): 0x0(0) -> 0x7b(123)\n" ..
            "    7: write uarch.pc@0x330(816): 0x70000000(1879048192) -> 0x70000004(1879048196)\n" ..
            "  end addi\n" ..
            "  8: write uarch.cycle@0x320(800): 0x0(0) -> 0x1(1)\n" ..
            "end step\n"

        print("Output of dump log:")
        print("--------------------------")
        print(output)
        print("--------------------------")
        assert(output == expected_output, "Output does not match expected output:\n"..expected_output)
    end
)

print("\n\ntesting step and verification")
do_test("machine step should pass verifications",
    function(machine)
        local module = cartesi
        if (type == "grpc") then
            if not remote then remote = connect() end
            module = remote
        end
        local initial_hash = machine:get_root_hash()
        local log = machine:uarch_step({proofs = true, annotations = true})
        local final_hash = machine:get_root_hash()
        module.machine.verify_state_transition(initial_hash, log, final_hash, {})
        module.machine.verify_access_log(log, {})
    end
)

print("\n\nAll machine binding tests for type " .. machine_type .. " passed")
