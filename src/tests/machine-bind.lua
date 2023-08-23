#!/usr/bin/env lua5.4

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
local test_util = require("tests.util")

local remote_address
local checkin_address
local test_path = "./"
local cleanup = {}
local concurrency_update_merkle_tree = util.parse_number(os.getenv("CARTESI_CONCURRENCY_UPDATE_MERKLE_TREE")) or 0

local lua_cmd = arg[-1] .. " -e "

-- There is no UINT64_MAX in Lua, so we have to use the signed representation
local MAX_MCYCLE = -1
local MAX_UARCH_CYCLE = -1

-- Print help and exit
local function help()
    io.stderr:write(string.format(
        [=[
Usage:

  %s <machine_type> [options]

where options are:

  --remote-address=<address>
    run tests on a remote cartesi machine (when machine type is grpc or jsonrpc).
    (grcp requires --checkin-address to be defined as well)

  --checkin-address=<address>
    address of the local checkin server to run

  --test-path=<dir>
    path to test execution folder. In case of grpc tests, path must be
    working directory of remote-cartesi-machine and must be locally readable
    (default: "./")

  --concurrency=<key>:<value>[,<key>:<value>[,...]...]
    configures the number of threads used in some implementation parts.

    <key>:<value> is one of
        update_merkle_tree:<number>

        update_merkle_tree (optional)
        defines the number of threads to use while calculating the merkle tree.
        when omitted or defined as 0, the number of hardware threads is used if
        it can be identified or else a single thread is used.

<address> is one of the following formats:
  <host>:<port>
   unix:<path>

<host> can be a host name, IPv4 or IPv6 address.
]=],
        arg[0]
    ))
    os.exit()
end

local options = {
    {
        "^%-%-h$",
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
        "^%-%-remote%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            remote_address = o
            return true
        end,
    },
    {
        "^%-%-checkin%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            checkin_address = o
            return true
        end,
    },
    {
        "^%-%-test%-path%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            test_path = o
            if string.sub(test_path, -1, -1) ~= "/" then error("test-path must end in '/'") end
            return true
        end,
    },
    {
        "^(%-%-concurrency%=(.+))$",
        function(all, opts)
            if not opts then return false end
            local c = util.parse_options(opts, {
                update_merkle_tree = true,
            })
            c.update_merkle_tree =
                assert(util.parse_number(c.update_merkle_tree), "invalid update_merkle_tree number in " .. all)
            concurrency_update_merkle_tree = c.update_merkle_tree
            return true
        end,
    },
    { ".*", function(all) error("unrecognized option " .. all) end },
}

-- Process command line options
local arguments = {}
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then break end
        end
    else
        arguments[#arguments + 1] = argument
    end
end

local SHADOW_BASE = 0x0

local cpu_x_addr = {}
for i = 0, 31 do
    cpu_x_addr[i] = i * 8
end

local function get_cpu_xreg_test_values()
    local values = {}
    for i = 0, 31 do
        values[i] = i * 8
    end
    return values
end

local function get_cpu_uarch_xreg_test_values()
    local values = {}
    for i = 0, 31 do
        values[i] = 0x10000 + (i * 8)
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
assert(
    machine_type == "local" or machine_type == "grpc" or machine_type == "jsonrpc",
    "unknown machine type, should be 'local', 'grpc', or 'jsonrpc'"
)
local protocol
if machine_type == "grpc" then
    assert(remote_address ~= nil, "remote cartesi machine address is missing")
    assert(checkin_address, "missing checkin address")
    assert(test_path ~= nil, "test path must be provided and must be working directory of remote cartesi machine")
    protocol = require("cartesi.grpc")
end
if machine_type == "jsonrpc" then
    assert(remote_address ~= nil, "remote cartesi machine address is missing")
    assert(test_path ~= nil, "test path must be provided and must be working directory of remote cartesi machine")
    protocol = require("cartesi.jsonrpc")
end

local function connect()
    local remote = protocol.stub(remote_address, checkin_address)
    local version = assert(remote.get_version(), "could not connect to remote cartesi machine at " .. remote_address)
    local shutdown = function() remote.shutdown() end
    local mt = { __gc = function() pcall(shutdown) end }
    setmetatable(cleanup, mt)
    return remote, version
end

local remote

local function build_machine_config(config_options)
    if not config_options then config_options = {} end

    -- Create new machine
    local initial_csr_values = get_cpu_csr_test_values()
    local initial_xreg_values = get_cpu_xreg_test_values()
    local initial_uarch_xreg_values = get_cpu_uarch_xreg_test_values()
    initial_csr_values.x = initial_xreg_values
    local config = {
        processor = config_options.processor or initial_csr_values,
        rom = { image_filename = test_util.images_path .. "rom.bin" },
        ram = { length = 1 << 20 },
        uarch = config_options.uarch or {
            processor = {
                x = initial_uarch_xreg_values,
            },
            ram = {
                length = 0x1000,
                image_filename = test_util.create_test_uarch_program(),
            },
        },
    }
    local runtime = {
        concurrency = {
            update_merkle_tree = concurrency_update_merkle_tree,
        },
    }
    return config, runtime
end

local function build_machine(type, config_options)
    local config, runtime = build_machine_config(config_options)
    local new_machine
    if type ~= "local" then
        if not remote then remote = connect() end
        new_machine = assert(remote.machine(config, runtime))
    else
        new_machine = assert(cartesi.machine(config, runtime))
    end
    if config.uarch.ram and config.uarch.ram.image_filename then os.remove(config.uarch.ram.image_filename) end
    return new_machine
end

local do_test = test_util.make_do_test(build_machine, machine_type)

print("Testing machine bindings for type " .. machine_type)

print("\n\ntesting machine initial flags")
do_test("machine should not have halt and yield initial flags set", function(machine)
    -- Check machine is not halted
    assert(not machine:read_iflags_H(), "machine shouldn't be halted")
    -- Check machine is not yielded
    assert(not machine:read_iflags_Y(), "machine shouldn't be yielded")
end)

print("\n\ntesting machine register initial flag values ")
do_test("machine should have default config shadow register values", function(machine)
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
end)

print("\n\ntesting merkle tree get_proof for values for registers")
do_test("should provide proof for values in registers", function(machine)
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
            assert(test_util.check_proof(assert(machine:get_proof(a, el)), "no proof"), "proof failed")
        end
    end

    for _, v in pairs(initial_xreg_values) do
        for el = 3, 63 do
            local a = test_util.align(v, el)
            assert(test_util.check_proof(assert(machine:get_proof(a, el), "no proof")), "proof failed")
        end
    end
end)

print("\n\ntesting get_csr_address function binding")
do_test("should return address value for csr register", function()
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then remote = connect() end
        module = remote
    end
    -- Check CSR address
    for k, v in pairs(cpu_csr_addr) do
        local u = module.machine.get_csr_address(k)
        assert(u == v, "invalid return for " .. v)
    end
end)

print("\n\ntesting get_x_address function binding")
do_test("should return address value for x registers", function()
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then remote = connect() end
        module = remote
    end
    -- Check x address
    for i = 0, 31 do
        assert(module.machine.get_x_address(i) == SHADOW_BASE + i * 8, "invalid return for x" .. i)
    end
end)

print("\n\ntesting get_x_uarch_address function binding")
do_test("should return address value for uarch x registers", function()
    local SHADOW_UARCH_XBASE = test_util.PMA_SHADOW_UARCH_STATE_START + 32
    local module = cartesi
    if machine_type == "grpc" then
        if not remote then remote = connect() end
        module = remote
    end
    -- Check x address
    for i = 0, 31 do
        assert(module.machine.get_uarch_x_address(i) == SHADOW_UARCH_XBASE + i * 8, "invalid return for uarch x" .. i)
    end
end)

local function test_config_memory_range(range, name)
    assert(type(range.length) == "number", "invalid " .. name .. ".length")
    assert(type(range.start) == "number", "invalid " .. name .. ".start")
    assert(range.shared == nil or type(range.shared) == "boolean", "invalid " .. name .. ".shared")
    assert(
        range.image_filename == nil or type(range.image_filename) == "string",
        "invalid " .. name .. ".image_filename"
    )
end

local function test_config(config)
    assert(type(config) == "table", "config not a table")
    for _, field in ipairs({ "processor", "htif", "clint", "flash_drive", "ram", "dtb" }) do
        assert(config[field] and type(config[field]) == "table", "invalid field " .. field)
    end
    for i = 1, 31 do
        assert(type(config.processor.x[i]) == "number", "x" .. i .. " is not a number")
    end
    local htif = config.htif
    for _, field in ipairs({ "console_getchar", "yield_manual", "yield_automatic" }) do
        assert(htif[field] == nil or type(htif[field]) == "boolean", "invalid htif." .. field)
    end
    assert(type(htif.tohost) == "number", "invalid htif.tohost")
    assert(type(htif.fromhost) == "number", "invalid htif.fromhost")
    local clint = config.clint
    assert(type(clint.mtimecmp) == "number", "invalid clint.mtimecmp")
    local ram = config.ram
    assert(type(ram.length) == "number", "invalid ram.length")
    assert(ram.image_filename == nil or type(ram.image_filename) == "string", "invalid ram.image_filename")
    local dtb = config.dtb
    assert(dtb.image_filename == nil or type(dtb.image_filename) == "string", "invalid dtb.image_filename")
    assert(dtb.bootargs == nil or type(dtb.bootargs) == "string", "invalid dtb.bootargs")
    assert(dtb.init == nil or type(dtb.init) == "string", "invalid dtb.init")
    assert(dtb.entrypoint == nil or type(dtb.entrypoint) == "string", "invalid dtb.entrypoint")
    local tlb = config.tlb
    assert(tlb.image_filename == nil or type(tlb.image_filename) == "string", "invalid tlb.image_filename")
    for _, f in ipairs(config.flash_drive) do
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
do_test("should return default machine config", function()
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then remote = connect() end
        module = remote
    end
    test_config(module.machine.get_default_config())
end)

print("\n\n test verifying integrity of the merkle tree")
do_test("verify_merkle_tree should return true", function(machine)
    -- Verify starting merkle tree
    assert(machine:verify_merkle_tree(), "error, non consistent merkle tree")
end)

print("\n\n test calculation of initial root hash")
do_test("should return expected value", function(machine)
    -- Get starting root hash
    local root_hash = machine:get_root_hash()
    print("Root hash: ", test_util.tohex(root_hash))

    local calculated_root_hash = test_util.calculate_emulator_hash(machine)

    assert(root_hash == calculated_root_hash, "initial root hash does not match")
end)

print("\n\n test get_initial_config")
do_test("should have expected values", function(machine)
    -- Check initial config
    local initial_config = machine:get_initial_config()
    test_config(initial_config)
    assert(initial_config.processor.pc == 0x200, "wrong pc reg initial config value")
    assert(initial_config.processor.ilrsc == 0x2e0, "wrong ilrsc reg initial config value")
    assert(initial_config.processor.mstatus == 0x230, "wrong mstatus reg initial config value")
    assert(initial_config.clint.mtimecmp == 0, "wrong clint mtimecmp initial config value")
    assert(initial_config.htif.fromhost == 0, "wrong htif fromhost initial config value")
    assert(initial_config.htif.tohost == 0, "wrong htif tohost initial config value")
    assert(initial_config.htif.yield_automatic == false, "wrong htif yield automatic initial config value")
    assert(initial_config.htif.yield_manual == false, "wrong htif yield manual initial config value")
end)

print("\n\n test read_csr")
do_test("should return expected values", function(machine)
    local initial_csr_values = get_cpu_csr_test_values()
    initial_csr_values.mvendorid = cartesi.MVENDORID
    initial_csr_values.marchid = cartesi.MARCHID
    initial_csr_values.mimpid = cartesi.MIMPID
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
            assert(machine[method_name](machine) == initial_csr_values[k], "wrong " .. k .. " value")
        end
    end
end)

print("\n\n read and write x registers")
do_test("writen and expected register values should match", function(machine)
    local initial_xreg_values = get_cpu_xreg_test_values()
    -- Write/Read X registers
    local x1_initial_value = machine:read_x(1)
    assert(x1_initial_value == initial_xreg_values[1], "error reading x1 register")
    machine:write_x(1, 0x1122)
    assert(machine:read_x(1) == 0x1122, "error with writing to x1 register")
    machine:write_x(1, x1_initial_value)
    assert(machine:read_x(1) == x1_initial_value)
    -- Read unexsisting register
    local status_invalid_reg = pcall(machine.read_x, machine, 1000)
    assert(status_invalid_reg == false, "no error reading invalid x register")
end)

print("\n\n read and write uarch x registers")
do_test("writen and expected register values should match", function(machine)
    local initial_xreg_values = get_cpu_uarch_xreg_test_values()
    -- Write/Read uarch X registers
    local x1_initial_value = machine:read_uarch_x(1)
    assert(x1_initial_value == initial_xreg_values[1], "error reading uarch x1 register")
    machine:write_uarch_x(1, 0x1122)
    assert(machine:read_uarch_x(1) == 0x1122, "error with writing to uarch x1 register")
    machine:write_uarch_x(1, x1_initial_value)
    assert(machine:read_uarch_x(1) == x1_initial_value)
    -- Read unexsisting uarch register
    local status_invalid_reg = pcall(machine.read_uarch_x, machine, 1000)
    assert(status_invalid_reg == false, "no error reading invalid uarch x register")
end)

print("\n\n read and write csr registers")
do_test("writen and expected register values should match", function(machine)
    -- Check csr register write
    local sscratch_initial_value = machine:read_csr("sscratch")
    assert(machine:read_sscratch() == sscratch_initial_value, "error reading csr sscratch")
    machine:write_csr("sscratch", 0x1122)
    assert(machine:read_csr("sscratch") == 0x1122)
    machine:write_csr("sscratch", sscratch_initial_value)

    -- Read unexsisting register
    local status_invalid_reg = pcall(machine.read_csr, machine, "invalidreg")
    assert(status_invalid_reg == false, "no error reading invalid csr register")
end)

print("\n\n perform step and check mcycle register")
do_test("mcycle value should match", function(machine)
    local log_type = {}
    local uarch_cycle_initial_value = machine:read_csr("uarch_cycle")

    machine:step_uarch(log_type)

    -- Check mcycle increment
    local uarch_cycle_current_value = machine:read_csr("uarch_cycle")
    assert(uarch_cycle_current_value == uarch_cycle_initial_value + 1, "wrong uarch_cycle value")
end)

do_test("should error if target mcycle is smaller than current mcycle", function(machine)
    machine:write_mcycle(MAX_MCYCLE)
    assert(machine:read_mcycle() == MAX_MCYCLE)
    local success, err = pcall(function() machine:run(MAX_MCYCLE - 1) end)
    assert(success == false)
    assert(err:match("mcycle is past"))
    assert(machine:read_mcycle() == MAX_MCYCLE)
end)

do_test("should error if target uarch_cycle is smaller than current uarch_cycle", function(machine)
    machine:write_uarch_cycle(MAX_UARCH_CYCLE)
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
    local success, err = pcall(function() machine:run_uarch(MAX_UARCH_CYCLE - 1) end)
    assert(success == false)
    assert(err:match("uarch_cycle is past"))
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
end)

print("\n\n run_uarch tests")

do_test("advance one micro cycle without halting", function(machine)
    assert(machine:read_uarch_cycle() == 0, "uarch cycle should be 0")
    assert(machine:read_uarch_halt_flag() == false, "uarch halt flag should be cleared")
    assert(machine:read_iflags_Y() == false, "iflags.Y should be cleared")
    assert(machine:read_iflags_H() == false, "iflags.H should be cleared")
    local status = machine:run_uarch(1)
    assert(status == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_CYCLE)
    assert(machine:read_uarch_cycle() == 1, "uarch cycle should be 1")
    assert(machine:read_uarch_halt_flag() == false, "uarch should not be halted")
end)

do_test("do not advance micro cycle if uarch is halted", function(machine)
    machine:set_uarch_halt_flag()
    assert(machine:read_uarch_cycle() == 0, "uarch cycle should be 0")
    assert(machine:read_uarch_halt_flag() == true, "uarch halt flag should be set")
    assert(machine:read_iflags_Y() == false, "iflags.Y should be cleared")
    assert(machine:read_iflags_H() == false, "iflags.H should be cleared")
    local status = machine:run_uarch(1)
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED, "run_uarch should return UARCH_BREAK_REASON_UARCH_HALTED")
    assert(machine:read_uarch_cycle() == 0, "uarch cycle should still be 0")
end)

do_test("advance micro cycles until halt", function(machine)
    assert(machine:read_uarch_cycle() == 0, "uarch cycle should be 0")
    assert(machine:read_uarch_halt_flag() == false, "machine should not be halted")
    local status = machine:run_uarch()
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
    assert(machine:read_uarch_cycle() == 4, "uarch cycle should be 4")
    assert(machine:read_uarch_halt_flag() == true, "uarch should be halted")
end)

print("\n\n run machine to 1000 mcycle")
do_test("mcycle value should be 1000 after execution", function(machine)
    -- Run machine
    machine:write_csr("mcycle", 0)
    assert(machine:read_csr("mcycle") == 0)

    local test = machine:read_mcycle()
    while test < 1000 do
        machine:run(1000)
        test = machine:read_mcycle()
    end
    assert(machine:read_csr("mcycle") == 1000)
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
    assert(machine:read_htif_fromhost() == 0x12345678, "error writing htif fromhost")
    machine:write_htif_fromhost_data(0x123456789A)
    assert(machine:read_htif_ihalt(), "error reading htif ihalt")
    assert(machine:read_htif_iyield(), "error reading htif yield")
end)

print("\n\n check memory reading/writing")
do_test("written and read values should match", function(machine)
    -- Check mem write and mem read
    machine:write_memory(0x800000FF, "mydataol12345678", 0x10)
    local memory_read = machine:read_memory(0x800000FF, 0x10)
    assert(memory_read == "mydataol12345678")
end)

print("\n\n dump log  to console")
do_test("dumped log content should match", function()
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
                                 uarch = {
                                    ram = { length = 1 << 16, image_filename = uarch_ram_path }
                                 }
                                 }
                                 os.remove(uarch_ram_path)
                                 local log_type = {proofs = false, annotations = true}
                                 local log = machine:step_uarch(log_type)
                                 cartesi_util.dump_log(log, io.stdout)
                                 " 2>&1]]

    local p = io.popen(lua_cmd .. lua_code)
    local output = p:read(2000)
    p:close()
    local expected_output = "begin step\n"
        .. "  1: read uarch.cycle@0x70000008(1879048200): 0x0(0)\n"
        .. "  2: read uarch.halt_flag@0x70000000(1879048192): 0x0(0)\n"
        .. "  3: read uarch.pc@0x70000010(1879048208): 0x78000000(2013265920)\n"
        .. "  4: read memory@0x78000000(2013265920): 0x700002b707b00513(8070453517379175699)\n"
        .. "  begin addi\n"
        .. "    5: read uarch.x@0x70000020(1879048224): 0x0(0)\n"
        .. "    6: write uarch.x@0x70000070(1879048304): 0x0(0) -> 0x7b(123)\n"
        .. "    7: write uarch.pc@0x70000010(1879048208): 0x78000000(2013265920) -> 0x78000004(2013265924)\n"
        .. "  end addi\n"
        .. "  8: write uarch.cycle@0x70000008(1879048200): 0x0(0) -> 0x1(1)\n"
        .. "end step\n"

    print("Output of dump log:")
    print("--------------------------")
    print(output)
    print("--------------------------")
    assert(output == expected_output, "Output does not match expected output:\n" .. expected_output)
end)

print("\n\ntesting step and verification")
do_test("machine step should pass verifications", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then remote = connect() end
        module = remote
    end
    local initial_hash = machine:get_root_hash()
    local log = machine:step_uarch({ proofs = true, annotations = true })
    local final_hash = machine:get_root_hash()
    module.machine.verify_state_transition(initial_hash, log, final_hash, {})
    module.machine.verify_access_log(log, {})
end)

do_test("step when uarch cycle is max", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then remote = connect() end
        module = remote
    end
    machine:write_uarch_cycle(MAX_UARCH_CYCLE)
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
    local initial_hash = machine:get_root_hash()
    local log = machine:step_uarch({ proofs = true, annotations = true })
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
    local final_hash = machine:get_root_hash()
    assert(final_hash == initial_hash)
    module.machine.verify_state_transition(initial_hash, log, final_hash, {})
    module.machine.verify_access_log(log, {})
end)

local uarch_proof_step_program = {
    0x00000297, -- auipc	t0,0x0
    0x10028293, -- addi	t0,t0,256 # 0x100
    0x0ca00313, -- li	t1,0xca
    0x0fe00393, -- li	t2,0xfe
    0x0062b023, -- sd	t1,0(t0) [0xca]
    0x0072b023, -- sd	t2,0(t0) [0xfe]
    0x0062b023, -- sd	t1,0(t0) [0xca]
}

test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { length = 1 << 16, image_filename = test_util.create_test_uarch_program(uarch_proof_step_program) },
    },
})("merkle tree must be consistent when stepping alternating with and without proofs", function(machine)
    local t0 = 5
    local t1 = 6
    local t2 = 7
    local uarch_ram_start = test_util.PMA_UARCH_RAM_START
    local with_proofs = { proofs = true }
    local without_proofs = {}

    machine:step_uarch(with_proofs) -- auipc	t0,0x0
    machine:step_uarch(with_proofs) -- addi	t0,t0,256 # 0x100
    assert(machine:read_uarch_x(t0) == uarch_ram_start + 0x100)
    machine:step_uarch(with_proofs) -- li	t1,0xca
    assert(machine:read_uarch_x(t1) == 0xca)
    machine:step_uarch(with_proofs) -- li	t2,0xfe
    assert(machine:read_uarch_x(t2) == 0xfe)

    -- sd and assert stored correctly
    machine:step_uarch(with_proofs) -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)

    -- sd and assert stored correctly
    machine:step_uarch(without_proofs) -- t2,0(t0) [0xfe]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xfe)

    -- This step should run successfully
    -- The previous unproven step should have marked the updated pages dirty, allowing
    -- the tree to be updated correctly in the next proved step
    machine:step_uarch(with_proofs) -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)
end)

test_util.make_do_test(build_machine, machine_type, { uarch = { ram = { length = 0x1000 } } })(
    "It should initialize uarch ram with zeros when only uarch ram length is provided",
    function(machine)
        local m = machine:read_memory(test_util.PMA_UARCH_RAM_START, 0x1000)
        assert(m == string.rep("\0", 0x1000))
        assert(machine:read_uarch_ram_length() == 0x1000)
    end
)

test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { length = 0x1000, image_filename = test_util.create_test_uarch_program(uarch_proof_step_program) },
    },
})("It should load the uarch ram image from a file", function(machine)
    local expected_ram_image = ""
    for _, insn in pairs(uarch_proof_step_program) do
        expected_ram_image = expected_ram_image .. string.pack("I4", insn)
    end
    local zeros = string.rep("\0", 0x1000 - #expected_ram_image)
    expected_ram_image = expected_ram_image .. zeros

    local ram_image = machine:read_memory(test_util.PMA_UARCH_RAM_START, 0x1000)
    assert(ram_image == expected_ram_image)
    assert(machine:read_uarch_ram_length() == 0x1000)
end)

test_util.make_do_test(build_machine, machine_type, { processor = { mcycle = 1 }, uarch = {} })(
    "It should use the embedded uarch-ram.bin when the uarch config is not provided",
    function(machine)
        assert(machine:read_mcycle() == 1)

        -- Advance one mcycle by running the "big interpreter" compiled to the microarchitecture that is embedded
        -- in the emulator executable. Note that the config used to create the machine has an empty uarch key;
        -- therefore, the embedded uarch image is used.
        machine:run_uarch()

        assert(machine:read_mcycle() == 2)
        assert(machine:read_uarch_ram_length() == test_util.PMA_UARCH_RAM_LENGTH)
    end
)

print("\n\nAll machine binding tests for type " .. machine_type .. " passed")
