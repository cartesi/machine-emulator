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
local test_util = require("cartesi.tests.util")

local remote_address
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
    run tests on a remote cartesi machine (when machine type is jsonrpc).

  --test-path=<dir>
    path to test execution folder. In case of jsonrpc tests, path must be
    working directory of jsonrpc-remote-cartesi-machine and must be locally readable
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
            if not all then
                return false
            end
            help()
        end,
    },
    {
        "^%-%-help$",
        function(all)
            if not all then
                return false
            end
            help()
        end,
    },
    {
        "^%-%-remote%-address%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            remote_address = o
            return true
        end,
    },
    {
        "^%-%-test%-path%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            test_path = o
            if string.sub(test_path, -1, -1) ~= "/" then
                error("test-path must end in '/'")
            end
            return true
        end,
    },
    {
        "^(%-%-concurrency%=(.+))$",
        function(all, opts)
            if not opts then
                return false
            end
            local c = util.parse_options(opts, {
                update_merkle_tree = true,
            })
            c.update_merkle_tree =
                assert(util.parse_number(c.update_merkle_tree), "invalid update_merkle_tree number in " .. all)
            concurrency_update_merkle_tree = c.update_merkle_tree
            return true
        end,
    },
    {
        ".*",
        function(all)
            error("unrecognized option " .. all)
        end,
    },
}

-- Process command line options
local arguments = {}
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        arguments[#arguments + 1] = argument
    end
end

local SHADOW_BASE = 0x0

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
    iunrep = 752,
    clint_mtimecmp = 760,
    plic_girqpend = 768,
    plic_girqsrvd = 776,
    htif_tohost = 784,
    htif_fromhost = 792,
    htif_ihalt = 800,
    htif_iconsole = 808,
    htif_iyield = 816,
}
for i = 0, 31 do
    cpu_csr_addr["x" .. i] = i * 8
end

local function get_uarch_cpu_csr_test_values()
    local processor = {}
    for i = 0, 31 do
        processor["x" .. i] = 0x10000 + (i * 8)
    end
    return processor
end

local function get_cpu_csr_test_values()
    local csr_values = {
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
        iunrep = 0x0,
    }
    for i = 0, 31 do
        csr_values["x" .. i] = i * 8
    end
    return csr_values
end

local machine_type = assert(arguments[1], "missing machine type")
assert(machine_type == "local" or machine_type == "jsonrpc", "unknown machine type, should be 'local' or 'jsonrpc'")
local protocol
if machine_type == "jsonrpc" then
    assert(remote_address ~= nil, "remote cartesi machine address is missing")
    assert(test_path ~= nil, "test path must be provided and must be working directory of remote cartesi machine")
    protocol = require("cartesi.jsonrpc")
end

local function connect()
    local remote = protocol.stub(remote_address)
    local version = assert(remote.get_version(), "could not connect to remote cartesi machine at " .. remote_address)
    local shutdown = function()
        remote.shutdown()
    end
    local mt = {
        __gc = function()
            pcall(shutdown)
        end,
    }
    setmetatable(cleanup, mt)
    return remote, version
end

local remote

local function build_machine_config(config_options)
    if not config_options then
        config_options = {}
    end

    -- Create new machine
    local initial_csr_values = get_cpu_csr_test_values()
    local config = {
        processor = config_options.processor or initial_csr_values,
        rom = { image_filename = test_util.images_path .. "rom.bin" },
        ram = { length = 1 << 20 },
        htif = config_options.htif or nil,
        cmio = config_options.cmio or nil,
        uarch = config_options.uarch or {
            processor = get_uarch_cpu_csr_test_values(),
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
        if not remote then
            remote = connect()
        end
        new_machine = assert(remote.machine(config, runtime))
    else
        new_machine = assert(cartesi.machine(config, runtime))
    end
    if config.uarch.ram and config.uarch.ram.image_filename then
        os.remove(config.uarch.ram.image_filename)
    end
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
    initial_csr_values.mvendorid = nil
    initial_csr_values.marchid = nil
    initial_csr_values.mimpid = nil
    -- Check initialization and shadow reads
    for k, v in pairs(initial_csr_values) do
        local r = machine:read_word(cpu_csr_addr[k])
        assert(v == r)
    end
end)

print("\n\ntesting merkle tree get_proof for values for registers")
do_test("should provide proof for values in registers", function(machine)
    local initial_csr_values = get_cpu_csr_test_values()
    initial_csr_values.mvendorid = nil
    initial_csr_values.marchid = nil
    initial_csr_values.mimpid = nil

    -- Check proofs
    for _, v in pairs(initial_csr_values) do
        for el = cartesi.TREE_LOG2_WORD_SIZE, cartesi.TREE_LOG2_ROOT_SIZE - 1 do
            local a = test_util.align(v, el)
            assert(test_util.check_proof(assert(machine:get_proof(a, el)), "no proof"), "proof failed")
        end
    end
end)

print("\n\ntesting get_csr_address function binding")
do_test("should return address value for csr register", function()
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
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
        if not remote then
            remote = connect()
        end
        module = remote
    end
    -- Check x address
    for i = 0, 31 do
        assert(module.machine.get_x_address(i) == SHADOW_BASE + i * 8, "invalid return for x" .. i)
    end
end)

print("\n\ntesting get_x_uarch_address function binding")
do_test("should return address value for uarch x registers", function()
    local SHADOW_UARCH_XBASE = cartesi.UARCH_SHADOW_START_ADDRESS + 24
    local module = cartesi
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

local function test_cmio_buffer_config(buffer_config, name)
    assert(buffer_config.shared == nil or type(buffer_config.shared) == "boolean", "invalid " .. name .. ".shared")
    assert(
        buffer_config.image_filename == nil or type(buffer_config.image_filename) == "string",
        "invalid " .. name .. ".image_filename"
    )
end

local function test_config(config)
    assert(type(config) == "table", "config not a table")
    for _, field in ipairs({ "processor", "htif", "clint", "plic", "flash_drive", "ram", "dtb" }) do
        assert(config[field] and type(config[field]) == "table", "invalid field " .. field)
    end
    for i = 1, 31 do
        assert(type(config.processor["x" .. i]) == "number", "x" .. i .. " is not a number")
    end
    local htif = config.htif
    for _, field in ipairs({ "console_getchar", "yield_manual", "yield_automatic" }) do
        assert(htif[field] == nil or type(htif[field]) == "boolean", "invalid htif." .. field)
    end
    assert(type(htif.tohost) == "number", "invalid htif.tohost")
    assert(type(htif.fromhost) == "number", "invalid htif.fromhost")
    local clint = config.clint
    assert(type(clint.mtimecmp) == "number", "invalid clint.mtimecmp")
    local plic = config.plic
    assert(type(plic.girqpend) == "number", "invalid plic.girqpend")
    assert(type(plic.girqsrvd) == "number", "invalid plic.girqsrvd")
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
    local cmio = config.cmio
    if config.cmio then
        test_cmio_buffer_config(cmio.rx_buffer, "cmio.rx_buffer")
        test_cmio_buffer_config(cmio.tx_buffer, "cmio.tx_buffer")
    end
end

print("\n\ntesting get_default_config function binding")
do_test("should return default machine config", function()
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
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
    assert(initial_config.plic.girqpend == 0, "wrong plic girqpend initial config value")
    assert(initial_config.plic.girqsrvd == 0, "wrong plic girqsrvd initial config value")
    assert(initial_config.htif.fromhost == 0, "wrong htif fromhost initial config value")
    assert(initial_config.htif.tohost == 0, "wrong htif tohost initial config value")
    assert(initial_config.htif.yield_automatic == true, "wrong htif yield automatic initial config value")
    assert(initial_config.htif.yield_manual == true, "wrong htif yield manual initial config value")
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
    initial_csr_values.htif_iyield = 3

    -- Check csr register read
    local to_ignore = {
        iflags = true,
        clint_mtimecmp = true,
        plic_girqpend = true,
        plic_girqsrvd = true,
        htif_ihalt = true,
        htif_iconsole = true,
    }
    for k in pairs(cpu_csr_addr) do
        if not to_ignore[k] then
            assert(machine:read_csr(k) == initial_csr_values[k], "wrong " .. k .. " value")
        end
    end
end)

print("\n\n read and write x registers")
do_test("written and expected register values should match", function(machine)
    -- Write/Read X registers
    local initial_csr_values = get_cpu_csr_test_values()
    local x1_initial_value = machine:read_csr("x1")
    assert(x1_initial_value == initial_csr_values.x1, "error reading x1 register")
    machine:write_csr("x1", 0x1122)
    assert(machine:read_csr("x1") == 0x1122, "error with writing to x1 register")
    machine:write_csr("x1", x1_initial_value)
    assert(machine:read_csr("x1") == x1_initial_value)
    -- Read invalid register
    local status_invalid_reg = pcall(machine.read_csr, machine, "x1000")
    assert(status_invalid_reg == false, "no error reading invalid x register")
end)

print("\n\n read and write uarch x registers")
do_test("written and expected register values should match", function(machine)
    -- Write/Read uarch X registers
    local initial_csr_values = get_uarch_cpu_csr_test_values()
    local x1_initial_value = machine:read_csr("uarch_x1")
    assert(x1_initial_value == initial_csr_values.x1, "error reading uarch x1 register")
    machine:write_csr("uarch_x1", 0x1122)
    assert(machine:read_csr("uarch_x1") == 0x1122, "error with writing to uarch x1 register")
    machine:write_csr("uarch_x1", x1_initial_value)
    assert(machine:read_csr("uarch_x1") == x1_initial_value)
    -- Read invalid uarch register
    local status_invalid_reg = pcall(machine.read_csr, machine, "uarch_x1000")
    assert(status_invalid_reg == false, "no error reading invalid uarch x register")
end)

print("\n\n read and write csr registers")
do_test("written and expected register values should match", function(machine)
    -- Check csr register write
    local sscratch_initial_value = machine:read_csr("sscratch")
    assert(machine:read_csr("sscratch") == sscratch_initial_value, "error reading csr sscratch")
    machine:write_csr("sscratch", 0x1122)
    assert(machine:read_csr("sscratch") == 0x1122)
    machine:write_csr("sscratch", sscratch_initial_value)

    -- Read invalid register
    local status_invalid_reg = pcall(machine.read_csr, machine, "invalidreg")
    assert(status_invalid_reg == false, "no error reading invalid csr register")
end)

print("\n\n perform step and check mcycle register")
do_test("mcycle value should match", function(machine)
    local log_type = {}
    local uarch_cycle_initial_value = machine:read_csr("uarch_cycle")

    machine:log_step_uarch(log_type)

    -- Check mcycle increment
    local uarch_cycle_current_value = machine:read_csr("uarch_cycle")
    assert(uarch_cycle_current_value == uarch_cycle_initial_value + 1, "wrong uarch_cycle value")
end)

do_test("should error if target mcycle is smaller than current mcycle", function(machine)
    machine:write_mcycle(MAX_MCYCLE)
    assert(machine:read_mcycle() == MAX_MCYCLE)
    local success, err = pcall(function()
        machine:run(MAX_MCYCLE - 1)
    end)
    assert(success == false)
    assert(err:match("mcycle is past"))
    assert(machine:read_mcycle() == MAX_MCYCLE)
end)

do_test("should error if target uarch_cycle is smaller than current uarch_cycle", function(machine)
    machine:write_uarch_cycle(MAX_UARCH_CYCLE)
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
    local success, err = pcall(function()
        machine:run_uarch(MAX_UARCH_CYCLE - 1)
    end)
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
    assert(machine:read_uarch_cycle() == 3, "uarch cycle should be 4")
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
    assert(machine:read_csr("htif_tohost"), "error reading htif tohost")
    assert(machine:read_csr("htif_tohost_dev"), "error reading htif tohost dev")
    assert(machine:read_csr("htif_tohost_cmd"), "error reading htif tohost cmd")
    assert(machine:read_csr("htif_tohost_data"), "error reading htif tohost data")
    assert(machine:read_csr("htif_fromhost"), "error reading htif fromhost")
    machine:write_csr("htif_tohost", 0x123456)
    assert(machine:read_csr("htif_tohost") == 0x123456, "error writing htif tohost")
    machine:write_csr("htif_fromhost", 0x12345678)
    assert(machine:read_csr("htif_fromhost") == 0x12345678, "error writing htif fromhost")
    machine:write_csr("htif_fromhost_data", 0x12345678)
    assert(machine:read_csr("htif_ihalt"), "error reading htif ihalt")
    assert(machine:read_csr("htif_iyield"), "error reading htif yield")
end)

print("\n\n check memory reading/writing")
do_test("written and read values should match", function(machine)
    -- Check mem write and mem read
    machine:write_memory(0x800000FF, "mydataol12345678", 0x10)
    local memory_read = machine:read_memory(0x800000FF, 0x10)
    assert(memory_read == "mydataol12345678")
end)

print("\n\n dump step log  to console")
do_test("dumped step log content should match", function(machine)
    local log_type = { proofs = false, annotations = true }
    local log = machine:log_step_uarch(log_type)
    local temp_file <close> = test_util.new_temp_file()
    util.dump_log(log, temp_file)
    local log_output = temp_file:read_all()
    -- luacheck: push no max line length
    local expected_output = "begin step\n"
        .. "  1: read uarch.cycle@0x400008(4194312): 0x0(0)\n"
        .. "  2: read uarch.halt_flag@0x400000(4194304): 0x0(0)\n"
        .. "  3: read uarch.pc@0x400010(4194320): 0x600000(6291456)\n"
        .. "  4: read memory@0x600000(6291456): 0x10089307b00513(4513027209561363)\n"
        .. "  begin addi\n"
        .. "    5: read uarch.x@0x400018(4194328): 0x0(0)\n"
        .. "    6: write uarch.x@0x400068(4194408): 0x10050(65616) -> 0x7b(123)\n"
        .. "    7: write uarch.pc@0x400010(4194320): 0x600000(6291456) -> 0x600004(6291460)\n"
        .. "  end addi\n"
        .. "  8: write uarch.cycle@0x400008(4194312): 0x0(0) -> 0x1(1)\n"
        .. "end step\n"
    -- luacheck: pop
    print("Log output:")
    print("--------------------------")
    print(log_output)
    print("--------------------------")
    assert(log_output == expected_output, "Output does not match expected output:\n" .. expected_output)
end)

print("\n\ntesting step and verification")
do_test("machine step should pass verifications", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
        module = remote
    end
    local initial_hash = machine:get_root_hash()
    local log = machine:log_step_uarch({ proofs = true, annotations = true })
    local final_hash = machine:get_root_hash()
    module.machine.verify_step_uarch_state_transition(initial_hash, log, final_hash, {})
    module.machine.verify_step_uarch_log(log, {})
end)

print("\n\ntesting step and verification")
do_test("Step log must contain conssitent data hashes", function(machine)
    local wrong_hash = string.rep("\0", 32)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
        module = remote
    end
    local log = machine:log_step_uarch({ proofs = false, annotations = false })
    module.machine.verify_step_uarch_log(log, {})
    local read_access = log.accesses[1]
    assert(read_access.type == "read")
    local read_hash = read_access.read_hash
    -- ensure that verification fails with wrong read hash
    read_access.read_hash = wrong_hash
    local _, err = pcall(module.machine.verify_step_uarch_log, log, {})
    assert(err:match("logged read data of uarch.uarch_cycle data does not hash to the logged read hash at access 1"))
    read_access.read_hash = read_hash -- restore correct value

    -- ensure that verification fails with wrong read hash
    local write_access = log.accesses[#log.accesses]
    assert(write_access.type == "write")
    read_hash = write_access.read_hash
    write_access.read_hash = wrong_hash
    _, err = pcall(module.machine.verify_step_uarch_log, log, {})
    assert(err:match("logged read data of uarch.cycle does not hash to the logged read hash at access 8"))
    write_access.read_hash = read_hash -- restore correct value

    -- ensure that verification fails with wrong written hash
    write_access.written_hash = wrong_hash
    _, err = pcall(module.machine.verify_step_uarch_log, log, {})
    assert(err:match("logged written data of uarch.cycle does not hash to the logged written hash at access 8"))
end)

do_test("step when uarch cycle is max", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
        module = remote
    end
    machine:write_uarch_cycle(MAX_UARCH_CYCLE)
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
    local initial_hash = machine:get_root_hash()
    local log = machine:log_step_uarch({ proofs = true, annotations = true })
    assert(machine:read_uarch_cycle() == MAX_UARCH_CYCLE)
    local final_hash = machine:get_root_hash()
    assert(final_hash == initial_hash)
    module.machine.verify_step_uarch_state_transition(initial_hash, log, final_hash, {})
    module.machine.verify_step_uarch_log(log, {})
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
        ram = { image_filename = test_util.create_test_uarch_program(uarch_proof_step_program) },
    },
})("merkle tree must be consistent when stepping alternating with and without proofs", function(machine)
    local t0 = 5
    local t1 = 6
    local t2 = 7
    local uarch_ram_start = cartesi.UARCH_RAM_START_ADDRESS
    local with_proofs = { proofs = true }
    local without_proofs = {}

    machine:log_step_uarch(with_proofs) -- auipc	t0,0x0
    machine:log_step_uarch(with_proofs) -- addi	t0,t0,256 # 0x100
    assert(machine:read_csr("uarch_x" .. t0) == uarch_ram_start + 0x100)
    machine:log_step_uarch(with_proofs) -- li	t1,0xca
    assert(machine:read_csr("uarch_x" .. t1) == 0xca)
    machine:log_step_uarch(with_proofs) -- li	t2,0xfe
    assert(machine:read_csr("uarch_x" .. t2) == 0xfe)

    -- sd and assert stored correctly
    machine:log_step_uarch(with_proofs) -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)

    -- sd and assert stored correctly
    machine:log_step_uarch(without_proofs) -- t2,0(t0) [0xfe]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xfe)

    -- This step should run successfully
    -- The previous unproven step should have marked the updated pages dirty, allowing
    -- the tree to be updated correctly in the next proved step
    machine:log_step_uarch(with_proofs) -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)
end)

test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { image_filename = test_util.create_test_uarch_program(uarch_proof_step_program) },
    },
})("It should load the uarch ram image from a file", function(machine)
    local expected_ram_image = ""
    for _, insn in pairs(uarch_proof_step_program) do
        expected_ram_image = expected_ram_image .. string.pack("I4", insn)
    end
    local zeros = string.rep("\0", 0x1000 - #expected_ram_image)
    expected_ram_image = expected_ram_image .. zeros

    local ram_image = machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, 0x1000)
    assert(ram_image == expected_ram_image)
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
    end
)

print("\n\n testing reset uarch")

test_util.make_do_test(build_machine, machine_type, { uarch = {} })(
    "uarch reset using default uarch configuration ",
    function(machine)
        local initial_hash = machine:get_root_hash()
        -- resetting immediately should not produce different hash
        machine:reset_uarch()
        local hash_after_immediate_reset = machine:get_root_hash()
        assert(initial_hash == hash_after_immediate_reset)
        -- hash should change after one step (shadow uarch change)
        machine:log_step_uarch({})
        local hash_after_step = machine:get_root_hash()
        assert(hash_after_step ~= initial_hash)
        -- reset should restore initial hash
        machine:reset_uarch()
        local hash_after_2nd_reset = machine:get_root_hash()
        assert(hash_after_2nd_reset == initial_hash)
        -- Modifying uarch ram changes hash
        machine:write_memory(cartesi.UARCH_RAM_START_ADDRESS, string.rep("X", 1 << 8))
        local hash_after_write = machine:get_root_hash()
        assert(hash_after_write ~= initial_hash)
        -- reset should restore initial hash
        machine:reset_uarch()
        local hash_after_3rd_reset = machine:get_root_hash()
        assert(hash_after_3rd_reset == initial_hash)
    end
)

local test_reset_uarch_config = {
    processor = {
        halt_flag = true,
        cycle = 1,
        pc = 0,
    },
}
for i = 0, 31 do
    test_reset_uarch_config.processor["x" .. i] = 0x10000 + (i * 8)
end

local function test_reset_uarch(machine, with_log, with_proofs, with_annotations)
    -- assert initial fixture state
    assert(machine:read_uarch_halt_flag() == true)
    assert(machine:read_uarch_cycle() == 1)
    assert(machine:read_csr("uarch_pc") == 0)
    for i = 1, 31 do
        assert(machine:read_csr("uarch_x" .. i) == test_reset_uarch_config.processor["x" .. i])
    end
    -- modify uarch ram
    local gibberish = "mydataol12345678"
    machine:write_memory(cartesi.UARCH_RAM_START_ADDRESS, gibberish, #gibberish)
    assert(machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, #gibberish) == gibberish)
    -- assert uarch state hash is not pristine
    local uarch_state_hash = test_util.calculate_uarch_state_hash(machine)
    assert(uarch_state_hash ~= cartesi.UARCH_PRISTINE_STATE_HASH)
    -- reset uarch state
    if with_log then
        local log = machine:log_reset_uarch({ proofs = with_proofs, annotations = with_annotations })
        assert(#log.accesses == 1)
        local access = log.accesses[1]
        if with_proofs then
            assert(access.sibling_hashes ~= nil)
        else
            assert(access.sibling_hashes == nil)
        end
        assert(access.address == cartesi.UARCH_SHADOW_START_ADDRESS)
        assert(access.log2_size == cartesi.UARCH_STATE_LOG2_SIZE)
        assert(access.written_hash == cartesi.UARCH_PRISTINE_STATE_HASH)
        assert(access.written == nil)
        assert(access.read_hash ~= nil)
        assert(access.read == nil)
    else
        machine:reset_uarch()
    end
    --- assert registers are reset to pristine values
    assert(machine:read_uarch_halt_flag() == false)
    assert(machine:read_uarch_cycle() == 0)
    assert(machine:read_csr("uarch_pc") == cartesi.UARCH_RAM_START_ADDRESS)
    for i = 1, 31 do
        assert(machine:read_csr("uarch_x" .. i) == 0)
    end
    -- assert that gibberish was removed from uarch ram
    assert(machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, #gibberish) ~= gibberish)
    -- compute current uarch state hash
    uarch_state_hash = test_util.calculate_uarch_state_hash(machine)
    -- assert computed and pristine hash match
    assert(uarch_state_hash == cartesi.UARCH_PRISTINE_STATE_HASH)
end

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing reset_uarch without logging",
    function(machine)
        test_reset_uarch(machine, false, false, false)
    end
)

for _, with_proofs in ipairs({ true, false }) do
    for _, with_annotations in ipairs({ true, false }) do
        test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
            "Testing reset_uarch with logging, proofs="
                .. tostring(with_proofs)
                .. ", annotations="
                .. tostring(with_annotations),
            function(machine)
                test_reset_uarch(machine, true, with_proofs, with_annotations)
            end
        )
    end
end

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing verify_reset_uarch_state_transition",
    function(machine)
        local module = cartesi
        if machine_type ~= "local" then
            module = remote
        end
        local initial_hash = machine:get_root_hash()
        local log = machine:log_reset_uarch({ proofs = true, annotations = true })
        local final_hash = machine:get_root_hash()
        -- verify happy path
        module.machine.verify_reset_uarch_state_transition(initial_hash, log, final_hash, {})
        -- verifying incorrect initial hash
        local wrong_hash = string.rep("0", 32)
        local _, err = pcall(module.machine.verify_reset_uarch_state_transition, wrong_hash, log, final_hash, {})
        assert(err:match("Mismatch in root hash of access 1"))
        -- verifying incorrect final hash
        _, err = pcall(module.machine.verify_reset_uarch_state_transition, initial_hash, log, wrong_hash, {})
        assert(err:match("mismatch in root hash after replay"))
    end
)

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing verify_reset_uarch_log",
    function(machine)
        local module = cartesi
        if machine_type ~= "local" then
            module = remote
        end
        local log = machine:log_reset_uarch({ proofs = true, annotations = true })
        module.machine.verify_reset_uarch_log(log, {})
    end
)

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Dump of log produced by log_reset_uarch should match",
    function(machine)
        local log = machine:log_reset_uarch({ proofs = true, annotations = true })
        local expected_dump_pattern = "begin reset uarch state\n"
            .. "  1: write uarch_state@0x400000%(4194304%): "
            .. 'hash:"[0-9a-f]+"%(2%^22 bytes%) %-> hash:"[0-9a-fA-F]+"%(2%^22 bytes%)\n'
            .. "end reset uarch state\n"

        local tmpname = os.tmpname()
        local deleter = {}
        setmetatable(deleter, {
            __gc = function()
                os.remove(tmpname)
            end,
        })
        local tmp <close> = io.open(tmpname, "w+")
        util.dump_log(log, tmp)
        tmp:seek("set", 0)
        local actual_dump = tmp:read("*all")

        print("Output of reset_uarch log dump:")
        print("--------------------------")
        print(actual_dump)
        print("--------------------------")
        assert(
            actual_dump:match(expected_dump_pattern),
            "Dump of uarch_reset_state does not match expected pattern:\n" .. expected_dump_pattern
        )
    end
)

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Log uarch reset with large_data option set must have consistent read and written data",
    function(machine)
        local module = cartesi
        if machine_type ~= "local" then
            module = remote
        end
        -- reset uarch and get log
        local log = machine:log_reset_uarch({ proofs = true, annotations = true, large_data = true })
        assert(#log.accesses == 1, "log should have 1 access")
        local access = log.accesses[1]
        -- in debug mode, the log must include read and written data
        assert(access.read ~= nil, "read data should not be nil")
        assert(access.written ~= nil, "written data should not be nil")
        -- verify returned log
        module.machine.verify_reset_uarch_log(log, {})
        -- save logged read and written data
        local original_read = access.read
        -- tamper with read data to produce a hash mismatch
        access.read = "X" .. access.read:sub(2)
        local _, err = pcall(module.machine.verify_reset_uarch_log, log, {})
        assert(err:match("hash of read data and read hash at access 1 does not match read hash"))
        -- restore correct read
        access.read = original_read
        --  change written data to produce a hash mismatch
        access.written = "X" .. access.written:sub(2)
        _, err = pcall(module.machine.verify_reset_uarch_log, log, {})
        assert(err:match("written hash and written data mismatch at access 1"))
    end
)

do_test("Test unhappy paths of verify_reset_uarch_state_transition", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
        module = remote
    end
    local bad_hash = string.rep("\0", 32)
    local function assert_error(expected_error, callback)
        machine:reset_uarch()
        local initial_hash = machine:get_root_hash()
        local log = machine:log_reset_uarch({ proofs = true, annotations = false })
        local final_hash = machine:get_root_hash()
        callback(log)
        local _, err = pcall(module.machine.verify_reset_uarch_state_transition, initial_hash, log, final_hash, {})
        assert(
            err:match(expected_error),
            'Error text "' .. err .. '"  does not match expected "' .. expected_error .. '"'
        )
    end
    assert_error("too few accesses in log", function(log)
        log.accesses = {}
    end)
    assert_error("expected address of access 1 to be the start address of the uarch state", function(log)
        log.accesses[1].address = 0
    end)

    assert_error("expected access 1 to write 2%^22 bytes to uarchState", function(log)
        log.accesses[1].log2_size = 64
    end)

    assert_error("hash length must be 32 bytes", function(log)
        log.accesses[#log.accesses].read_hash = nil
    end)
    assert_error("Mismatch in root hash of access 1", function(log)
        log.accesses[1].read_hash = bad_hash
    end)
    assert_error("access log was not fully consumed", function(log)
        log.accesses[#log.accesses + 1] = log.accesses[1]
    end)
    assert_error("hash length must be 32 bytes", function(log)
        log.accesses[#log.accesses].written_hash = nil
    end)
    assert_error("invalid written %(expected% string with 2%^22 bytes%)", function(log)
        log.accesses[#log.accesses].written = "\0"
    end)
    assert_error("written hash and written data mismatch at access 1", function(log)
        log.accesses[#log.accesses].written = string.rep("\0", 2 ^ 22)
    end)
    assert_error("Mismatch in root hash of access 1", function(log)
        log.accesses[1].sibling_hashes[1] = bad_hash
    end)
end)

do_test("Test unhappy paths of verify_step_uarch_state_transition", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
        module = remote
    end
    local bad_hash = string.rep("\0", 32)
    local function assert_error(expected_error, callback)
        machine:reset_uarch()
        local initial_hash = machine:get_root_hash()
        local log = machine:log_step_uarch({ proofs = true, annotations = false })
        local final_hash = machine:get_root_hash()
        callback(log)
        local _, err = pcall(module.machine.verify_step_uarch_state_transition, initial_hash, log, final_hash, {})
        assert(
            err:match(expected_error),
            'Error text "' .. err .. '"  does not match expected "' .. expected_error .. '"'
        )
    end
    assert_error("too few accesses in log", function(log)
        log.accesses = {}
    end)
    assert_error("expected access 1 to read uarch.uarch_cycle", function(log)
        log.accesses[1].address = 0
    end)
    assert_error("expected access 1 to read 2%^5 bytes from uarch.uarch_cycle", function(log)
        log.accesses[1].log2_size = 2
    end)
    assert_error("target size cannot be greater than root size", function(log)
        log.accesses[1].log2_size = 65
    end)
    assert_error("missing read uarch.uarch_cycle data at access 1", function(log)
        log.accesses[1].read = nil
    end)
    assert_error("invalid read %(expected string with 2%^5 bytes%)", function(log)
        log.accesses[1].read = "\0"
    end)
    assert_error(
        "logged read data of uarch.uarch_cycle data does not hash to the logged read hash at access 1",
        function(log)
            log.accesses[1].read_hash = bad_hash
        end
    )
    assert_error("hash length must be 32 bytes", function(log)
        log.accesses[#log.accesses].read_hash = nil
    end)
    assert_error("access log was not fully consumed", function(log)
        log.accesses[#log.accesses + 1] = log.accesses[1]
    end)
    assert_error("hash length must be 32 bytes", function(log)
        log.accesses[#log.accesses].written_hash = nil
    end)
    assert_error("invalid written %(expected string with 2%^5 bytes%)", function(log)
        log.accesses[#log.accesses].written = "\0"
    end)
    assert_error(
        "logged written data of uarch.cycle does not hash to the logged written hash at access 7",
        function(log)
            log.accesses[#log.accesses].written = string.rep("\0", 32)
        end
    )
    assert_error("Mismatch in root hash of access 1", function(log)
        log.accesses[1].sibling_hashes[1] = bad_hash
    end)
end)

print("\n\n testing unsupported uarch instructions ")

local uarch_illegal_insn_program = {
    0x00000000, -- some illegal instruction
}

test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { image_filename = test_util.create_test_uarch_program(uarch_illegal_insn_program) },
    },
})("Detect illegal instruction", function(machine)
    local success, err = pcall(machine.run_uarch, machine)
    assert(success == false)
    assert(err:match("illegal instruction"))
end)

do_test("uarch ecall putchar should print char to console", function()
    local lua_code = [[ "
                                 local cartesi = require 'cartesi'
                                 local test_util = require 'cartesi.tests.util'
                                 local cartesi_util = require 'cartesi.util'
                                 local initial_csr_values = {}
                                 local program = {
                                    (cartesi.UARCH_ECALL_FN_PUTCHAR << 20) | 0x00893, -- li	a7,putchar
                                    0x05800813, -- li	a6,'X''
                                    0x00000073, -- ecall
                                }
                                 local uarch_ram_path = test_util.create_test_uarch_program(program)
                                 local machine = cartesi.machine {
                                 processor = initial_csr_values,
                                 ram = {length = 1 << 20},
                                 uarch = {
                                    ram = { image_filename = uarch_ram_path }
                                 }
                                 }
                                 os.remove(uarch_ram_path)
                                 local log_type = {proofs = false, annotations = true}
                                 machine:run_uarch(3) -- run 3 instructions
                                 " 2>&1]]
    local p = io.popen(lua_cmd .. lua_code)
    local output = p:read(2000)
    p:close()
    local expected_output = "X"
    print("Output of uarch ecall putchar:")
    print("--------------------------")
    print(output)
    print("--------------------------")
    assert(output == expected_output, "Output does not match expected output:\n" .. expected_output)
end)

print("\n\ntesting send cmio response ")

do_test("send_cmio_response fails if iflags.Y is not set", function(machine)
    local reason = 1
    local data = string.rep("a", 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
    machine:reset_iflags_Y()
    assert(machine:read_iflags_Y() == false)
    test_util.assert_error("iflags.Y is not set", function()
        machine:send_cmio_response(reason, data)
    end)
    test_util.assert_error("iflags.Y is not set", function()
        machine:log_send_cmio_response(reason, data, {})
    end)
end)

do_test("send_cmio_response fails if data is too big", function(machine)
    local reason = 1
    local data_too_big = string.rep("a", 1 + (1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE))
    machine:set_iflags_Y()
    test_util.assert_error("address range not entirely in memory PMA", function()
        machine:send_cmio_response(reason, data_too_big)
    end)
    test_util.assert_error("address range not entirely in memory PMA", function()
        machine:log_send_cmio_response(reason, data_too_big, {})
    end)
end)

-- asserts that an access has the expected key  values
local function assert_access(accesses, index, expected_key_and_values)
    assert(index <= #accesses)
    for k, v in pairs(expected_key_and_values) do
        local a = accesses[index]
        assert(a[k] == v, "access." .. tostring(index) .. " should be " .. tostring(v) .. " but is " .. tostring(a[k]))
    end
end

local function test_send_cmio_input_with_different_arguments()
    local data = string.rep("a", 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
    local reason = 1
    local max_rx_buffer_len = 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE
    local data_hash = test_util.merkle_hash(data, 0, cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
    local all_zeros = string.rep("\0", max_rx_buffer_len)
    local all_zeros_hash = test_util.merkle_hash(all_zeros, 0, cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
    -- prepares and asserts the state before send_cmio_response is called
    local function assert_before_cmio_response_sent(machine)
        machine:set_iflags_Y()
        -- initial rx buffer should be all zeros
        assert(machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, max_rx_buffer_len) == all_zeros)
    end
    -- asserts that the machine state is as expected after send_cmio_response is called
    local function assert_after_cmio_response_sent(machine)
        -- rx buffer should now contain the data
        assert(machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, max_rx_buffer_len) == data)
        -- iflags.Y should be cleared
        assert(machine:read_iflags_Y() == false)
        -- fromhost should reflect the reason and data length
        local expected_fromhost = ((reason & 0xffff) << 32) | (#data & 0xffffffff)
        assert(machine:read_csr("htif_fromhost") == expected_fromhost)
    end
    do_test("send_cmio_response happy path", function(machine)
        assert_before_cmio_response_sent(machine)
        machine:send_cmio_response(reason, data)
        assert_after_cmio_response_sent(machine)
    end)
    for _, proofs in ipairs({ false, true }) do
        for _, large_data in ipairs({ false, true }) do
            local annotations = true
            do_test(
                string.format(
                    "log_send_cmio_response happy path with proofs=%s, annotations=%s, large_data=%s",
                    proofs,
                    annotations,
                    large_data
                ),
                function(machine)
                    local log_type = { proofs = proofs, annotations = annotations, large_data = large_data }
                    local module = cartesi
                    if machine_type ~= "local" then
                        if not remote then
                            remote = connect()
                        end
                        module = remote
                    end
                    assert_before_cmio_response_sent(machine)
                    local root_hash_before = proofs and machine:get_root_hash() or nil
                    local log = machine:log_send_cmio_response(reason, data, log_type)
                    assert_after_cmio_response_sent(machine)
                    local root_hash_after = proofs and machine:get_root_hash() or nil
                    -- check log
                    local accesses = log.accesses
                    assert(#accesses == 5)
                    assert_access(accesses, 1, {
                        type = "read",
                        address = module.machine.get_csr_address("iflags"),
                        log2_size = 3,
                    })
                    assert_access(accesses, 2, {
                        type = "write",
                        address = cartesi.PMA_CMIO_RX_BUFFER_START,
                        log2_size = cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE,
                        read_hash = all_zeros_hash,
                        read = large_data and all_zeros or nil,
                        written_hash = data_hash,
                        written = large_data and data or nil,
                    })
                    assert_access(accesses, 3, {
                        type = "write",
                        address = module.machine.get_csr_address("htif_fromhost"),
                        log2_size = 3,
                    })
                    assert_access(accesses, 4, {
                        type = "read",
                        address = module.machine.get_csr_address("iflags"),
                        log2_size = 3,
                    })
                    assert_access(accesses, 5, {
                        type = "write",
                        address = module.machine.get_csr_address("iflags"),
                        log2_size = 3,
                    })
                    -- ask machine to verify the log
                    module.machine.verify_send_cmio_response_log(reason, data, log, {})
                    if proofs then
                        -- ask machine to verify state transitions
                        module.machine.verify_send_cmio_response_state_transition(
                            reason,
                            data,
                            root_hash_before,
                            log,
                            root_hash_after,
                            log_type,
                            {}
                        )
                    end
                end
            )
        end
    end
end
test_send_cmio_input_with_different_arguments()

do_test("Dump of log produced by send_cmio_response should match", function(machine)
    machine:set_iflags_Y()
    local data = "0123456789"
    local reason = 7
    local log = machine:log_send_cmio_response(reason, data, { proofs = true, annotations = true, large_data = false })
    -- luacheck: push no max line length
    local expected_dump = "begin send cmio response\n"
        .. "  1: read iflags.Y@0x2e8(744): 0x1a(26)\n"
        .. '  2: write cmio rx buffer@0x60000000(1610612736): hash:"290decd9"(2^5 bytes) -> hash:"555b1f6d"(2^5 bytes)\n'
        .. "  3: write htif.fromhost@0x318(792): 0x0(0) -> 0x70000000a(30064771082)\n"
        .. "  4: read iflags.Y@0x2e8(744): 0x1a(26)\n"
        .. "  5: write iflags.Y@0x2e8(744): 0x1a(26) -> 0x18(24)\n"
        .. "end send cmio response\n"
    -- luacheck: pop
    local temp_file <close> = test_util.new_temp_file()
    util.dump_log(log, temp_file)
    local actual_dump = temp_file:read_all()
    print("Output of log_send_cmio_response dump:")
    print("--------------------------")
    print(actual_dump)
    print("--------------------------")
    assert(actual_dump == expected_dump, "Dump of uarch_reset_state does not match expected:\n" .. expected_dump)
end)

do_test("send_cmio_response with different data sizes", function(machine)
    local test_cases = {
        { data_len = 1, write_len = 32 },
        { data_len = 32, write_len = 32 },
        { data_len = 33, write_len = 64 },
        { data_len = 64, write_len = 64 },
        { data_len = 1 << 20, write_len = 1 << 20 },
        { data_len = (1 << 20) + 1, write_len = 1 << 21 },
        { data_len = 1 << 21, write_len = 1 << 21 },
    }
    local rx_buffer_size = 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE
    local initial_rx_buffer = string.rep("x", rx_buffer_size)
    local reason = 1
    local function padded_data(data, len, padding)
        return data .. string.rep(padding, len - #data)
    end
    for _, case in ipairs(test_cases) do
        -- test logging and lo not logging
        for _, logging in ipairs({ false, true }) do
            print(
                string.format(
                    "   testing sending cmio response of %s bytes causing a write of %s bytes with logging=%s ",
                    case.data_len,
                    case.write_len,
                    logging
                )
            )
            machine:write_memory(cartesi.PMA_CMIO_RX_BUFFER_START, initial_rx_buffer)
            assert(machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, rx_buffer_size) == initial_rx_buffer)
            local data = string.rep("a", case.data_len)
            machine:set_iflags_Y()
            if logging then
                local log = machine:log_send_cmio_response(reason, data, {})
                assert(#log.accesses == 5, string.format("log should have 5 accesses, but it has %s", #log.accesses))
                assert(log.accesses[2].type == "write", "access 2 should be a write")
                assert(1 << log.accesses[2].log2_size == case.write_len, "log2_size of write access does not match")
            else
                machine:send_cmio_response(reason, data)
            end
            local expected_rx_buffer = padded_data(data, case.write_len, "\0")
                .. string.rep("x", rx_buffer_size - case.write_len)
            local new_rx_buffer = machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, rx_buffer_size)
            assert(
                new_rx_buffer == expected_rx_buffer,
                string.format(
                    "rx_buffer\n'%s...'\n of length %s does not match\nexpected\n'%s...' of length %s",
                    string.sub(new_rx_buffer, 1, 80),
                    #new_rx_buffer,
                    string.sub(expected_rx_buffer, 1, 80),
                    #expected_rx_buffer
                )
            )
        end
    end
end)

do_test("send_cmio_response of zero bytes", function(machine)
    local module = cartesi
    if machine_type ~= "local" then
        if not remote then
            remote = connect()
        end
        module = remote
    end
    local rx_buffer_size = 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE
    local initial_rx_buffer = string.rep("x", rx_buffer_size)
    machine:write_memory(cartesi.PMA_CMIO_RX_BUFFER_START, initial_rx_buffer)
    assert(machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, rx_buffer_size) == initial_rx_buffer)
    machine:set_iflags_Y()
    local reason = 1
    local data = ""
    machine:send_cmio_response(reason, data)
    local new_rx_buffer = machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, rx_buffer_size)
    assert(new_rx_buffer == initial_rx_buffer, "rx_buffer should not have been modified")
    assert(machine:read_iflags_Y() == false, "iflags.Y should be cleared")
    -- log and verify
    machine:set_iflags_Y()
    local hash_before = machine:get_root_hash()
    local log = machine:log_send_cmio_response(reason, data, { proofs = true })
    assert(#log.accesses == 4, "log should have 4 accesses")
    local hash_after = machine:get_root_hash()
    module.machine.verify_send_cmio_response_log(reason, data, log, {})
    module.machine.verify_send_cmio_response_state_transition(reason, data, hash_before, log, hash_after, {}, {})
end)

local function test_cmio_buffers_backed_by_files()
    local rx_filename = os.tmpname()
    local tx_filename = os.tmpname()
    local rx_init_data = string.rep("R", 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
    local tx_init_data = string.rep("T", 1 << cartesi.PMA_CMIO_TX_BUFFER_LOG2_SIZE)
    local deleter = {}
    setmetatable(deleter, {
        __gc = function()
            os.remove(rx_filename)
            os.remove(tx_filename)
        end,
    })
    -- initialize test cmio files
    local rx = io.open(rx_filename, "w+")
    rx:write(rx_init_data)
    rx:close()
    local tx = io.open(tx_filename, "w+")
    tx:write(tx_init_data)
    tx:close()
    local tx_new_data = string.rep("x", 1 << cartesi.PMA_CMIO_TX_BUFFER_LOG2_SIZE)
    local rx_new_data = string.rep("y", 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)

    test_util.make_do_test(build_machine, machine_type, {
        cmio = {
            rx_buffer = { image_filename = rx_filename, shared = false },
            tx_buffer = { image_filename = tx_filename, shared = false },
        },
    })("cmio buffers initialized from backing files", function(machine)
        local rx_data = machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
        assert(rx_data == rx_init_data, "rx buffer data does not match")
        local tx_data = machine:read_memory(cartesi.PMA_CMIO_TX_BUFFER_START, 1 << cartesi.PMA_CMIO_TX_BUFFER_LOG2_SIZE)
        assert(tx_data == tx_init_data, "tx buffer data does not match")
        -- write new data to buffers to later assert that it was not written to the files
        machine:write_memory(cartesi.PMA_CMIO_RX_BUFFER_START, rx_new_data)
        machine:write_memory(cartesi.PMA_CMIO_TX_BUFFER_START, tx_new_data)
    end)
    -- the shared=false from last test should prevent saving the new data to files
    test_util.make_do_test(build_machine, machine_type, {
        cmio = {
            rx_buffer = { image_filename = rx_filename, shared = true },
            tx_buffer = { image_filename = tx_filename, shared = true },
        },
    })("cmio buffers initialized from backing files should not change", function(machine)
        local rx_data = machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
        assert(rx_data == rx_init_data, "rx buffer data does not match")
        local tx_data = machine:read_memory(cartesi.PMA_CMIO_TX_BUFFER_START, 1 << cartesi.PMA_CMIO_TX_BUFFER_LOG2_SIZE)
        assert(tx_data == tx_init_data, "tx buffer data does not match")
        -- write new data to buffers to later assert that it was written to the files
        machine:write_memory(cartesi.PMA_CMIO_RX_BUFFER_START, rx_new_data)
        machine:write_memory(cartesi.PMA_CMIO_TX_BUFFER_START, tx_new_data)
    end)
    -- the shared=true from last test should save memory changes to files
    test_util.make_do_test(build_machine, machine_type, {
        cmio = {
            rx_buffer = { image_filename = rx_filename, shared = false },
            tx_buffer = { image_filename = tx_filename, shared = false },
        },
    })("cmio buffer files should be modified by last write_memory", function(machine)
        local rx_data = machine:read_memory(cartesi.PMA_CMIO_RX_BUFFER_START, 1 << cartesi.PMA_CMIO_RX_BUFFER_LOG2_SIZE)
        assert(rx_data == rx_new_data, "rx buffer data does not match")
        local tx_data = machine:read_memory(cartesi.PMA_CMIO_TX_BUFFER_START, 1 << cartesi.PMA_CMIO_TX_BUFFER_LOG2_SIZE)
        assert(tx_data == tx_new_data, "tx buffer data does not match")
    end)
end
test_cmio_buffers_backed_by_files()

local uarch_store_double_in_t0_to_t1 = {
    0x00533023, -- sd	t0,0(t1)
}
test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { image_filename = test_util.create_test_uarch_program(uarch_store_double_in_t0_to_t1) },
    },
})("Log of word access unaligned to merkle tree leaf ", function(machine)
    local leaf_size = 1 << cartesi.TREE_LOG2_WORD_SIZE
    local word_size = 8
    local t0 = 5 -- x5 register
    local t1 = t0 + 1 -- x6 register
    local function make_leaf(w1, w2, w3, w4)
        return string.rep(w1, word_size)
            .. string.rep(w2, word_size)
            .. string.rep(w3, word_size)
            .. string.rep(w4, word_size)
    end
    -- write initial leaf data
    local leaf_data = make_leaf("\x11", "\x22", "\x33", "\x44")
    assert(#leaf_data == leaf_size)
    local leaf_address = cartesi.UARCH_RAM_START_ADDRESS + (1 << cartesi.TREE_LOG2_WORD_SIZE)
    machine:write_memory(leaf_address, leaf_data, leaf_size)

    -- step and log one instruction that stores the word in t0 to the address in t1
    -- returns raw and formatted log
    local function log_step()
        local log_type = { proofs = true, annotations = true }
        local log = machine:log_step_uarch(log_type)
        local temp_file <close> = test_util.new_temp_file()
        util.dump_log(log, temp_file)
        return log, temp_file:read_all()
    end

    -- write to the first word
    machine:write_csr("uarch_x" .. t1, leaf_address)
    machine:write_csr("uarch_x" .. t0, 0xaaaaaaaaaaaaaaaa)
    local log, dump = log_step()
    assert(dump:match("7: write memory@0x%x+%(%d+%): 0x1111111111111111%(%d+%) %-> 0xaaaaaaaaaaaaaaaa%(%d+%)"))
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size) -- read and check written data
    assert(leaf_data == make_leaf("\xaa", "\x22", "\x33", "\x44"))
    assert(log.accesses[7].written == leaf_data)

    -- restart program and write to second leaf word
    machine:write_csr("uarch_pc", cartesi.UARCH_RAM_START_ADDRESS)
    machine:write_csr("uarch_x" .. t1, machine:read_csr("uarch_x" .. t1) + word_size)
    machine:write_csr("uarch_x" .. t0, 0xbbbbbbbbbbbbbbbb)
    log, dump = log_step()
    assert(dump:match("7: write memory@0x%x+%(%d+%): 0x2222222222222222%(%d+%) %-> 0xbbbbbbbbbbbbbbbb%(%d+%)"))
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size)
    assert(leaf_data == make_leaf("\xaa", "\xbb", "\x33", "\x44"))
    assert(log.accesses[7].written == leaf_data)

    -- restart program and write to third leaf word
    machine:write_csr("uarch_pc", cartesi.UARCH_RAM_START_ADDRESS)
    machine:write_csr("uarch_x" .. t1, machine:read_csr("uarch_x" .. t1) + word_size)
    machine:write_csr("uarch_x" .. t0, 0xcccccccccccccccc)
    log, dump = log_step()
    assert(dump:match("7: write memory@0x%x+%(%d+%): 0x3333333333333333%(%d+%) %-> 0xcccccccccccccccc%(%d+%)"))
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size)
    assert(leaf_data == make_leaf("\xaa", "\xbb", "\xcc", "\x44"))
    assert(log.accesses[7].written == leaf_data)

    -- restart program and write to fourth leaf word
    machine:write_csr("uarch_pc", cartesi.UARCH_RAM_START_ADDRESS)
    machine:write_csr("uarch_x" .. t1, machine:read_csr("uarch_x" .. t1) + word_size)
    machine:write_csr("uarch_x" .. t0, 0xdddddddddddddddd)
    log, dump = log_step()
    assert(dump:match("7: write memory@0x%x+%(%d+%): 0x4444444444444444%(%d+%) %-> 0xdddddddddddddddd%(%d+%)"))
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size)
    assert(leaf_data == make_leaf("\xaa", "\xbb", "\xcc", "\xdd"))
    assert(log.accesses[7].written == leaf_data)
end)

print("\n\nAll machine binding tests for type " .. machine_type .. " passed")
