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
local jsonrpc

local remote_address
local test_path = "./"
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

  --remote-address=<ip>:<port>
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

local function get_uarch_cpu_reg_test_values()
    local registers = {}
    for i = 0, 31 do
        registers["x" .. i] = 0x10000 + (i * 8)
    end
    return registers
end

local function get_cpu_reg_test_values()
    local reg_values = {
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
        reg_values["x" .. i] = i * 8
    end
    return reg_values
end

local function check_error_find(err, expected_err)
    if not err then
        error("expected error with '" .. expected_err .. "' (got no error)")
    end
    if not err:find(expected_err, 1, true) then
        error("expected error with '" .. expected_err .. "' (got '" .. tostring(err) .. "')")
    end
end

local machine_type = assert(arguments[1], "missing machine type")
assert(machine_type == "local" or machine_type == "jsonrpc", "unknown machine type, should be 'local' or 'jsonrpc'")
local to_shutdown -- luacheck: no unused
if machine_type == "jsonrpc" then
    assert(remote_address ~= nil, "remote cartesi machine address is missing")
    assert(test_path ~= nil, "test path must be provided and must be working directory of remote cartesi machine")
    jsonrpc = require("cartesi.jsonrpc")
    to_shutdown = jsonrpc.connect_server(remote_address):set_cleanup_call(jsonrpc.SHUTDOWN)
end

local function build_machine_config(config_options)
    if not config_options then
        config_options = {}
    end

    -- Create new machine
    local initial_reg_values = get_cpu_reg_test_values()
    local config = {
        processor = config_options.processor or {
            registers = initial_reg_values,
        },
        ram = { length = 1 << 20 },
        cmio = config_options.cmio or nil,
        uarch = config_options.uarch
            or {
                processor = {
                    registers = get_uarch_cpu_reg_test_values(),
                },
                ram = {
                    length = 0x1000,
                    backing_store = {
                        data_filename = test_util.create_test_uarch_program(test_util.uarch_programs.default),
                    },
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
        local jsonrpc_machine <close> = assert(jsonrpc.connect_server(remote_address))
        new_machine = assert(jsonrpc_machine(config, runtime):set_cleanup_call(jsonrpc.SHUTDOWN))
    else
        new_machine = assert(cartesi.machine(config, runtime))
    end
    if config.uarch.ram and config.uarch.ram.backing_store and config.uarch.ram.backing_store.data_filename then
        os.remove(config.uarch.ram.backing_store.data_filename)
    end
    return new_machine
end

local do_test = test_util.make_do_test(build_machine, machine_type)

print("Testing machine bindings for type " .. machine_type)

print("\n\ntesting machine initial flags")
do_test("machine should not have halt and yield initial flags set", function(machine)
    -- Check machine is not halted
    assert(machine:read_reg("iflags_H") == 0, "machine shouldn't be halted")
    -- Check machine is not yielded
    assert(machine:read_reg("iflags_Y") == 0, "machine shouldn't be yielded")
end)

print("\n\ntesting machine register initial flag values ")
do_test("machine should have default config shadow register values", function(machine)
    local initial_reg_values = get_cpu_reg_test_values()
    initial_reg_values.mvendorid = nil
    initial_reg_values.marchid = nil
    initial_reg_values.mimpid = nil
    -- Check initialization and shadow reads
    for k, v in pairs(initial_reg_values) do
        assert(v == machine:read_word(machine:get_reg_address(k)))
    end
end)

print("\n\ntesting merkle tree get_proof for values for registers")
do_test("should provide proof for values in registers", function(machine)
    local initial_reg_values = get_cpu_reg_test_values()
    initial_reg_values.mvendorid = nil
    initial_reg_values.marchid = nil
    initial_reg_values.mimpid = nil

    -- Check proofs
    for _, v in pairs(initial_reg_values) do
        for el = cartesi.TREE_LOG2_WORD_SIZE, cartesi.TREE_LOG2_ROOT_SIZE - 1 do
            local a = test_util.align(v, el)
            assert(test_util.check_proof(assert(machine:get_proof(a, el), "no proof")), "proof failed")
        end
    end
end)

print("\n\ntesting get_reg_address function binding")
do_test("should return address value for registers", function(machine)
    -- Check register address
    local initial_reg_values = get_cpu_reg_test_values()
    for k, v in pairs(initial_reg_values) do
        assert(machine:read_reg(k) == machine:read_word(machine:get_reg_address(k)), "invalid return for " .. v)
    end
end)

print("\n\ntesting get x address function binding")
do_test("should return address value for x registers", function(machine)
    -- Check x address
    for i = 0, 31 do
        assert(machine:get_reg_address("x" .. i) == SHADOW_BASE + i * 8, "invalid return for x" .. i)
    end
end)

print("\n\ntesting get x uarch_address function binding")
do_test("should return address value for uarch x registers", function(machine)
    local SHADOW_UARCH_XBASE = cartesi.UARCH_SHADOW_START_ADDRESS + 24
    -- Check x address
    for i = 0, 31 do
        assert(machine:get_reg_address("uarch_x" .. i) == SHADOW_UARCH_XBASE + i * 8, "invalid return for uarch x" .. i)
    end
end)

local function getfield(t, i, i_prev)
    if not t then
        return nil
    end
    for f in (i .. "."):gmatch("([^%.]*)%.") do
        if type(t) ~= "table" then
            error(string.format("type of %s is %s (expected table)", i_prev, type(t)))
        end
        t = t[f]
        i_prev = i_prev .. "." .. f
        if not t then
            return nil
        end
    end
    return t
end

local function assertfield(t, i, expected, i_prev, needed)
    i_prev = i_prev or "config"
    local what = type(getfield(t, i, i_prev))
    if what ~= expected and what ~= "nil" or needed and what == "nil" then
        error(string.format("type of %s.%s is %s (expected %s)", i_prev, i, what, expected))
    end
end

local function test_backing_store_config(config, name, i_prev)
    assertfield(config, name .. ".shared", "boolean", i_prev)
    assertfield(config, name .. ".truncate", "boolean", i_prev)
    assertfield(config, name .. ".data_filename", "string", i_prev)
    assertfield(config, name .. ".dht_filename", "string", i_prev)
end

local function test_flash_drive_config(config, i_prev)
    assertfield(config, "length", "number", i_prev, "needed")
    assertfield(config, "start", "number", i_prev, "needed")
    test_backing_store_config(config, "backing_store", i_prev)
end

local function test_config(config)
    assert(type(config) == "table", "config not a table")
    local config_fields = {
        "processor",
        "ram",
        "dtb",
        "flash_drive",
        "virtio",
        "cmio",
        "pmas",
        "uarch",
        "hash_tree",
    }
    for _, field in ipairs(config_fields) do
        assertfield(config, field, "table", "config", "needed")
    end
    for i = 0, 31 do
        assertfield(config.processor, "registers.x" .. i, "number", "processor", "needed")
    end
    for i = 0, 31 do
        assertfield(config.processor, "registers.f" .. i, "number", "processor", "needed")
    end
    local csrs = {
        "pc",
        "fcsr",
        "mvendorid",
        "marchid",
        "mimpid",
        "mcycle",
        "icycleinstret",
        "mstatus",
        "mtvec",
        "mscratch",
        "mepc",
        "mcause",
        "mtval",
        "misa",
        "mie",
        "mip",
        "medeleg",
        "mideleg",
        "mcounteren",
        "menvcfg",
        "stvec",
        "sscratch",
        "sepc",
        "scause",
        "stval",
        "satp",
        "scounteren",
        "senvcfg",
        "ilrsc",
        "iprv",
        "iflags.X",
        "iflags.Y",
        "iflags.H",
        "iunrep",
        "htif.ihalt",
        "htif.iconsole",
        "htif.iyield",
        "htif.tohost",
        "htif.fromhost",
        "clint.mtimecmp",
        "plic.girqpend",
        "plic.girqsrvd",
    }
    for _, csr in ipairs(csrs) do
        assertfield(config.processor, "registers." .. csr, "number", "processor", "needed")
    end
    assertfield(config, "ram.length", "number")
    test_backing_store_config(config, "ram.backing_store")
    assertfield(config, "dtb.bootargs", "string")
    assertfield(config, "dtb.init", "string")
    assertfield(config, "dtb.entrypoint", "string")
    test_backing_store_config(config, "dtb.backing_store")
    test_backing_store_config(config, "processor.backing_store")
    test_backing_store_config(config, "pmas.backing_store")
    for i, f in ipairs(config.flash_drive or {}) do
        test_flash_drive_config(f, "config.flash_drive[" .. i .. "]")
    end
    test_backing_store_config(config, "cmio.rx_buffer.backing_store")
    test_backing_store_config(config, "cmio.tx_buffer.backing_store")
    test_backing_store_config(config, "uarch.processor.backing_store")
    test_backing_store_config(config, "uarch.ram.backing_store")
    assertfield(config, "hash_tree.shared", "boolean")
    assertfield(config, "hash_tree.truncate", "boolean")
    assertfield(config, "hash_tree.sht_filename", "string")
    assertfield(config, "hash_tree.phtc_filename", "string")
    assertfield(config, "hash_tree.phtc_size", "number")
end

print("\n\ntesting get_default_config function binding")
do_test("should return default machine config", function(machine)
    test_config(machine:get_default_config())
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
    assert(initial_config.processor.registers.pc == 0x200, "wrong pc reg initial config value")
    assert(initial_config.processor.registers.ilrsc == 0x2e0, "wrong ilrsc reg initial config value")
    assert(initial_config.processor.registers.mstatus == 0x230, "wrong mstatus reg initial config value")
    assert(initial_config.processor.registers.clint.mtimecmp == 0, "wrong clint mtimecmp initial config value")
    assert(initial_config.processor.registers.plic.girqpend == 0, "wrong plic girqpend initial config value")
    assert(initial_config.processor.registers.plic.girqsrvd == 0, "wrong plic girqsrvd initial config value")
    assert(initial_config.processor.registers.htif.fromhost == 0, "wrong htif fromhost initial config value")
    assert(initial_config.processor.registers.htif.tohost == 0, "wrong htif tohost initial config value")
    assert(
        initial_config.processor.registers.htif.iyield
            == cartesi.HTIF_YIELD_CMD_MANUAL_MASK | cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK,
        "wrong htif yield automatic initial config value"
    )
end)

print("\n\n test read_reg")
do_test("should return expected values", function(machine)
    local initial_reg_values = get_cpu_reg_test_values()
    initial_reg_values.mvendorid = cartesi.MVENDORID
    initial_reg_values.marchid = cartesi.MARCHID
    initial_reg_values.mimpid = cartesi.MIMPID
    initial_reg_values.htif_tohost = 0x0
    initial_reg_values.htif_fromhost = 0x0
    initial_reg_values.htif_ihalt = 0x0
    initial_reg_values.htif_iconsole = 0x0
    initial_reg_values.htif_iyield = cartesi.HTIF_YIELD_CMD_MANUAL_MASK | cartesi.HTIF_YIELD_CMD_AUTOMATIC_MASK

    -- Check register read
    local to_ignore = {
        iflags_X = true,
        iflags_Y = true,
        iflags_H = true,
        iprv = true,
        clint_mtimecmp = true,
        plic_girqpend = true,
        plic_girqsrvd = true,
        htif_ihalt = true,
        htif_iconsole = true,
    }
    for k in pairs(initial_reg_values) do
        if not to_ignore[k] then
            assert(machine:read_reg(k) == initial_reg_values[k], "wrong " .. k .. " value")
        end
    end
end)

print("\n\n read and write x registers")
do_test("written and expected register values should match", function(machine)
    -- Write/Read X registers
    local initial_reg_values = get_cpu_reg_test_values()
    local x1_initial_value = machine:read_reg("x1")
    assert(x1_initial_value == initial_reg_values.x1, "error reading x1 register")
    machine:write_reg("x1", 0x1122)
    assert(machine:read_reg("x1") == 0x1122, "error with writing to x1 register")
    machine:write_reg("x1", x1_initial_value)
    assert(machine:read_reg("x1") == x1_initial_value)
    -- Read invalid register
    local status_invalid_reg = pcall(machine.read_reg, machine, "x1000")
    assert(status_invalid_reg == false, "no error reading invalid x register")
end)

print("\n\n read and write uarch x registers")
do_test("written and expected register values should match", function(machine)
    -- Write/Read uarch X registers
    local initial_reg_values = get_uarch_cpu_reg_test_values()
    local x1_initial_value = machine:read_reg("uarch_x1")
    assert(x1_initial_value == initial_reg_values.x1, "error reading uarch x1 register")
    machine:write_reg("uarch_x1", 0x1122)
    assert(machine:read_reg("uarch_x1") == 0x1122, "error with writing to uarch x1 register")
    machine:write_reg("uarch_x1", x1_initial_value)
    assert(machine:read_reg("uarch_x1") == x1_initial_value)
    -- Read invalid uarch register
    local status_invalid_reg = pcall(machine.read_reg, machine, "uarch_x1000")
    assert(status_invalid_reg == false, "no error reading invalid uarch x register")
end)

print("\n\n read and write machine registers")
do_test("written and expected register values should match", function(machine)
    -- Check register write
    local sscratch_initial_value = machine:read_reg("sscratch")
    assert(machine:read_reg("sscratch") == sscratch_initial_value, "error reading register sscratch")
    machine:write_reg("sscratch", 0x1122)
    assert(machine:read_reg("sscratch") == 0x1122)
    machine:write_reg("sscratch", sscratch_initial_value)

    -- Read invalid register
    local status_invalid_reg = pcall(machine.read_reg, machine, "invalidreg")
    assert(status_invalid_reg == false, "no error reading invalid register")
end)

print("\n\n perform step and check mcycle register")
do_test("mcycle value should match", function(machine)
    local uarch_cycle_initial_value = machine:read_reg("uarch_cycle")

    machine:log_step_uarch()

    -- Check mcycle increment
    local uarch_cycle_current_value = machine:read_reg("uarch_cycle")
    assert(uarch_cycle_current_value == uarch_cycle_initial_value + 1, "wrong uarch_cycle value")
end)

do_test("should error if target mcycle is smaller than current mcycle", function(machine)
    machine:write_reg("mcycle", MAX_MCYCLE)
    assert(machine:read_reg("mcycle") == MAX_MCYCLE)
    local success, err = pcall(function()
        machine:run(MAX_MCYCLE - 1)
    end)
    assert(success == false)
    check_error_find(err, "mcycle is past")
    assert(machine:read_reg("mcycle") == MAX_MCYCLE)
end)

do_test("should error if target uarch_cycle is smaller than current uarch_cycle", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local success, err = pcall(function()
        machine:run_uarch(MAX_UARCH_CYCLE - 1)
    end)
    assert(success == false)
    check_error_find(err, "uarch_cycle is past")
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
end)

print("\n\n run_uarch tests")

do_test("advance one micro cycle without halting", function(machine)
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should be 0")
    assert(machine:read_reg("uarch_halt_flag") == 0, "uarch halt flag should be cleared")
    assert(machine:read_reg("iflags_Y") == 0, "iflags.Y should be cleared")
    assert(machine:read_reg("iflags_H") == 0, "iflags.H should be cleared")
    local status = machine:run_uarch(1)
    assert(status == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_CYCLE)
    assert(machine:read_reg("uarch_cycle") == 1, "uarch cycle should be 1")
    assert(machine:read_reg("uarch_halt_flag") == 0, "uarch should not be halted")
end)

do_test("do not advance micro cycle if uarch is halted", function(machine)
    machine:write_reg("uarch_halt_flag", 1)
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should be 0")
    assert(machine:read_reg("uarch_halt_flag") ~= 0, "uarch halt flag should be set")
    assert(machine:read_reg("iflags_Y") == 0, "iflags.Y should be cleared")
    assert(machine:read_reg("iflags_H") == 0, "iflags.H should be cleared")
    local status = machine:run_uarch(1)
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED, "run_uarch should return UARCH_BREAK_REASON_UARCH_HALTED")
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should still be 0")
end)

do_test("advance micro cycles until halt", function(machine)
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should be 0")
    assert(machine:read_reg("uarch_halt_flag") == 0, "machine should not be halted")
    local status = machine:run_uarch()
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
    assert(machine:read_reg("uarch_cycle") == 3, "uarch cycle should be 4")
    assert(machine:read_reg("uarch_halt_flag") ~= 0, "uarch should be halted")
end)

print("\n\n run machine to 1000 mcycle")
do_test("mcycle value should be 1000 after execution", function(machine)
    -- Run machine
    machine:write_reg("mcycle", 0)
    assert(machine:read_reg("mcycle") == 0)

    local test = machine:read_reg("mcycle")
    while test < 1000 do
        machine:run(1000)
        test = machine:read_reg("mcycle")
    end
    assert(machine:read_reg("mcycle") == 1000)
end)

print("\n\n check reading and writing htif registers")
do_test("htif register values should match", function(machine)
    -- Check HTIF interface bindings
    assert(machine:read_reg("htif_tohost"), "error reading htif tohost")
    assert(machine:read_reg("htif_tohost_dev"), "error reading htif tohost dev")
    assert(machine:read_reg("htif_tohost_cmd"), "error reading htif tohost cmd")
    assert(machine:read_reg("htif_tohost_data"), "error reading htif tohost data")
    assert(machine:read_reg("htif_fromhost"), "error reading htif fromhost")
    machine:write_reg("htif_tohost", 0x123456)
    assert(machine:read_reg("htif_tohost") == 0x123456, "error writing htif tohost")
    machine:write_reg("htif_fromhost", 0x12345678)
    assert(machine:read_reg("htif_fromhost") == 0x12345678, "error writing htif fromhost")
    machine:write_reg("htif_fromhost_data", 0x12345678)
    assert(machine:read_reg("htif_ihalt"), "error reading htif ihalt")
    assert(machine:read_reg("htif_iyield"), "error reading htif yield")
end)

print("\n\n check memory reading/writing")
do_test("written and read values should match", function(machine)
    -- Check mem write and mem read
    local written = "mydataol12345678"
    machine:write_memory(0x800000FF, written)
    local read = machine:read_memory(0x800000FF, written:len())
    if read ~= written then
        error(string.format("expected %q (got %q)", written, read))
    end
end)

print("\n\n dump step log to console")
do_test("dumped step log content should match", function(machine)
    local log = machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS | cartesi.ACCESS_LOG_TYPE_LARGE_DATA)
    local temp_file <close> = test_util.new_temp_file()
    util.dump_log(log, temp_file)
    local log_output = temp_file:read_all()
    -- luacheck: push no max line length
    local expected_output = "begin step\n"
        .. "  1: read uarch.cycle@0x400008(4194312): 0x0(0)\n"
        .. "  2: read uarch.halt_flag@0x400000(4194304): 0x0(0)\n"
        .. "  3: read uarch.pc@0x400010(4194320): 0x600000(6291456)\n"
        .. "  4: read uarch.ram@0x600000(6291456): 0x10089307b00513(4513027209561363)\n"
        .. "  begin addi\n"
        .. "    5: read uarch.x0@0x400018(4194328): 0x0(0)\n"
        .. "    6: write uarch.x10@0x400068(4194408): 0x10050(65616) -> 0x7b(123)\n"
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
    local initial_hash = machine:get_root_hash()
    local log = machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
    local final_hash = machine:get_root_hash()
    machine:verify_step_uarch(initial_hash, log, final_hash)
end)

print("\n\ntesting step and verification")
do_test("Step log must contain conssitent data hashes", function(machine)
    local wrong_hash = string.rep("\0", cartesi.HASH_SIZE)
    local initial_hash = machine:get_root_hash()
    local log = machine:log_step_uarch()
    local final_hash = machine:get_root_hash()
    machine:verify_step_uarch(initial_hash, log, final_hash)
    local read_access = log.accesses[1]
    assert(read_access.type == "read")
    local read_hash = read_access.read_hash
    -- ensure that verification fails with wrong read hash
    read_access.read_hash = wrong_hash
    local _, err = pcall(machine.verify_step_uarch, machine, initial_hash, log, final_hash)
    check_error_find(err, "siblings and read hash do not match root hash before 1st access to uarch.cycle")
    read_access.read_hash = read_hash -- restore correct value

    -- ensure that verification fails with wrong read hash
    local write_access = log.accesses[#log.accesses]
    assert(write_access.type == "write")
    read_hash = write_access.read_hash
    write_access.read_hash = wrong_hash
    _, err = pcall(machine.verify_step_uarch, machine, initial_hash, log, final_hash)
    check_error_find(err, "siblings and read hash do not match root hash before 8th access to uarch.cycle")
    write_access.read_hash = read_hash -- restore correct value

    -- ensure that verification fails with wrong written hash
    write_access.written_hash = wrong_hash
    _, err = pcall(machine.verify_step_uarch, machine, initial_hash, log, final_hash)
    check_error_find(err, "written hash for uarch.cycle does not match expected hash in 8th access")
end)

do_test("step when uarch cycle is max", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local initial_hash = machine:get_root_hash()
    local log = machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local final_hash = machine:get_root_hash()
    assert(final_hash == initial_hash)
    machine:verify_step_uarch(initial_hash, log, final_hash)
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
        ram = { backing_store = { data_filename = test_util.create_test_uarch_program(uarch_proof_step_program) } },
    },
})("merkle tree must be consistent when stepping alternating with and without proofs", function(machine)
    local t0 = 5
    local t1 = 6
    local t2 = 7
    local uarch_ram_start = cartesi.UARCH_RAM_START_ADDRESS

    machine:log_step_uarch() -- auipc	t0,0x0
    machine:log_step_uarch() -- addi	t0,t0,256 # 0x100
    assert(machine:read_reg("uarch_x" .. t0) == uarch_ram_start + 0x100)
    machine:log_step_uarch() -- li	t1,0xca
    assert(machine:read_reg("uarch_x" .. t1) == 0xca)
    machine:log_step_uarch() -- li	t2,0xfe
    assert(machine:read_reg("uarch_x" .. t2) == 0xfe)

    -- sd and assert stored correctly
    machine:log_step_uarch() -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)

    -- sd and assert stored correctly
    machine:log_step_uarch() -- t2,0(t0) [0xfe]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xfe)

    -- This step should run successfully
    -- The previous unproven step should have marked the updated pages dirty, allowing
    -- the tree to be updated correctly in the next proved step
    machine:log_step_uarch() -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)
end)

test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { backing_store = { data_filename = test_util.create_test_uarch_program(uarch_proof_step_program) } },
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

test_util.make_do_test(build_machine, machine_type, { processor = { registers = { mcycle = 1 } }, uarch = {} })(
    "It should use the embedded uarch-ram.bin when the uarch config is not provided",
    function(machine)
        assert(machine:read_reg("mcycle") == 1)

        -- Advance one mcycle by running the "big interpreter" compiled to the microarchitecture that is embedded
        -- in the emulator executable. Note that the config used to create the machine has an empty uarch key;
        -- therefore, the embedded uarch image is used.
        machine:run_uarch()

        assert(machine:read_reg("mcycle") == 2)
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
        machine:log_step_uarch()
        local hash_after_step = machine:get_root_hash()
        assert(hash_after_step ~= initial_hash)
        -- reset should restore initial hash
        machine:reset_uarch()
        local hash_after_second_reset = machine:get_root_hash()
        assert(hash_after_second_reset == initial_hash)
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
        registers = {
            halt_flag = 1,
            cycle = 1,
            pc = 0,
        },
    },
}
for i = 0, 31 do
    test_reset_uarch_config.processor.registers["x" .. i] = 0x10000 + (i * 8)
end

local function test_reset_uarch(machine, with_log, with_annotations)
    -- assert initial fixture state
    assert(machine:read_reg("uarch_halt_flag") ~= 0)
    assert(machine:read_reg("uarch_cycle") == 1)
    assert(machine:read_reg("uarch_pc") == 0)
    for i = 1, 31 do
        assert(machine:read_reg("uarch_x" .. i) == test_reset_uarch_config.processor.registers["x" .. i])
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
        local log_type = (with_annotations and cartesi.ACCESS_LOG_TYPE_ANNOTATIONS or 0)
        local log = machine:log_reset_uarch(log_type)
        assert(#log.accesses == 1)
        local access = log.accesses[1]
        assert(access.sibling_hashes ~= nil)
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
    assert(machine:read_reg("uarch_halt_flag") == 0)
    assert(machine:read_reg("uarch_cycle") == 0)
    assert(machine:read_reg("uarch_pc") == cartesi.UARCH_RAM_START_ADDRESS)
    for i = 1, 31 do
        assert(machine:read_reg("uarch_x" .. i) == 0)
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
        test_reset_uarch(machine, false, false)
    end
)

for _, with_annotations in ipairs({ true, false }) do
    test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
        "Testing reset_uarch with logging, annotations=" .. tostring(with_annotations),
        function(machine)
            test_reset_uarch(machine, true, with_annotations)
        end
    )
end

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing verify_reset_uarch",
    function(machine)
        local initial_hash = machine:get_root_hash()
        local log = machine:log_reset_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
        local final_hash = machine:get_root_hash()
        -- verify happy path
        machine:verify_reset_uarch(initial_hash, log, final_hash)
        -- verifying incorrect initial hash
        local wrong_hash = string.rep("0", cartesi.HASH_SIZE)
        local _, err = pcall(machine.verify_reset_uarch, machine, wrong_hash, log, final_hash)
        check_error_find(err, "siblings and read hash do not match root hash before 1st access to uarch.state")
        -- verifying incorrect final hash
        _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, log, wrong_hash)
        check_error_find(err, "mismatch in root hash after replay")
    end
)

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing verify_reset_uarch",
    function(machine)
        local initial_hash = machine:get_root_hash()
        local log = machine:log_reset_uarch()
        local final_hash = machine:get_root_hash()
        machine:verify_reset_uarch(initial_hash, log, final_hash)
    end
)

test_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Dump of log produced by log_reset_uarch should match",
    function(machine)
        local log = machine:log_reset_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
        local expected_dump_pattern = "begin reset_uarch_state\n"
            .. "  1: write uarch.state@0x400000%(4194304%): "
            .. 'hash:"[0-9a-f]+"%(2%^22 bytes%) %-> hash:"[0-9a-fA-F]+"%(2%^22 bytes%)\n'
            .. "end reset_uarch_state\n"

        local tmpname = os.tmpname()
        local deleter = {}
        setmetatable(deleter, {
            __gc = function()
                os.remove(tmpname)
            end,
        })
        local tmp <close> = assert(io.open(tmpname, "w+"))
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
        -- reset uarch and get log
        local initial_hash = machine:get_root_hash()
        local log = machine:log_reset_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS | cartesi.ACCESS_LOG_TYPE_LARGE_DATA)
        local final_hash = machine:get_root_hash()
        assert(#log.accesses == 1, "log should have 1 access")
        local access = log.accesses[1]
        -- when large data is requested, the log must include read and written data
        assert(access.read ~= nil, "read data should not be nil")
        assert(access.written ~= nil, "written data should not be nil")
        -- verify returned log
        machine:verify_reset_uarch(initial_hash, log, final_hash)
        -- save logged read and written data
        local original_read = access.read
        -- tamper with read data to produce a hash mismatch
        access.read = "X" .. access.read:sub(2)
        local _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, log, final_hash)
        check_error_find(err, "read data for uarch.state does not match read hash in 1st access")
        -- restore correct read
        access.read = original_read
        --  change written data to produce a hash mismatch
        access.written = "X" .. access.written:sub(2)
        _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, log, final_hash)
        check_error_find(err, "written data for uarch.state does not match written hash in 1st access")
    end
)

do_test("Test unhappy paths of verify_reset_uarch", function(machine)
    local bad_hash = string.rep("\0", cartesi.HASH_SIZE)
    local function assert_error(expected_error, callback)
        machine:reset_uarch()
        local initial_hash = machine:get_root_hash()
        local log = machine:log_reset_uarch()
        local final_hash = machine:get_root_hash()
        callback(log)
        local _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, log, final_hash)
        check_error_find(err, expected_error)
    end
    assert_error("log is missing access 1st access to uarch.state", function(log)
        log.accesses = {}
    end)
    assert_error("expected 1st access to write uarch.state at address 0x400000(4194304)", function(log)
        log.accesses[1].address = 0
    end)

    assert_error('"log/accesses/0/log2_size" is out of bounds', function(log)
        log.accesses[1].log2_size = 64
    end)

    assert_error('missing field "log/accesses/0/read_hash"', function(log)
        log.accesses[#log.accesses].read_hash = nil
    end)
    assert_error("siblings and read hash do not match root hash before 1st access to uarch.state", function(log)
        log.accesses[1].read_hash = bad_hash
    end)
    assert_error("access log was not fully consumed", function(log)
        log.accesses[#log.accesses + 1] = log.accesses[1]
    end)
    assert_error("missing written hash of uarch.state in 1st access", function(log)
        log.accesses[#log.accesses].written_hash = nil
    end)
    assert_error('"log/accesses/0/written" has wrong length', function(log)
        log.accesses[#log.accesses].written = "\0"
    end)
    assert_error("written data for uarch.state does not match written hash in 1st access", function(log)
        log.accesses[#log.accesses].written = string.rep("\0", 2 ^ 22)
    end)
    assert_error("siblings and read hash do not match root hash before 1st access to uarch.state", function(log)
        log.accesses[1].sibling_hashes[1] = bad_hash
    end)
end)

do_test("Test unhappy paths of verify_step_uarch", function(machine)
    local bad_hash = string.rep("\0", cartesi.HASH_SIZE)
    local function assert_error(expected_error, callback)
        machine:reset_uarch()
        local initial_hash = machine:get_root_hash()
        local log = machine:log_step_uarch()
        local final_hash = machine:get_root_hash()
        callback(log)
        local _, err = pcall(machine.verify_step_uarch, machine, initial_hash, log, final_hash)
        check_error_find(err, expected_error)
    end
    assert_error("log is missing access 1st access to uarch.cycle", function(log)
        log.accesses = {}
    end)
    assert_error("expected 1st access to read uarch.cycle", function(log)
        log.accesses[1].address = 0
    end)
    assert_error("expected 1st access to uarch.cycle to read 2^3 bytes", function(log)
        log.accesses[1].log2_size = 2
    end)
    assert_error("is out of bounds", function(log)
        log.accesses[1].log2_size = 65
    end)
    assert_error("missing read data for uarch.cycle in 1st access", function(log)
        log.accesses[1].read = nil
    end)
    assert_error("has wrong length", function(log)
        log.accesses[1].read = "\0"
    end)
    assert_error("siblings and read hash do not match root hash before 1st access to uarch.cycle", function(log)
        log.accesses[1].read_hash = bad_hash
    end)
    assert_error("missing field", function(log)
        log.accesses[#log.accesses].read_hash = nil
    end)
    assert_error("access log was not fully consumed", function(log)
        log.accesses[#log.accesses + 1] = log.accesses[1]
    end)
    assert_error("missing written hash of uarch.cycle in 7th access", function(log)
        log.accesses[#log.accesses].written_hash = nil
    end)
    assert_error("has wrong length", function(log)
        log.accesses[#log.accesses].written = "\0"
    end)
    assert_error("written data for uarch.cycle does not match written hash in 7th access", function(log)
        log.accesses[#log.accesses].written = string.rep("\0", cartesi.HASH_SIZE)
    end)
    assert_error("siblings and read hash do not match root hash before 1st access to uarch.cycle", function(log)
        log.accesses[1].sibling_hashes[1] = bad_hash
    end)
end)

print("\n\n testing unsupported uarch instructions ")

local uarch_illegal_insn_program = {
    0x00000000, -- some illegal instruction
}

test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { backing_store = { data_filename = test_util.create_test_uarch_program(uarch_illegal_insn_program) } },
    },
})("Detect illegal instruction", function(machine)
    local success, err = pcall(machine.run_uarch, machine)
    assert(success == false)
    check_error_find(err, "illegal instruction")
end)

do_test("uarch ecall putchar should print char to console", function()
    local lua_code = [[ "
                                 local cartesi = require 'cartesi'
                                 local test_util = require 'cartesi.tests.util'
                                 local cartesi_util = require 'cartesi.util'
                                 local initial_reg_values = {}
                                 local program = {
                                    (cartesi.UARCH_ECALL_FN_PUTCHAR << 20) | 0x00893, -- li	a7,putchar
                                    0x05800513, -- li a0,'X'
                                    0x00000073, -- ecall
                                 }
                                 local uarch_ram_path = test_util.create_test_uarch_program(program)
                                 local machine = cartesi.machine {
                                     registers = initial_reg_values,
                                     ram = {length = 1 << 20},
                                     uarch = {
                                        ram = { backing_store = { data_filename = uarch_ram_path } }
                                     }
                                 }
                                 os.remove(uarch_ram_path)
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
    local data = string.rep("a", 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
    machine:write_reg("iflags_Y", 0)
    assert(machine:read_reg("iflags_Y") == 0)
    test_util.assert_error("iflags.Y is not set", function()
        machine:send_cmio_response(reason, data)
    end)
    test_util.assert_error("iflags.Y is not set", function()
        machine:log_send_cmio_response(reason, data)
    end)
end)

do_test("send_cmio_response fails if data is too big", function(machine)
    local reason = 1
    local data_too_big = string.rep("a", 1 + (1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE))
    machine:write_reg("iflags_Y", 1)
    test_util.assert_error("CMIO response data is too large", function()
        machine:send_cmio_response(reason, data_too_big)
    end)
    test_util.assert_error("CMIO response data is too large", function()
        machine:log_send_cmio_response(reason, data_too_big)
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
    local data = string.rep("a", 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
    local reason = 1
    local max_rx_buffer_len = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE
    local data_hash = test_util.merkle_hash(data, 0, cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
    local all_zeros = string.rep("\0", max_rx_buffer_len)
    local all_zeros_hash = test_util.merkle_hash(all_zeros, 0, cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
    -- prepares and asserts the state before send_cmio_response is called
    local function assert_before_cmio_response_sent(machine)
        machine:write_reg("iflags_Y", 1)
        -- initial rx buffer should be all zeros
        assert(machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, max_rx_buffer_len) == all_zeros)
    end
    -- asserts that the machine state is as expected after send_cmio_response is called
    local function assert_after_cmio_response_sent(machine)
        -- rx buffer should now contain the data
        assert(machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, max_rx_buffer_len) == data)
        -- iflags.Y should be cleared
        assert(machine:read_reg("iflags_Y") == 0)
        -- fromhost should reflect the reason and data length
        local expected_fromhost = ((reason & 0xffff) << 32) | (#data & 0xffffffff)
        assert(machine:read_reg("htif_fromhost") == expected_fromhost)
    end
    do_test("send_cmio_response happy path", function(machine)
        assert_before_cmio_response_sent(machine)
        machine:send_cmio_response(reason, data)
        assert_after_cmio_response_sent(machine)
    end)
    for _, large_data in ipairs({ false, true }) do
        local annotations = true
        do_test(
            string.format(
                "log_send_cmio_response happy path with annotations=%s, large_data=%s",
                annotations,
                large_data
            ),
            function(machine)
                local log_type = (annotations and cartesi.ACCESS_LOG_TYPE_ANNOTATIONS or 0)
                    | (large_data and cartesi.ACCESS_LOG_TYPE_LARGE_DATA or 0)
                assert_before_cmio_response_sent(machine)
                local root_hash_before = machine:get_root_hash()
                local log = machine:log_send_cmio_response(reason, data, log_type)
                assert_after_cmio_response_sent(machine)
                local root_hash_after = machine:get_root_hash()
                -- check log
                local accesses = log.accesses
                assert(#accesses == 4)
                assert_access(accesses, 1, {
                    type = "read",
                    address = machine:get_reg_address("iflags_Y"),
                    log2_size = 3,
                })
                assert_access(accesses, 2, {
                    type = "write",
                    address = cartesi.AR_CMIO_RX_BUFFER_START,
                    log2_size = cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE,
                    read_hash = all_zeros_hash,
                    read = large_data and all_zeros or nil,
                    written_hash = data_hash,
                    written = large_data and data or nil,
                })
                assert_access(accesses, 3, {
                    type = "write",
                    address = machine:get_reg_address("htif_fromhost"),
                    log2_size = 3,
                })
                assert_access(accesses, 4, {
                    type = "write",
                    address = machine:get_reg_address("iflags_Y"),
                    log2_size = 3,
                })
                -- ask machine to verify state transitions
                machine:verify_send_cmio_response(reason, data, root_hash_before, log, root_hash_after, log_type, {})
            end
        )
    end
end

test_send_cmio_input_with_different_arguments()

do_test("Dump of log produced by send_cmio_response should match", function(machine)
    machine:write_reg("iflags_Y", 1)
    local data = "0123456789"
    local reason = 7
    local log = machine:log_send_cmio_response(reason, data, cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
    local expected_dump = [[
begin send_cmio_response
  1: read iflags.Y@0x300(768): 0x1(1)
  2: write cmio rx buffer@0x60000000(1610612736): hash:"290decd9"(2^5 bytes) -> hash:"555b1f6d"(2^5 bytes)
  3: write htif.fromhost@0x330(816): 0x0(0) -> 0x70000000a(30064771082)
  4: write iflags.Y@0x300(768): 0x1(1) -> 0x0(0)
end send_cmio_response
]]
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
    local rx_buffer_size = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE
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
            machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, initial_rx_buffer)
            assert(machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, rx_buffer_size) == initial_rx_buffer)
            local data = string.rep("a", case.data_len)
            machine:write_reg("iflags_Y", 1)
            if logging then
                local log = machine:log_send_cmio_response(reason, data)
                assert(#log.accesses == 4, string.format("log should have 4 accesses, but it has %s", #log.accesses))
                assert(log.accesses[2].type == "write", "access 2 should be a write")
                assert(1 << log.accesses[2].log2_size == case.write_len, "log2_size of write access does not match")
            else
                machine:send_cmio_response(reason, data)
            end
            local expected_rx_buffer = padded_data(data, case.write_len, "\0")
                .. string.rep("x", rx_buffer_size - case.write_len)
            local new_rx_buffer = machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, rx_buffer_size)
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
    local rx_buffer_size = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE
    local initial_rx_buffer = string.rep("x", rx_buffer_size)
    machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, initial_rx_buffer)
    assert(machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, rx_buffer_size) == initial_rx_buffer)
    machine:write_reg("iflags_Y", 1)
    local reason = 1
    local data = ""
    machine:send_cmio_response(reason, data)
    local new_rx_buffer = machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, rx_buffer_size)
    assert(new_rx_buffer == initial_rx_buffer, "rx_buffer should not have been modified")
    assert(machine:read_reg("iflags_Y") == 0, "iflags.Y should be cleared")
    -- log and verify
    machine:write_reg("iflags_Y", 1)
    local hash_before = machine:get_root_hash()
    local log = machine:log_send_cmio_response(reason, data)
    util.dump_log(log, io.stderr)
    assert(#log.accesses == 3, "log should have 3 accesses")
    local hash_after = machine:get_root_hash()
    machine:verify_send_cmio_response(reason, data, hash_before, log, hash_after)
end)

local function test_cmio_buffers_backed_by_files()
    local rx_filename = os.tmpname()
    local tx_filename = os.tmpname()
    local rx_init_data = string.rep("R", 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
    local tx_init_data = string.rep("T", 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE)
    local deleter = {}
    setmetatable(deleter, {
        __gc = function()
            os.remove(rx_filename)
            os.remove(tx_filename)
        end,
    })
    -- initialize test cmio files
    local rx = assert(io.open(rx_filename, "w+"))
    rx:write(rx_init_data)
    rx:close()
    local tx = assert(io.open(tx_filename, "w+"))
    tx:write(tx_init_data)
    tx:close()
    local tx_new_data = string.rep("x", 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE)
    local rx_new_data = string.rep("y", 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)

    test_util.make_do_test(build_machine, machine_type, {
        cmio = {
            rx_buffer = { backing_store = { data_filename = rx_filename, shared = false } },
            tx_buffer = { backing_store = { data_filename = tx_filename, shared = false } },
        },
    })("cmio buffers initialized from backing files", function(machine)
        local rx_data = machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
        assert(rx_data == rx_init_data, "rx buffer data does not match")
        local tx_data = machine:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE)
        assert(tx_data == tx_init_data, "tx buffer data does not match")
        -- write new data to buffers to later assert that it was not written to the files
        machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, rx_new_data)
        machine:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, tx_new_data)
    end)
    -- the shared=false from last test should prevent saving the new data to files
    test_util.make_do_test(build_machine, machine_type, {
        cmio = {
            rx_buffer = { backing_store = { data_filename = rx_filename, shared = true } },
            tx_buffer = { backing_store = { data_filename = tx_filename, shared = true } },
        },
    })("cmio buffers initialized from backing files should not change", function(machine)
        local rx_data = machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
        assert(rx_data == rx_init_data, "rx buffer data does not match")
        local tx_data = machine:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE)
        assert(tx_data == tx_init_data, "tx buffer data does not match")
        -- write new data to buffers to later assert that it was written to the files
        machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, rx_new_data)
        machine:write_memory(cartesi.AR_CMIO_TX_BUFFER_START, tx_new_data)
    end)
    -- the shared=true from last test should save memory changes to files
    test_util.make_do_test(build_machine, machine_type, {
        cmio = {
            rx_buffer = { backing_store = { data_filename = rx_filename, shared = false } },
            tx_buffer = { backing_store = { data_filename = tx_filename, shared = false } },
        },
    })("cmio buffer files should be modified by last write_memory", function(machine)
        local rx_data = machine:read_memory(cartesi.AR_CMIO_RX_BUFFER_START, 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
        assert(rx_data == rx_new_data, "rx buffer data does not match")
        local tx_data = machine:read_memory(cartesi.AR_CMIO_TX_BUFFER_START, 1 << cartesi.AR_CMIO_TX_BUFFER_LOG2_SIZE)
        assert(tx_data == tx_new_data, "tx buffer data does not match")
    end)
end
test_cmio_buffers_backed_by_files()

local uarch_store_double_in_t0_to_t1 = {
    0x00533023, -- sd	t0,0(t1)
}
test_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = {
            backing_store = { data_filename = test_util.create_test_uarch_program(uarch_store_double_in_t0_to_t1) },
        },
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
        local log = machine:log_step_uarch(cartesi.ACCESS_LOG_TYPE_ANNOTATIONS)
        local temp_file <close> = test_util.new_temp_file()
        util.dump_log(log, temp_file)
        return log, temp_file:read_all()
    end

    -- write to the first word
    machine:write_reg("uarch_x" .. t1, leaf_address)
    machine:write_reg("uarch_x" .. t0, 0xaaaaaaaaaaaaaaaa)
    local log, dump = log_step()
    assert(
        dump:find(
            "write uarch.ram@0x600020(6291488): 0x1111111111111111(1229782938247303441)"
                .. " -> 0xaaaaaaaaaaaaaaaa(12297829382473034410)",
            1,
            true
        )
    )
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size) -- read and check written data
    assert(leaf_data == make_leaf("\xaa", "\x22", "\x33", "\x44"))
    assert(log.accesses[7].written == leaf_data)

    -- restart program and write to second leaf word
    machine:write_reg("uarch_pc", cartesi.UARCH_RAM_START_ADDRESS)
    machine:write_reg("uarch_x" .. t1, machine:read_reg("uarch_x" .. t1) + word_size)
    machine:write_reg("uarch_x" .. t0, 0xbbbbbbbbbbbbbbbb)
    log, dump = log_step()
    assert(
        dump:find(
            "write uarch.ram@0x600028(6291496): 0x2222222222222222(2459565876494606882)"
                .. " -> 0xbbbbbbbbbbbbbbbb(13527612320720337851)",
            1,
            true
        )
    )
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size)
    assert(leaf_data == make_leaf("\xaa", "\xbb", "\x33", "\x44"))
    assert(log.accesses[7].written == leaf_data)

    -- restart program and write to third leaf word
    machine:write_reg("uarch_pc", cartesi.UARCH_RAM_START_ADDRESS)
    machine:write_reg("uarch_x" .. t1, machine:read_reg("uarch_x" .. t1) + word_size)
    machine:write_reg("uarch_x" .. t0, 0xcccccccccccccccc)
    log, dump = log_step()
    assert(
        dump:find(
            "7: write uarch.ram@0x600030(6291504): 0x3333333333333333(3689348814741910323)"
                .. " -> 0xcccccccccccccccc(14757395258967641292)",
            1,
            true
        )
    )
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size)
    assert(leaf_data == make_leaf("\xaa", "\xbb", "\xcc", "\x44"))
    assert(log.accesses[7].written == leaf_data)

    -- restart program and write to fourth leaf word
    machine:write_reg("uarch_pc", cartesi.UARCH_RAM_START_ADDRESS)
    machine:write_reg("uarch_x" .. t1, machine:read_reg("uarch_x" .. t1) + word_size)
    machine:write_reg("uarch_x" .. t0, 0xdddddddddddddddd)
    log, dump = log_step()
    assert(
        dump:find(
            "7: write uarch.ram@0x600038(6291512): 0x4444444444444444(4919131752989213764)"
                .. " -> 0xdddddddddddddddd(15987178197214944733)",
            1,
            true
        )
    )
    assert(log.accesses[7].read == leaf_data)
    leaf_data = machine:read_memory(leaf_address, leaf_size)
    assert(leaf_data == make_leaf("\xaa", "\xbb", "\xcc", "\xdd"))
    assert(log.accesses[7].written == leaf_data)
end)

-- helper function to load a step log file into a table
local function read_step_log_file(filename)
    local file <close> = assert(io.open(filename, "rb"))
    local page_count = string.unpack("<I8", file:read(8))
    local log = { pages = {}, siblings = {} }
    for i = 1, page_count do
        log.pages[i] = {
            index = string.unpack("<I8", file:read(8)),
            data = file:read(4096),
            hash = file:read(32),
        }
    end
    local sibling_count = string.unpack("<I8", file:read(8))
    for i = 1, sibling_count do
        log.siblings[i] = file:read(32)
    end
    return log
end

-- helper function to write a step log file from a table
local function write_step_log_file(logdata, filename)
    local file <close> = assert(io.open(filename, "wb"))
    local page_count = #logdata.pages
    if logdata.override_page_count then
        page_count = logdata.override_page_count
    end
    file:write(string.pack("<I8", page_count))
    for _, page in ipairs(logdata.pages) do
        file:write(string.pack("<I8", page.index))
        file:write(page.data)
        file:write(page.hash)
    end
    local sibling_count = #logdata.siblings
    if logdata.override_sibling_count then
        sibling_count = logdata.override_sibling_count
    end
    file:write(string.pack("<I8", sibling_count))
    for _, sibling in ipairs(logdata.siblings) do
        file:write(sibling)
    end
end

-- helper function to easily create a modified copy of a step log file
local function copy_step_log(original_filename, new_filename, callback)
    local log_data = read_step_log_file(original_filename)
    callback(log_data)
    os.remove(new_filename)
    write_step_log_file(log_data, new_filename)
end

test_util.make_do_test(build_machine, machine_type, { uarch = {} })("log_step sanity check", function(machine)
    local success, err, _
    local filename1 = os.tmpname()
    local filename2 = os.tmpname()
    local deleter = {}
    setmetatable(deleter, {
        __gc = function()
            os.remove(filename1)
            os.remove(filename2)
        end,
    })

    machine:write_reg("mcycle", 0)
    assert(machine:read_reg("mcycle") == 0)
    -- log_step should fail because the temp file already exists
    success, err = pcall(function()
        machine:log_step(1, filename1)
    end)
    assert(not success)
    check_error_find(err, "file already exists")
    -- delete file and confirm that machine is on same mcycle
    os.remove(filename1)
    assert(machine:read_reg("mcycle") == 0)
    -- get current root hash and log step
    local root_hash_before = machine:get_root_hash()
    local mcycle_count = 10
    local status = machine:log_step(mcycle_count, filename1)
    assert(status == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:read_reg("mcycle") == mcycle_count)
    local root_hash_after = machine:get_root_hash()
    assert(root_hash_before ~= root_hash_after)
    -- verify step should pass
    status = machine:verify_step(root_hash_before, filename1, mcycle_count, root_hash_after)
    assert(status == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    -- with incorrect hash args, verify step should fail
    local bad_hash = string.rep("\0", 32)
    _, err = pcall(function()
        machine:verify_step(bad_hash, filename1, mcycle_count, root_hash_after)
    end)
    check_error_find(err, "initial root hash mismatch")
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename1, mcycle_count, bad_hash)
    end)
    check_error_find(err, "final root hash mismatch")
    -- ensure that copy_step_log() works
    copy_step_log(filename1, filename2, function()
        -- copy original file without modifications
    end)
    machine:verify_step(root_hash_before, filename2, mcycle_count, root_hash_after)
    -- modify page data
    copy_step_log(filename1, filename2, function(log_data)
        log_data.pages[1].data = string.reverse(log_data.pages[1].data)
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, root_hash_after)
    end)
    check_error_find(err, "initial root hash mismatch")
    -- page indices not in ascending order should fail
    copy_step_log(filename1, filename2, function(log_data)
        log_data.pages[2].index = log_data.pages[1].index
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "invalid log format: page index is not in increasing order")
    -- page scratch hash area not zeroed
    copy_step_log(filename1, filename2, function(log_data)
        log_data.pages[1].hash = string.rep("\1", 32)
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "invalid log format: page scratch hash area is not zero")
    -- add one extra page
    copy_step_log(filename1, filename2, function(log_data)
        table.insert(log_data.pages, {
            index = log_data.pages[#log_data.pages].index + 1,
            data = log_data.pages[#log_data.pages].data,
            hash = log_data.pages[#log_data.pages].hash,
        })
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "too many sibling hashes in log")
    -- remove one page
    copy_step_log(filename1, filename2, function(log_data)
        table.remove(log_data.pages)
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "too many sibling hashes in log")
    -- override page count to zero
    copy_step_log(filename1, filename2, function(log_data)
        log_data.override_page_count = 0
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "page count is zero")
    -- override page count to overflow
    copy_step_log(filename1, filename2, function(log_data)
        -- There is no UINT64_MAX in Lua, so we have to use the signed representation
        local MAX_MCYCLE_COUNT = -1
        log_data.override_page_count = MAX_MCYCLE_COUNT
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "page data past end of step log")
    -- remove one sibling
    copy_step_log(filename1, filename2, function(log_data)
        table.remove(log_data.siblings)
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "too few sibling hashes in log")
    -- add an extra sibling
    copy_step_log(filename1, filename2, function(log_data)
        table.insert(log_data.siblings, bad_hash)
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "too many sibling hashes in log")
    -- modify one sibling hash
    copy_step_log(filename1, filename2, function(log_data)
        log_data.siblings[1] = bad_hash
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "initial root hash mismatch")
    -- empty siblings
    copy_step_log(filename1, filename2, function(log_data)
        log_data.siblings = {}
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "too few sibling hashes in log")
    -- override sibling count to overflow
    copy_step_log(filename1, filename2, function(log_data)
        log_data.override_sibling_count = 0xffffffff
    end)
    _, err = pcall(function()
        machine:verify_step(root_hash_before, filename2, mcycle_count, bad_hash)
    end)
    check_error_find(err, "sibling hashes past end of step log")
    -- log_step should fail if uarch is not reset
    machine:run_uarch(1) -- advance 1 micro step 0< uarch is not reset
    os.remove(filename1)
    _, err = pcall(function()
        machine:log_step(1, filename1)
    end)
    check_error_find(err, "microarchitecture is not reset")
    -- after uarch is reset, log_step should work
    machine:reset_uarch()
    status = machine:log_step(1, filename1)
    assert(status == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
end)

print("\n\nAll machine binding tests for type " .. machine_type .. " passed")
