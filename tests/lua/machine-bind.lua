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
local hash_tree = require("cartesi.hash-tree")
local util = require("cartesi.util")
local tests_util = require("cartesi.tests.util")
local jsonrpc

local remote_address
local test_path = "./"
local concurrency_update_hash_tree = util.parse_number(os.getenv("CARTESI_CONCURRENCY_UPDATE_HASH_TREE")) or 0

local lua_cmd = arg[-1] .. " -e "

local MAX_MCYCLE = cartesi.MCYCLE_MAX
local MAX_UARCH_CYCLE = cartesi.UARCH_CYCLE_MAX

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
    working directory of cartesi-jsonrpc-machine and must be locally readable
    (default: "./")

  --concurrency=<key>:<value>[,<key>:<value>[,...]...]
    configures the number of threads used in some implementation parts.

    <key>:<value> is one of
        update_hash_tree:<number>

        update_hash_tree (optional)
        defines the number of threads to use while calculating the hash tree.
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
            local c = util.parse_options(opts, all, {
                update_hash_tree = "number",
            })
            c.update_hash_tree = assert(c.update_hash_tree, "invalid update_hash_tree number in " .. all)
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
        imcyclemax = cartesi.MCYCLE_MAX,
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
assert(cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE == 48)
assert(cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE == 20)
assert(cartesi.ROLLUP_LOG2_MAX_OUTPUT_COUNT == 63)
assert(cartesi.ROLLUP_LOG2_MAX_ADVANCE_STATES_PER_EPOCH == 24)
assert(cartesi.UARCH_CYCLE_MAX == (1 << cartesi.ROLLUP_LOG2_MAX_UARCH_CYCLES_PER_MCYCLE) - 1)
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
        hash_tree = config_options.hash_tree or nil,
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
                        data_filename = tests_util.create_test_uarch_program(tests_util.uarch_programs.default),
                    },
                },
            },
    }
    local runtime = {
        concurrency = {
            update_hash_tree = concurrency_update_hash_tree,
        },
    }
    return config, runtime
end

local function build_machine(type, config_options)
    local config, runtime = build_machine_config(config_options)
    local new_machine
    if type ~= "local" then
        local jsonrpc_machine <close> = assert(jsonrpc.connect_server(remote_address))
        new_machine = jsonrpc_machine:fork_server():set_cleanup_call(jsonrpc.SHUTDOWN):create(config, runtime)
    else
        new_machine = cartesi.machine(config, runtime)
    end
    if config.uarch.ram and config.uarch.ram.backing_store and config.uarch.ram.backing_store.data_filename then
        os.remove(config.uarch.ram.backing_store.data_filename)
    end
    return new_machine
end

local do_test = tests_util.make_do_test(build_machine, machine_type)

-- Step-log filename helpers. os.tmpname() returns a name and creates the file;
-- log_* require the file to not exist, so we remove it first.

local function tmpname_for_log()
    local filename = os.tmpname()
    os.remove(filename)
    return filename
end

local function step_uarch(machine)
    local filename = tmpname_for_log()
    machine:log_step_uarch(1, filename)
    os.remove(filename)
end

-- Binary step log helpers (definitions in cartesi.tests.util).
local read_step_log_file = tests_util.read_step_log_file
local copy_step_log = tests_util.copy_step_log

-- Sentinel revert root hash send_cmio_response stores in its shadow slot; uarch reset reads it back.
local CMIO_REVERT_HASH = string.rep("\xab", cartesi.HASH_SIZE)

print("Testing machine bindings for type " .. machine_type)

print("\n\nDifferent hash tree hash targets")

do_test("Hash tree hash function should be keccak256 by default", function(machine)
    assert(
        machine:get_initial_config().hash_tree.hash_function == "keccak256",
        "hash tree hash function should be uarch"
    )
end)

tests_util.make_do_test(build_machine, machine_type, { hash_tree = { hash_function = "keccak256" } })(
    "Hash tree hash function keccak256 should work properly",
    function(machine)
        assert(
            machine:get_initial_config().hash_tree.hash_function == "keccak256",
            "hash tree hash function should be uarch"
        )
        local root_hash = machine:get_root_hash()
        local keccak256_calculated = tests_util.calculate_emulator_hash(machine, "keccak256")
        assert(root_hash == keccak256_calculated, "initial root hash does not match")
        local sha256_calculated = tests_util.calculate_emulator_hash(machine, "sha256")
        assert(root_hash ~= sha256_calculated, "initial root hash should not match sha256")
    end
)

tests_util.make_do_test(build_machine, machine_type, { hash_tree = { hash_function = "sha256" } })(
    "Hash tree hash function sha256 should work properly",
    function(machine)
        assert(
            machine:get_initial_config().hash_tree.hash_function == "sha256",
            "hash tree hash function should be sha256"
        )
        local root_hash = machine:get_root_hash()
        local sha256_calculated = tests_util.calculate_emulator_hash(machine, "sha256")
        assert(root_hash == sha256_calculated, "initial root hash does not match")
        local keccak256_calculated = tests_util.calculate_emulator_hash(machine, "keccak256")
        assert(root_hash ~= keccak256_calculated, "initial root hash should not match keccak256")
    end
)

tests_util.make_do_test(function() end, machine_type, {})(
    "Fails to construct machine of unsupported hash tree hash function",
    function()
        local success, err = pcall(function()
            build_machine(machine_type, {
                hash_tree = { hash_function = "invalid" },
            })
        end)
        assert(success == false)
        print(err)
        assert(err and err:match("invalid hash function type"))
    end
)

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
    initial_reg_values.x0 = nil
    -- Check initialization and shadow reads
    for k, v in pairs(initial_reg_values) do
        assert(v == machine:read_word(machine:get_reg_address(k)))
        machine:write_word(machine:get_reg_address(k), ~v)
        assert(~v == machine:read_word(machine:get_reg_address(k)))
    end
end)

print("\n\ntesting hash tree get_proof for values for registers")
do_test("should provide proof for values in registers", function(machine)
    local initial_reg_values = get_cpu_reg_test_values()
    initial_reg_values.mvendorid = nil
    initial_reg_values.marchid = nil
    initial_reg_values.mimpid = nil

    -- Check proofs
    local hash_fn = machine:get_initial_config().hash_tree.hash_function
    for _, v in pairs(initial_reg_values) do
        for el = cartesi.HASH_TREE_LOG2_WORD_SIZE, cartesi.HASH_TREE_LOG2_ROOT_SIZE - 1 do
            local a = tests_util.align(v, el)
            hash_tree.verify_slice(assert(machine:get_proof(a, el), "no proof"), hash_fn)
        end
    end
end)

print("\n\ntesting revert root hash")
do_test("should write/read revert root hash", function(machine)
    local before_root_hash = machine:get_root_hash()
    machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, before_root_hash)
    assert(
        machine:read_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, cartesi.HASH_SIZE) == before_root_hash,
        "unexpected revert root hash"
    )
    local after_root_hash = machine:get_root_hash()
    assert(before_root_hash ~= after_root_hash)
    machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, string.rep("\x00", 32))
    assert(before_root_hash == machine:get_root_hash())
end)

print("\n\ntesting get_reg_address function binding")
do_test("should return address value for registers", function(machine)
    -- Check register address
    local initial_reg_values = get_cpu_reg_test_values()
    for k, v in pairs(initial_reg_values) do
        assert(machine:read_reg(k) == machine:read_word(machine:get_reg_address(k)), "invalid return for " .. v)
    end
    assert(machine:get_reg_address("first_") == machine:get_reg_address("x0"))
    assert(machine:get_reg_address("last_") == machine:get_reg_address("htif_iyield"))
    assert(machine:get_reg_address("uarch_first_") == machine:get_reg_address("uarch_halt"))
    assert(machine:get_reg_address("uarch_last_") == machine:get_reg_address("uarch_x31"))
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
        "imcyclemax",
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
    assertfield(config, "hash_tree.hash_function", "string")
end

print("\n\ntesting get_default_config function binding")
do_test("should return default machine config", function(machine)
    test_config(machine:get_default_config())
end)

print("\n\n test verifying integrity of the hash tree")
do_test("verify_hash_tree should return true", function(machine)
    -- Verify starting hash tree
    assert(machine:verify_hash_tree(), "error, non consistent hash tree")
end)

print("\n\n test calculation of initial root hash")
do_test("should return expected value", function(machine)
    -- Get starting root hash
    local root_hash = machine:get_root_hash()
    print("Root hash: ", cartesi.tohex(root_hash))

    local calculated_root_hash = tests_util.calculate_emulator_hash(machine)

    assert(root_hash == calculated_root_hash, "initial root hash does not match")
end)

print("\n\n test get_initial_config")
do_test("should have expected values", function(machine)
    -- Check initial config
    local initial_config = machine:get_initial_config()
    test_config(initial_config)
    assert(initial_config.processor.registers.pc == 0x200, "wrong pc reg initial config value")
    assert(initial_config.processor.registers.imcyclemax == cartesi.MCYCLE_MAX, "wrong imcyclemax value")
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

    step_uarch(machine)

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
    assert(machine:read_reg("uarch_halt") == 0, "uarch halt should be cleared")
    assert(machine:read_reg("iflags_Y") == 0, "iflags.Y should be cleared")
    assert(machine:read_reg("iflags_H") == 0, "iflags.H should be cleared")
    local status = machine:run_uarch(1)
    assert(status == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE)
    assert(machine:read_reg("uarch_cycle") == 1, "uarch cycle should be 1")
    assert(machine:read_reg("uarch_halt") == 0, "uarch should not be halted")
end)

do_test("do not advance micro cycle if uarch is halted", function(machine)
    machine:write_reg("uarch_halt", 1)
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should be 0")
    assert(machine:read_reg("uarch_halt") ~= 0, "uarch halt should be set")
    assert(machine:read_reg("iflags_Y") == 0, "iflags.Y should be cleared")
    assert(machine:read_reg("iflags_H") == 0, "iflags.H should be cleared")
    local status = machine:run_uarch(1)
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED, "run_uarch should return UARCH_BREAK_REASON_UARCH_HALTED")
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should still be 0")
end)

do_test("do not advance micro cycle if uarch cycle overflows", function(machine)
    machine:write_reg("uarch_cycle", cartesi.UARCH_CYCLE_MAX)
    assert(machine:read_reg("uarch_cycle") == cartesi.UARCH_CYCLE_MAX, "uarch cycle should be 0")
    local status = machine:run_uarch(cartesi.UARCH_CYCLE_MAX + 1)
    assert(
        status == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW,
        "run_uarch should return UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW"
    )
    assert(machine:read_reg("uarch_cycle") == cartesi.UARCH_CYCLE_MAX, "uarch cycle should still be 0")
    assert(machine:read_reg("uarch_halt") == 0)
end)

do_test("final micro cycle should immediately overflow", function(machine)
    machine:write_reg("uarch_cycle", cartesi.UARCH_CYCLE_MAX - 1)
    local status = machine:run_uarch(cartesi.UARCH_CYCLE_MAX)
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_CYCLE_OVERFLOW)
    assert(machine:read_reg("uarch_cycle") == cartesi.UARCH_CYCLE_MAX)
    assert(machine:read_reg("uarch_halt") == 0)
end)

do_test("advance micro cycles until halt", function(machine)
    assert(machine:read_reg("uarch_cycle") == 0, "uarch cycle should be 0")
    assert(machine:read_reg("uarch_halt") == 0, "machine should not be halted")
    local status = machine:run_uarch(3)
    assert(status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
    assert(machine:read_reg("uarch_cycle") == 3, "uarch cycle should be 4")
    assert(machine:read_reg("uarch_halt") == 1, "uarch should be halted")
    assert(machine:run_uarch(3) == cartesi.UARCH_BREAK_REASON_UARCH_HALTED)
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

do_test("machine should overflow exactly at imcyclemax", function(machine)
    machine:write_reg("mcycle", 0)
    machine:write_reg("imcyclemax", 5)
    machine:write_reg("iflags_H", 0)
    machine:write_reg("iflags_Y", 0)
    assert(machine:run(4) == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
    assert(machine:read_reg("mcycle") == 4)
    assert(machine:run(5) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
    assert(machine:read_reg("mcycle") == 5)
    assert(machine:read_reg("iflags_H") == 0)
    assert(machine:run(6) == cartesi.BREAK_REASON_MCYCLE_OVERFLOW)
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

print("\n\ntesting step and verification")
do_test("machine step should pass verifications", function(machine)
    local initial_hash = machine:get_root_hash()
    local filename = tmpname_for_log()
    machine:log_step_uarch(1, filename)
    local final_hash = machine:get_root_hash()
    assert(machine:verify_step_uarch(initial_hash, filename, 1) == final_hash)
    os.remove(filename)
end)

-- The C++ replayer handles multi-cycle uarch step logs (the Solidity verifier is scoped to one
-- cycle; C++ stays general). Record and verify a 2-cycle log to keep that path covered.
do_test("multi-cycle uarch step log should pass verification", function(machine)
    local initial_hash = machine:get_root_hash()
    local filename = tmpname_for_log()
    machine:log_step_uarch(2, filename)
    local final_hash = machine:get_root_hash()
    assert(machine:verify_step_uarch(initial_hash, filename, 2) == final_hash)
    os.remove(filename)
end)

do_test("pretty_print_step_uarch writes a readable printout", function(machine)
    local log = tmpname_for_log()
    -- Two micro cycles to exercise the multi-cycle replay (default program: "li a0,123", "li a7,halt").
    machine:log_step_uarch(2, log)
    local text = cartesi.machine:pretty_print_step_uarch(log)
    os.remove(log)
    -- Match the whole printout line by line; addresses and values are wildcarded so the expectation
    -- survives shadow-layout/cycle drift while order, numbering, names, and brackets stay pinned.
    local expected = {
        -- Every cycle has the same shape: uarch_step's cycle/halt/pc reads, the fetch,
        -- the bracketed instruction body, and the cycle increment.
        "^1: read uarch%.cycle@0x%x+: 0x%x+$",
        "^2: read uarch%.halt@0x%x+: 0x%x+$",
        "^3: read uarch%.pc@0x%x+: 0x%x+$",
        "^4: read @0x%x+: 0x%x+$",
        "^begin addi$",
        "^  5: read uarch%.x0@0x%x+: 0x%x+$",
        "^  6: write uarch%.x10@0x%x+: 0x%x+ %-> 0x%x+$",
        "^  7: write uarch%.pc@0x%x+: 0x%x+ %-> 0x%x+$",
        "^end addi$",
        "^8: write uarch%.cycle@0x%x+: 0x%x+ %-> 0x%x+$",
        "^9: read uarch%.cycle@0x%x+: 0x%x+$",
        "^10: read uarch%.halt@0x%x+: 0x%x+$",
        "^11: read uarch%.pc@0x%x+: 0x%x+$",
        "^12: read @0x%x+: 0x%x+$",
        "^begin addi$",
        "^  13: read uarch%.x0@0x%x+: 0x%x+$",
        "^  14: write uarch%.x17@0x%x+: 0x%x+ %-> 0x%x+$",
        "^  15: write uarch%.pc@0x%x+: 0x%x+ %-> 0x%x+$",
        "^end addi$",
        "^16: write uarch%.cycle@0x%x+: 0x%x+ %-> 0x%x+$",
    }
    local lines = {}
    for line in (text .. "\n"):gmatch("(.-)\n") do
        lines[#lines + 1] = line
    end
    if lines[#lines] == "" then -- drop the trailing empty split element
        lines[#lines] = nil
    end
    assert(#lines == #expected, string.format("printout has %d lines, expected %d:\n%s", #lines, #expected, text))
    for i, pat in ipairs(expected) do
        assert(lines[i]:match(pat), string.format("printout line %d %q does not match %q", i, lines[i], pat))
    end
end)

do_test("pretty_print_step_uarch flags a log that fails the final root check", function(machine)
    local log = tmpname_for_log()
    machine:log_step_uarch(2, log)
    -- Corrupt one byte of the header's root_hash_after (offset 48: signature +
    -- root_hash_before + requested_cycle_count) so the replay's final check fails.
    local f = assert(io.open(log, "r+b"))
    assert(f:seek("set", 48))
    local byte = assert(f:read(1))
    assert(f:seek("set", 48))
    assert(f:write(string.char((byte:byte() + 1) % 256)))
    f:close()
    local text = cartesi.machine:pretty_print_step_uarch(log)
    os.remove(log)
    -- The printout must survive intact, with the failure reported as a trailing warning.
    assert(text:match("^1: read uarch%.cycle@0x%x+"), "printout body missing")
    assert(text:match("WARNING: replay does not verify: final root hash mismatch"), text)
end)

-- Generic step-log format-corruption rejection is tested against the replay parser in
-- spec-verify-step-failure.lua. The cases below cover only what is per-function:
-- the Layer 2 argument checks and the function-specific replay checks
-- (UARCH_STATE pristine for reset, supra-page padded hash for cmio).

print("\n\ntesting verify_step_uarch unhappy paths")
do_test("verify_step_uarch rejects mismatched Layer 2 arguments", function(machine)
    local bad_hash = string.rep("\0", cartesi.HASH_SIZE)
    local initial_hash = machine:get_root_hash()
    local filename = tmpname_for_log()
    machine:log_step_uarch(1, filename)
    local final_hash = machine:get_root_hash()
    -- sanity: happy path
    assert(machine:verify_step_uarch(initial_hash, filename, 1) == final_hash)
    -- bad root_hash_before arg
    local _, err = pcall(machine.verify_step_uarch, machine, bad_hash, filename, 1)
    check_error_find(err, "root hash before does not match")
    -- bad uarch_cycle_count arg
    _, err = pcall(machine.verify_step_uarch, machine, initial_hash, filename, 99)
    check_error_find(err, "uarch cycle count does not match")
    -- a wrong belief about the final state is the caller's to detect via the returned hash
    assert(machine:verify_step_uarch(initial_hash, filename, 1) ~= bad_hash)
    os.remove(filename)
end)

do_test("step at max uarch cycle preserves state", function(machine)
    machine:write_reg("uarch_cycle", MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    local initial_hash = machine:get_root_hash()
    local filename = tmpname_for_log()
    machine:log_step_uarch(1, filename)
    assert(machine:read_reg("uarch_cycle") == MAX_UARCH_CYCLE)
    assert(machine:read_reg("uarch_halt") == 0)
    local final_hash = machine:get_root_hash()
    assert(final_hash == initial_hash)
    assert(machine:verify_step_uarch(initial_hash, filename, 1) == final_hash)
    os.remove(filename)
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

tests_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { backing_store = { data_filename = tests_util.create_test_uarch_program(uarch_proof_step_program) } },
    },
})("hash tree must be consistent when stepping alternating with and without proofs", function(machine)
    local t0 = 5
    local t1 = 6
    local t2 = 7
    local uarch_ram_start = cartesi.UARCH_RAM_START_ADDRESS

    step_uarch(machine) -- auipc	t0,0x0
    step_uarch(machine) -- addi	t0,t0,256 # 0x100
    assert(machine:read_reg("uarch_x" .. t0) == uarch_ram_start + 0x100)
    step_uarch(machine) -- li	t1,0xca
    assert(machine:read_reg("uarch_x" .. t1) == 0xca)
    step_uarch(machine) -- li	t2,0xfe
    assert(machine:read_reg("uarch_x" .. t2) == 0xfe)

    -- sd and assert stored correctly
    step_uarch(machine) -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)

    -- sd and assert stored correctly
    step_uarch(machine) -- t2,0(t0) [0xfe]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xfe)

    -- This step should run successfully
    -- The previous unproven step should have marked the updated pages dirty, allowing
    -- the tree to be updated correctly in the next proved step
    step_uarch(machine) -- sd	t1,0(t0) [0xca]
    assert(string.unpack("I8", machine:read_memory(uarch_ram_start + 0x100, 8)) == 0xca)
end)

tests_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { backing_store = { data_filename = tests_util.create_test_uarch_program(uarch_proof_step_program) } },
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

tests_util.make_do_test(build_machine, machine_type, { processor = { registers = { mcycle = 1 } }, uarch = {} })(
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

tests_util.make_do_test(build_machine, machine_type, { uarch = {} })(
    "uarch reset using default uarch configuration ",
    function(machine)
        local initial_hash = machine:get_root_hash()
        -- resetting immediately should not produce different hash
        machine:reset_uarch()
        local hash_after_immediate_reset = machine:get_root_hash()
        assert(initial_hash == hash_after_immediate_reset)
        -- hash should change after one step (shadow uarch change)
        step_uarch(machine)
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
            halt = 1,
            cycle = 1,
            pc = 0,
        },
    },
}
for i = 0, 31 do
    test_reset_uarch_config.processor.registers["x" .. i] = 0x10000 + (i * 8)
end

local function test_reset_uarch(machine, with_log)
    -- assert initial fixture state
    assert(machine:read_reg("uarch_halt") ~= 0)
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
    local uarch_state_hash = tests_util.calculate_uarch_state_hash(machine)
    assert(uarch_state_hash ~= cartesi.UARCH_PRISTINE_STATE_HASH)
    -- reset uarch state
    if with_log then
        -- Exercise the logging path (log structure/round-trip covered separately).
        local filename = tmpname_for_log()
        machine:log_reset_uarch(filename)
        os.remove(filename)
    else
        machine:reset_uarch()
    end
    --- assert registers are reset to pristine values
    assert(machine:read_reg("uarch_halt") == 0)
    assert(machine:read_reg("uarch_cycle") == 0)
    assert(machine:read_reg("uarch_pc") == cartesi.UARCH_RAM_START_ADDRESS)
    for i = 1, 31 do
        assert(machine:read_reg("uarch_x" .. i) == 0)
    end
    -- assert that gibberish was removed from uarch ram
    assert(machine:read_memory(cartesi.UARCH_RAM_START_ADDRESS, #gibberish) ~= gibberish)
    -- compute current uarch state hash
    uarch_state_hash = tests_util.calculate_uarch_state_hash(machine)
    -- assert computed and pristine hash match
    assert(uarch_state_hash == cartesi.UARCH_PRISTINE_STATE_HASH)
end

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing reset_uarch without logging",
    function(machine)
        test_reset_uarch(machine, false)
    end
)

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing reset_uarch with logging",
    function(machine)
        test_reset_uarch(machine, true)
    end
)

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "log_reset_uarch records the UARCH_STATE node with the pristine post-hash",
    function(machine)
        local filename = tmpname_for_log()
        machine:log_reset_uarch(filename)
        local log_data = read_step_log_file(filename)
        assert(#log_data.nodes == 1, "expected exactly one node in a reset_uarch log")
        local n = log_data.nodes[1]
        assert(
            n.address == cartesi.UARCH_STATE_START_ADDRESS,
            string.format(
                "node address 0x%x != UARCH_STATE_START_ADDRESS 0x%x",
                n.address,
                cartesi.UARCH_STATE_START_ADDRESS
            )
        )
        assert(
            n.log2_size == cartesi.UARCH_STATE_LOG2_SIZE,
            string.format("node log2_size %d != UARCH_STATE_LOG2_SIZE %d", n.log2_size, cartesi.UARCH_STATE_LOG2_SIZE)
        )
        assert(
            n.hash_after == cartesi.UARCH_PRISTINE_STATE_HASH,
            "node hash_after does not match cartesi.UARCH_PRISTINE_STATE_HASH"
        )
        os.remove(filename)
    end
)

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "log_reset_uarch witnesses the revert root hash shadow page into the step log",
    function(machine)
        -- The reset accesses the revert root hash (seeded here) and htif.tohost, forcing their shadow
        -- page into the log so a consumer can read both straight off the reset proof.
        machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, CMIO_REVERT_HASH)
        local initial_hash = machine:get_root_hash()
        local filename = tmpname_for_log()
        machine:log_reset_uarch(filename)
        local final_hash = machine:get_root_hash()
        local log_data = read_step_log_file(filename)
        local page_idx = cartesi.AR_SHADOW_REVERT_ROOT_HASH_START >> cartesi.HASH_TREE_LOG2_PAGE_SIZE
        local offset = cartesi.AR_SHADOW_REVERT_ROOT_HASH_START & ((1 << cartesi.HASH_TREE_LOG2_PAGE_SIZE) - 1)
        local found
        for _, p in ipairs(log_data.pages) do
            if p.index == page_idx then
                found = p
            end
        end
        assert(found, "reset log must record the shadow page holding the revert root hash")
        assert(
            found.data:sub(offset + 1, offset + cartesi.HASH_SIZE) == CMIO_REVERT_HASH,
            "revert root hash not found at its shadow slot in the reset log"
        )
        machine:verify_reset_uarch(initial_hash, filename, final_hash)
        os.remove(filename)
    end
)

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "Testing verify_reset_uarch",
    function(machine)
        local initial_hash = machine:get_root_hash()
        local filename = tmpname_for_log()
        machine:log_reset_uarch(filename)
        local final_hash = machine:get_root_hash()
        -- verify happy path
        assert(machine:verify_reset_uarch(initial_hash, filename) == final_hash)
        -- verifying incorrect initial hash
        local wrong_hash = string.rep("\0", cartesi.HASH_SIZE)
        local _, err = pcall(machine.verify_reset_uarch, machine, wrong_hash, filename)
        check_error_find(err, "root hash before does not match")
        os.remove(filename)
    end
)

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "verify_reset_uarch rejects an unconsumed subtree-write node",
    function(machine)
        local initial_hash = machine:get_root_hash()
        local filename = tmpname_for_log()
        machine:log_reset_uarch(filename)
        -- A reset log carries exactly one node (the uarch state). A second node that no
        -- write consumes must be rejected: its hash_after is folded into the post-state
        -- root verbatim.
        local corrupted = tmpname_for_log()
        copy_step_log(filename, corrupted, tests_util.inject_unconsumed_node)
        local _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, corrupted)
        check_error_find(err, "unconsumed node in step log")
        os.remove(filename)
        os.remove(corrupted)
    end
)

tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "verify_reset_uarch rejects an unconsumed node on a reverted reset",
    function(machine)
        -- Pause the machine on an rx-rejected manual yield so the reset reverts: its post-state is the
        -- recorded revert root hash, not the recomputed tree root. The revert path substitutes that root
        -- instead of recomputing it, so the unconsumed-node check must hold there too.
        local revert_root_hash = string.rep("\171", 32)
        local tohost_rx_rejected = (2 << 56) | (1 << 48) | (cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED << 32)
        machine:write_reg("uarch_halt", 1)
        machine:write_reg("iflags_Y", 1)
        machine:write_reg("htif_tohost", tohost_rx_rejected)
        machine:write_memory(cartesi.AR_SHADOW_REVERT_ROOT_HASH_START, revert_root_hash)
        local initial_hash = machine:get_root_hash()
        local filename = tmpname_for_log()
        machine:log_reset_uarch(filename)
        local corrupted = tmpname_for_log()
        copy_step_log(filename, corrupted, tests_util.inject_unconsumed_node)
        local _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, corrupted)
        check_error_find(err, "unconsumed node in step log")
        os.remove(filename)
        os.remove(corrupted)
    end
)

tests_util.make_do_test(build_machine, machine_type)(
    "collect root hashes reject an out-of-range bundle count",
    function(machine)
        -- The bundle count narrows to int at the binding boundary; an oversized value must be
        -- rejected, not silently wrapped to a small valid-looking size.
        local huge = 1 << 32
        local ok, err = pcall(machine.collect_mcycle_root_hashes, machine, 0, 1, 0, huge)
        assert(not ok)
        check_error_find(err, "out of range")
        ok, err = pcall(machine.collect_uarch_cycle_root_hashes, machine, 0, huge)
        assert(not ok)
        check_error_find(err, "out of range")
    end
)

tests_util.make_do_test(build_machine, machine_type, { hash_tree = { hash_function = "sha256" } })(
    "Uarch operations should fail if hash tree hash function is not keccak256",
    function(machine)
        assert(
            machine:get_initial_config().hash_tree.hash_function == "sha256",
            "hash tree hash function should be sha256"
        )
        -- The machine is configured for sha256, therefore:
        -- run_uarch should fail
        local success, err = pcall(machine.run_uarch, machine, 1)
        assert(
            success == false and err:match("can only be used with hash tree configured with Keccak%-256 hash function")
        )
        -- reset_uarch should fail
        success, err = pcall(machine.reset_uarch, machine)
        assert(
            success == false and err:match("can only be used with hash tree configured with Keccak%-256 hash function")
        )
        -- log_reset_uarch should fail
        success, err = pcall(machine.log_reset_uarch, machine, tmpname_for_log())
        assert(
            success == false and err:match("can only be used with hash tree configured with Keccak%-256 hash function")
        )
        -- log_uarch step should fail
        success, err = pcall(machine.log_step_uarch, machine, 1, tmpname_for_log())
        assert(
            success == false and err:match("can only be used with hash tree configured with Keccak%-256 hash function")
        )
        -- log_send_cmio_response should fail
        success, err = pcall(machine.log_send_cmio_response, machine, 0, "", CMIO_REVERT_HASH, tmpname_for_log())
        assert(
            success == false and err:match("can only be used with hash tree configured with Keccak%-256 hash function")
        )
    end
)

print("\n\ntesting verify_reset_uarch unhappy paths")
tests_util.make_do_test(build_machine, machine_type, { uarch = test_reset_uarch_config })(
    "verify_reset_uarch rejects mismatched Layer 2 arguments and a non-pristine logged node",
    function(machine)
        local bad_hash = string.rep("\0", cartesi.HASH_SIZE)
        local initial_hash = machine:get_root_hash()
        local filename1 = tmpname_for_log()
        local filename2 = tmpname_for_log()
        machine:log_reset_uarch(filename1)
        local final_hash = machine:get_root_hash()
        -- sanity: happy path
        assert(machine:verify_reset_uarch(initial_hash, filename1) == final_hash)
        -- bad root_hash_before arg
        local _, err = pcall(machine.verify_reset_uarch, machine, bad_hash, filename1)
        check_error_find(err, "root hash before does not match")
        -- a wrong belief about the final state is the caller's to detect via the returned hash
        assert(machine:verify_reset_uarch(initial_hash, filename1) ~= bad_hash)
        -- non-pristine hash_after must trip the reset_uarch pristine-state check
        copy_step_log(filename1, filename2, function(log_data)
            assert(#log_data.nodes == 1, "reset_uarch log should have exactly one node")
            log_data.nodes[1].hash_after = bad_hash
        end)
        _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, filename2)
        check_error_find(err, "reset uarch node has wrong post-hash")
        -- canonical form: reset_uarch logs must record requested_cycle_count = 0
        copy_step_log(filename1, filename2, function(log_data)
            log_data.requested_cycle_count = 1
        end)
        _, err = pcall(machine.verify_reset_uarch, machine, initial_hash, filename2)
        check_error_find(err, "requested_cycle_count must be zero in reset_uarch log")
        os.remove(filename1)
        os.remove(filename2)
    end
)

print("\n\n testing unsupported uarch instructions ")

local uarch_illegal_insn_program = {
    0x00000000, -- some illegal instruction
}

tests_util.make_do_test(build_machine, machine_type, {
    uarch = {
        ram = { backing_store = { data_filename = tests_util.create_test_uarch_program(uarch_illegal_insn_program) } },
    },
})("Detect illegal instruction", function(machine)
    local success, err = pcall(machine.run_uarch, machine)
    assert(success == false)
    check_error_find(err, "illegal instruction")
end)

do_test("uarch ecall putchar should print char to console", function()
    local lua_code = [[ "
                                 local cartesi = require 'cartesi'
                                 local tests_util = require 'cartesi.tests.util'
                                 local cartesi_util = require 'cartesi.util'
                                 local initial_reg_values = {}
                                 local program = {
                                    (cartesi.UARCH_ECALL_FN_PUTCHAR << 20) | 0x00893, -- li	a7,putchar
                                    0x05800513, -- li a0,'X'
                                    0x00000073, -- ecall
                                 }
                                 local uarch_ram_path = tests_util.create_test_uarch_program(program)
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
    local p <close> = assert(io.popen(lua_cmd .. lua_code))
    local output = assert(p:read(2000))
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
    -- the host send refuses upfront
    tests_util.assert_error("iflags.Y is not set", function()
        machine:send_cmio_response(reason, data)
    end)
    -- the logged operation cannot fail; it is a no-op that leaves the state unchanged
    local hash_before = machine:get_root_hash()
    machine:log_send_cmio_response(reason, data, CMIO_REVERT_HASH, tmpname_for_log())
    assert(machine:read_reg("iflags_Y") == 0)
    assert(machine:get_root_hash() == hash_before)
end)

do_test("send_cmio_response fails if data is too big", function(machine)
    local reason = 1
    local data_too_big = string.rep("a", 1 + (1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE))
    machine:write_reg("iflags_Y", 1)
    -- the host send refuses upfront
    tests_util.assert_error("CMIO response data is too large", function()
        machine:send_cmio_response(reason, data_too_big)
    end)
    -- the logged operation cannot fail; it is a no-op that leaves the state unchanged
    local hash_before = machine:get_root_hash()
    machine:log_send_cmio_response(reason, data_too_big, CMIO_REVERT_HASH, tmpname_for_log())
    assert(machine:read_reg("iflags_Y") == 1)
    assert(machine:get_root_hash() == hash_before)
end)

do_test("advance-state response to a rejected machine logs as a no-op", function(machine)
    local advance_reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local data = "0123456789"
    -- the machine yielded manual but rejected the previous input
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
    machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
    machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    -- the host send refuses upfront
    local _, err = pcall(machine.send_cmio_response, machine, advance_reason, data, machine:get_root_hash())
    check_error_find(err, "machine is not waiting on an rx-accepted manual yield")
    -- the logged operation cannot fail; it is a no-op that leaves the state unchanged. The machine
    -- stays paused on a rejected yield, which must NOT trigger a revert substitution (send_cmio_response
    -- is not a step), so the post-operation hash is the unchanged machine root hash.
    local hash_before = machine:get_root_hash()
    local filename = tmpname_for_log()
    machine:log_send_cmio_response(advance_reason, data, hash_before, filename)
    assert(machine:read_reg("iflags_Y") == 1)
    local hash_after = machine:get_root_hash()
    assert(hash_after == hash_before)
    local obtained_hash =
        machine:verify_send_cmio_response(advance_reason, data, hash_before, filename, hash_before)
    assert(obtained_hash == hash_after)
end)

local function test_send_cmio_response_happy_path()
    local data = string.rep("a", 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE)
    local reason = 1
    local max_rx_buffer_len = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE
    local all_zeros = string.rep("\0", max_rx_buffer_len)
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
end

test_send_cmio_response_happy_path()

do_test("send_cmio_response should check the machine state for advance-state responses", function(machine)
    local advance_reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local data = "0123456789"
    local wrong_revert_root_hash = string.rep("\xff", cartesi.HASH_SIZE)
    -- put the machine in the state that waits for an advance-state input
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
    machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
    machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    local root_hash_before = machine:get_root_hash()
    -- a revert root hash other than the machine root hash is refused
    local _, err = pcall(machine.send_cmio_response, machine, advance_reason, data, wrong_revert_root_hash)
    check_error_find(err, "revert root hash does not match the machine root hash")
    -- the failed call did not change the machine state
    assert(machine:get_root_hash() == root_hash_before)
    -- an advance-state response without a revert root hash is refused
    _, err = pcall(machine.send_cmio_response, machine, advance_reason, data)
    check_error_find(err, "advance-state response requires a revert root hash")
    assert(machine:get_root_hash() == root_hash_before)
    -- a machine that is not waiting on an rx-accepted manual yield refuses the input
    machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    root_hash_before = machine:get_root_hash()
    local revert_root_hash = root_hash_before
    _, err = pcall(machine.send_cmio_response, machine, advance_reason, data, revert_root_hash)
    check_error_find(err, "machine is not waiting on an rx-accepted manual yield")
    assert(machine:get_root_hash() == root_hash_before)
    -- Other response reasons refuse the revert root hash
    _, err = pcall(machine.send_cmio_response, machine, cartesi.HTIF_YIELD_REASON_INSPECT_STATE, data, revert_root_hash)
    check_error_find(err, "revert root hash is only accepted for advance-state responses")
    assert(machine:get_root_hash() == root_hash_before)
    -- Other response reasons are not checked and do not change the mcycle limit.
    local imcyclemax = machine:read_reg("imcyclemax")
    machine:send_cmio_response(cartesi.HTIF_YIELD_REASON_INSPECT_STATE, data)
    assert(machine:read_reg("iflags_Y") == 0)
    assert(machine:read_reg("imcyclemax") == imcyclemax)
end)

do_test("advance-state response sets a saturating mcycle limit", function(machine)
    local advance_reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local function prepare()
        machine:write_reg("iflags_Y", 1)
        machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
        machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
    end
    local mcycle = 123
    machine:write_reg("mcycle", mcycle)
    prepare()
    machine:send_cmio_response(advance_reason, "", machine:get_root_hash())
    assert(machine:read_reg("imcyclemax") == mcycle + (1 << cartesi.ROLLUP_LOG2_MAX_MCYCLES_PER_ADVANCE_STATE) - 1)

    machine:write_reg("mcycle", cartesi.MCYCLE_MAX - 1)
    prepare()
    machine:send_cmio_response(advance_reason, "", machine:get_root_hash())
    assert(machine:read_reg("imcyclemax") == cartesi.MCYCLE_MAX)
end)

-- log_send_cmio_response writes (data || zero pad) to the rx buffer and logs it as:
-- no entry (data_len 0), a page entry (write_len <= page size), or a node entry at
-- AR_CMIO_RX_BUFFER_START with hash_after = merkle_tree_hash(data || zero pad).
do_test("send_cmio_response across data-size boundaries: machine state + log content", function(machine)
    local PAGE_LOG2 = cartesi.HASH_TREE_LOG2_PAGE_SIZE
    local PAGE_SIZE = 1 << PAGE_LOG2
    local WORD_SIZE = 1 << cartesi.HASH_TREE_LOG2_WORD_SIZE
    local rx_buffer_size = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE
    local rx_start = cartesi.AR_CMIO_RX_BUFFER_START
    local rx_page_idx = rx_start >> PAGE_LOG2
    local reason = 1
    local hash_fn = "keccak256"
    local initial_rx_buffer = string.rep("x", rx_buffer_size)
    -- Each row: data_len + the expected log2 of the rx-buffer write (nil = no write).
    local cases = {
        { data_len = 0, write_log2 = nil },
        { data_len = 1, write_log2 = 5 },
        { data_len = WORD_SIZE, write_log2 = 5 },
        { data_len = WORD_SIZE + 1, write_log2 = 6 },
        { data_len = PAGE_SIZE - 1, write_log2 = 12 },
        { data_len = PAGE_SIZE, write_log2 = 12 },
        { data_len = PAGE_SIZE + 1, write_log2 = 13 },
        { data_len = (1 << 20), write_log2 = 20 },
        { data_len = (1 << 20) + 1, write_log2 = 21 },
        { data_len = rx_buffer_size, write_log2 = cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE },
    }
    for _, c in ipairs(cases) do
        print(string.format("   data_len=%d  write_log2=%s", c.data_len, tostring(c.write_log2)))
        machine:write_memory(rx_start, initial_rx_buffer)
        local data = string.rep("a", c.data_len)
        local filename = tmpname_for_log()
        machine:write_reg("iflags_Y", 1)
        machine:log_send_cmio_response(reason, data, CMIO_REVERT_HASH, filename)

        -- Machine state: rx buffer = data || zero pad up to write_len, then the original "x"s.
        local write_len = c.write_log2 and (1 << c.write_log2) or 0
        local expected_rx = data
            .. string.rep("\0", write_len - c.data_len)
            .. string.rep("x", rx_buffer_size - write_len)
        assert(
            machine:read_memory(rx_start, rx_buffer_size) == expected_rx,
            string.format("rx buffer mismatch for data_len=%d", c.data_len)
        )

        -- Log content: zero-length writes touch no rx page/node; sub-page writes
        -- emit a page entry at the rx page index; supra-page writes emit a node
        -- entry at rx_start whose hash_after is computable from (data || zeros).
        local log_data = read_step_log_file(filename)
        if c.write_log2 == nil then
            for _, p in ipairs(log_data.pages) do
                assert(p.index ~= rx_page_idx, string.format("unexpected rx page touch for data_len=%d", c.data_len))
            end
            for _, n in ipairs(log_data.nodes) do
                assert(n.address ~= rx_start, string.format("unexpected rx node for data_len=%d", c.data_len))
            end
        elseif c.write_log2 > PAGE_LOG2 then
            local found
            for _, n in ipairs(log_data.nodes) do
                if n.address == rx_start then
                    found = n
                end
            end
            assert(found, string.format("missing rx node for data_len=%d", c.data_len))
            assert(
                found.log2_size == c.write_log2,
                string.format("node log2_size=%d != %d for data_len=%d", found.log2_size, c.write_log2, c.data_len)
            )
            local padded = data .. string.rep("\0", write_len - c.data_len)
            local expected_hash = tests_util.merkle_hash(padded, 0, c.write_log2, hash_fn)
            assert(
                found.hash_after == expected_hash,
                string.format("node hash_after mismatch for data_len=%d", c.data_len)
            )
        else
            local found
            for _, p in ipairs(log_data.pages) do
                if p.index == rx_page_idx then
                    found = p
                end
            end
            assert(found, string.format("missing rx page for data_len=%d", c.data_len))
            assert(
                found.data == string.rep("x", PAGE_SIZE),
                string.format("rx page pre-state mismatch for data_len=%d", c.data_len)
            )
        end
        os.remove(filename)
    end
end)

print("\n\ntesting verify_send_cmio_response unhappy paths")
do_test("verify_send_cmio_response rejects mismatched Layer 2 args and tampered data", function(machine)
    -- supra-page data (>4KB) -> rx-buffer write logged as a node entry, exercising
    -- the padded-hash mismatch check and node validation
    local data = string.rep("a", 5000)
    local reason = 1
    local bad_hash = string.rep("\0", cartesi.HASH_SIZE)
    machine:write_reg("iflags_Y", 1)
    local hash_before = machine:get_root_hash()
    local filename = tmpname_for_log()
    local corrupted = tmpname_for_log()
    machine:log_send_cmio_response(CMIO_REVERT_HASH, reason, data, filename)
    local hash_after = machine:get_root_hash()
    -- sanity: happy path
    machine:verify_send_cmio_response(CMIO_REVERT_HASH, reason, data, hash_before, filename, hash_after)
    -- bad root_hash_before arg
    local _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        bad_hash,
        filename,
        hash_after
    )
    check_error_find(err, "root hash before does not match")
    -- bad root_hash_after arg
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        filename,
        bad_hash
    )
    check_error_find(err, "root hash after does not match")
    -- tampered data: same length so the write_length_log2_size matches, but the
    -- bytes differ, so the recomputed padded merkle hash will not match the
    -- logged node's hash_after.
    local bad_data = string.rep("b", #data)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        bad_data,
        hash_before,
        filename,
        hash_after
    )
    check_error_find(err, "write_memory_with_padding does not match logged hash")
    -- node log2_size below page size: caught by replay parser
    copy_step_log(filename, corrupted, function(log_data)
        assert(#log_data.nodes >= 1, "cmio supra-page log should have at least one node")
        log_data.nodes[1].log2_size = cartesi.HASH_TREE_LOG2_PAGE_SIZE
    end)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        corrupted,
        hash_after
    )
    check_error_find(err, "invalid log format: node log2 size out of range")
    -- node address not aligned to its size: caught by replay parser
    copy_step_log(filename, corrupted, function(log_data)
        log_data.nodes[1].address = log_data.nodes[1].address + 1
    end)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        corrupted,
        hash_after
    )
    check_error_find(err, "node address not aligned to its size")
    -- duplicate the node so the combined pages+nodes stream has overlap
    copy_step_log(filename, corrupted, function(log_data)
        table.insert(log_data.nodes, {
            address = log_data.nodes[1].address,
            log2_size = log_data.nodes[1].log2_size,
            hash_before = log_data.nodes[1].hash_before,
            hash_after = log_data.nodes[1].hash_after,
        })
    end)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        corrupted,
        hash_after
    )
    check_error_find(err, "page or node overlaps a previous entry")
    -- node log2_size == HASH_TREE_LOG2_ROOT_SIZE spans the whole address space, so the
    -- parser requires address 0; the rx-buffer node's nonzero address trips "not aligned".
    copy_step_log(filename, corrupted, function(log_data)
        log_data.nodes[1].log2_size = cartesi.HASH_TREE_LOG2_ROOT_SIZE
    end)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        corrupted,
        hash_after
    )
    check_error_find(err, "node address not aligned to its size")
    -- a second node that no write consumes: its hash_after is folded into the
    -- post-state root verbatim, so the replayer must reject it
    copy_step_log(filename, corrupted, tests_util.inject_unconsumed_node)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        corrupted,
        hash_after
    )
    check_error_find(err, "unconsumed node in step log")
    -- canonical form: send_cmio_response logs must record requested_cycle_count = 0
    copy_step_log(filename, corrupted, function(log_data)
        log_data.requested_cycle_count = 1
    end)
    _, err = pcall(
        machine.verify_send_cmio_response,
        machine,
        CMIO_REVERT_HASH,
        reason,
        data,
        hash_before,
        corrupted,
        hash_after
    )
    check_error_find(err, "requested_cycle_count must be zero in send_cmio_response log")
    os.remove(filename)
    os.remove(corrupted)
end)

do_test("verify_send_cmio_response round-trips a single-byte sub-page write", function(machine)
    -- Sub-page round-trip: a single byte zero-pads to fill one 32-byte leaf word and
    -- is logged as a page entry the replayer reconstructs from data || zero pad.
    -- Pre-fill the rx buffer with non-zero bytes so the zero padding is meaningful.
    local rx_buffer_size = 1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE
    machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, string.rep("x", rx_buffer_size))
    local data = "a"
    local reason = 1
    machine:write_reg("iflags_Y", 1)
    local hash_before = machine:get_root_hash()
    local filename = tmpname_for_log()
    machine:log_send_cmio_response(CMIO_REVERT_HASH, reason, data, filename)
    local hash_after = machine:get_root_hash()
    machine:verify_send_cmio_response(CMIO_REVERT_HASH, reason, data, hash_before, filename, hash_after)
    os.remove(filename)
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
    local filename = tmpname_for_log()
    machine:log_send_cmio_response(reason, data, CMIO_REVERT_HASH, filename)
    local hash_after = machine:get_root_hash()
    assert(machine:verify_send_cmio_response(reason, data, hash_before, filename, CMIO_REVERT_HASH) == hash_after)
    os.remove(filename)
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

    tests_util.make_do_test(build_machine, machine_type, {
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
    tests_util.make_do_test(build_machine, machine_type, {
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
    tests_util.make_do_test(build_machine, machine_type, {
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

-- Sanity-only smoke for log_step. Corruption-rejection coverage lives in
-- spec-verify-step-failure.lua.
for _, hash_fn in pairs({ "keccak256", "sha256" }) do
    tests_util.make_do_test(build_machine, machine_type, { hash_tree = { hash_function = hash_fn }, uarch = {} })(
        "log_step sanity check",
        function(machine)
            local _, err
            local filename = os.tmpname()
            local deleter = {}
            setmetatable(deleter, {
                __gc = function()
                    os.remove(filename)
                end,
            })

            machine:write_reg("mcycle", 0)
            -- log_step rejects an already-existing target file
            _, err = pcall(function()
                machine:log_step(1, filename)
            end)
            check_error_find(err, "file already exists")
            os.remove(filename)
            assert(machine:read_reg("mcycle") == 0)

            -- happy round-trip: log_step then verify_step
            local root_hash_before = machine:get_root_hash()
            local mcycle_count = 10
            local status = machine:log_step(mcycle_count, filename)
            assert(status == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
            assert(machine:read_reg("mcycle") == mcycle_count)
            local root_hash_after = machine:get_root_hash()
            assert(root_hash_before ~= root_hash_after)
            -- verify step should pass and return the obtained root hash
            local obtained_root_hash = machine:verify_step(root_hash_before, filename, mcycle_count)
            assert(obtained_root_hash == root_hash_after)
            os.remove(filename)


            if hash_fn == "keccak256" then
                -- log_step requires uarch to be reset
                machine:run_uarch(1)
                _, err = pcall(function()
                    machine:log_step(1, filename)
                end)
                check_error_find(err, "microarchitecture is not reset")
                machine:reset_uarch()
            end
            status = machine:log_step(1, filename)
            assert(status == cartesi.BREAK_REASON_REACHED_TARGET_MCYCLE)
        end
    )
end

do_test("log_step from a rejected input state verifies against the revert root hash", function(machine)
    local filename = os.tmpname()
    os.remove(filename) -- log_step requires the file to not exist
    local deleter = {}
    setmetatable(deleter, {
        __gc = function()
            os.remove(filename)
        end,
    })
    local revert_hash = string.rep("\x5a", cartesi.HASH_SIZE)
    machine:write_revert_root_hash(revert_hash)
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
    machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
    machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    local mcycle_before = machine:read_reg("mcycle")
    local root_hash_before = machine:get_root_hash()
    machine:log_step(1, filename)
    -- the machine does not advance while the manual yield is pending
    assert(machine:read_reg("mcycle") == mcycle_before, "mcycle should not have advanced")
    assert(machine:get_root_hash() == root_hash_before, "machine state should not have changed")
    -- the canonical root hash after the step is the revert root hash,
    -- not the machine's actual root hash
    assert(machine:verify_step(root_hash_before, filename, 1) == revert_hash)
    assert(revert_hash ~= root_hash_before)
end)


print("\n\nAll machine binding tests for type " .. machine_type .. " passed")
