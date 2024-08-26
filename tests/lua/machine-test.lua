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
local test_util = require("cartesi.tests.util")

-- Note: for jsonrpc machine test to work, jsonrpc-remote-cartesi-machine must
-- run on the same computer and jsonrpc-remote-cartesi-machine execution path
-- must be provided

-- There is no UINT64_MAX in Lua, so we have to use the signed representation
local MAX_MCYCLE = -1

local remote_address
local test_path = "/tmp/"
local cleanup = {}

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
local function build_machine(type, config, runtime_config)
    config = config or {
        ram = { length = 1 << 20 },
    }
    runtime_config = runtime_config or {
        concurrency = {
            update_merkle_tree = 0,
        },
    }
    local new_machine
    if type ~= "local" then
        if not remote then
            remote = connect()
        end
        new_machine = assert(remote.machine(config, runtime_config))
    else
        new_machine = assert(cartesi.machine(config, runtime_config))
    end
    return new_machine
end

local do_test = test_util.make_do_test(build_machine, machine_type)

print("Testing machine for type " .. machine_type)

print("\n\ntesting getting machine initial config and iflags")
do_test("machine halt and yield flags and config matches", function(machine)
    -- Get machine default config  and test for known fields
    local initial_config = machine:get_initial_config()
    -- test_util.print_table(initial_config)
    assert(initial_config["processor"]["marchid"] == cartesi.MARCHID, "marchid value does not match")
    assert(initial_config["processor"]["pc"] == 0x80000000, "pc value does not match")
    assert(initial_config["ram"]["length"] == 1048576, "ram length value does not match")
    -- Check machine is not halted
    assert(not machine:read_iflags_H(), "machine shouldn't be halted")
    -- Check machine is not yielded
    assert(not machine:read_iflags_Y(), "machine shouldn't be yielded")
end)

print("\n\ntesting if machine initial hash is correct")
do_test("machine initial hash should match", function(machine)
    -- Get starting root hash
    local root_hash = machine:get_root_hash()

    local calculated_root_hash = test_util.calculate_emulator_hash(machine)

    print("Root hash:", test_util.tohex(root_hash), " calculated root hash:", test_util.tohex(calculated_root_hash))

    assert(root_hash == calculated_root_hash, "Initial root hash does not match")
end)

print("\n\ntesting root hash after step one")
do_test("machine root hash after step one should match", function(machine)
    -- Get starting root hash
    local root_hash = machine:get_root_hash()
    print("Root hash:", test_util.tohex(root_hash))

    local calculated_root_hash = test_util.calculate_emulator_hash(machine)
    assert(root_hash == calculated_root_hash, "Initial root hash does not match")

    -- Perform step and check if hash maches
    local log_type = {}
    machine:log_step_uarch(log_type)
    local root_hash_step1 = machine:get_root_hash()
    local calculated_root_hash_step1 = test_util.calculate_emulator_hash(machine)
    assert(root_hash_step1 == calculated_root_hash_step1, "hash after first step does not match")
end)

print("\n\ntesting proof after step one")
do_test("proof check should pass", function(machine)
    local log_type = {}
    machine:log_step_uarch(log_type)

    -- Find ram memory range
    local ram
    for _, v in ipairs(machine:get_memory_ranges()) do
        if v.description == "RAM" then
            ram = v
        end
    end
    -- Ccalculate hash of ram
    local ram_log2_size = math.ceil(math.log(ram.length, 2))
    local calculated_ram_hash = test_util.merkle_hash(machine:read_memory(ram.start, ram.length), 0, ram_log2_size)
    -- Get proof of ram and check if hashes match
    local ram_proof = machine:get_proof(ram.start, ram_log2_size)
    local root_hash = machine:get_root_hash()
    assert(root_hash == ram_proof.root_hash, "root hash in proof does not match")
    print(
        "target hash:",
        test_util.tohex(ram_proof.target_hash),
        " calculated target hash:",
        test_util.tohex(calculated_ram_hash)
    )
    assert(calculated_ram_hash == ram_proof.target_hash, "target hash in proof does not match")
end)

print("\n\nrun machine to 1000 mcycle and check for mcycle and root hash")
do_test("mcycle and root hash should match", function(machine)
    -- Run to 1000 cycle tics
    local current_mcycle = machine:read_mcycle()
    while current_mcycle < 1000 do
        machine:run(1000)
        current_mcycle = machine:read_mcycle()
    end

    assert(machine:read_mcycle() == 1000, "machine mcycle should be 1000")

    local root_hash = machine:get_root_hash()

    local calculated_root_hash_1000 = test_util.calculate_emulator_hash(machine)

    print("1000 cycle hash: ", test_util.tohex(root_hash))
    assert(root_hash == calculated_root_hash_1000, "machine hash does not match after 1000 cycles")
end)

print("\n\nrun machine to end mcycle and check for mcycle, hash and halt flag")
do_test("mcycle and root hash should match", function(machine)
    -- The following is a RISC-V bytecode that will halt the machine immediately,
    -- by writing 1 to HTIF tohost (0x40008000)
    local halt_bytecode = "\x93\x02\x10\x00" -- li t0,1
        .. "\x37\x83\x00\x40" -- lui t1,0x40008
        .. "\x23\x30\x53\x00" -- sd t0,0(t1) # 40008000
    machine:write_memory(machine:read_csr("pc"), halt_bytecode)

    machine:run(MAX_MCYCLE)
    -- Check machine is halted
    assert(machine:read_iflags_H(), "machine should be halted")
    -- Check for end mcycle
    local end_mcycle = machine:read_mcycle()
    assert(end_mcycle == 3, "machine mcycle should be 3")

    local root_hash = machine:get_root_hash()
    print("End hash: ", test_util.tohex(root_hash))

    local calculated_end_hash = test_util.calculate_emulator_hash(machine)

    assert(root_hash == calculated_end_hash, "machine hash does not match after on end cycle")
end)

if machine_type == "local" then
    print("\n\ntesting soft yield")
    test_util.make_do_test(build_machine, machine_type, {
        ram = { length = 1 << 20 },
    }, {
        soft_yield = true,
    })("check soft yield", function(machine)
        -- The following is a RISC-V bytecode that cause a soft yield immediately,
        local function sraiw(rd, rs1, shamt)
            return 0x4000501b | (rd << 7) | (rs1 << 15) | (shamt << 20)
        end
        local soft_yield_insn = sraiw(0, 31, 7)

        machine:write_memory(machine:read_csr("pc"), string.pack("<I4", soft_yield_insn))

        assert(machine:run(1000) == cartesi.BREAK_REASON_YIELDED_SOFTLY)

        -- Check machine state
        assert(machine:read_mcycle() == 1, "machine mcycle should be 1")
        assert(not machine:read_iflags_H())
        assert(not machine:read_iflags_Y())
        assert(not machine:read_iflags_X())

        -- Check if previous instruction match
        local prev_insn = string.unpack("<I4", machine:read_virtual_memory(machine:read_csr("pc") - 4, 4))
        assert(prev_insn == soft_yield_insn)
    end)
end

print("\n\nwrite something to ram memory and check if hash and proof matches")
do_test("proof  and root hash should match", function(machine)
    local ram_address_start = 0x80000000

    -- Find proof for first KB of ram
    local initial_ram_proof = machine:get_proof(ram_address_start, 10)
    -- Calculate hash
    local initial_memory_read = machine:read_memory(ram_address_start, 2 ^ 10)
    local initial_calculated_hash = test_util.merkle_hash(initial_memory_read, 0, 10)
    assert(initial_ram_proof.target_hash == initial_calculated_hash, "initial hash does not match")

    print(
        "initial target hash:",
        test_util.tohex(initial_ram_proof.target_hash),
        " calculated initial target hash:",
        test_util.tohex(initial_calculated_hash)
    )

    machine:write_memory(0x8000000F, "mydataol12345678", 0x10)

    local verify = machine:verify_merkle_tree()
    assert(verify, "verify merkle tree failed")

    -- Find proof for first KB of ram
    local ram_proof = machine:get_proof(ram_address_start, 10)
    -- Calculate hash
    local memory_read = machine:read_memory(ram_address_start, 2 ^ 10)
    local calculated_hash = test_util.merkle_hash(memory_read, 0, 10)

    print(
        "end target hash:",
        test_util.tohex(ram_proof.target_hash),
        " calculated end target hash:",
        test_util.tohex(calculated_hash)
    )

    assert(initial_ram_proof.target_hash ~= ram_proof.target_hash, "hash is same after memory is written")

    assert(initial_calculated_hash ~= calculated_hash, "calculated hash is same after memory is written")

    assert(ram_proof.target_hash == calculated_hash, "hash does not match after memory is written")
end)

print("\n\n check dirty page maps")
do_test("dirty page maps should be consistent", function(machine)
    -- Verify dirty page maps
    assert(machine:verify_dirty_page_maps(), "error verifying dirty page maps")
end)

print("\n\n check replace flash drives")
test_util.make_do_test(build_machine, machine_type, {
    processor = {},
    ram = { length = 1 << 20 },
    flash_drive = {
        {
            start = 0x80000000000000,
            length = 0x100000,
            shared = false,
        },
    },
})("should replace flash drive and read something", function(machine)
    local rootfs_length = machine:get_initial_config().flash_drive[1].length
    -- Create temp flash file
    local input_path = test_path .. "input.raw"
    local command = "echo 'test data 1234567890' > "
        .. input_path
        .. " && truncate -s "
        .. tostring(rootfs_length)
        .. " "
        .. input_path
    local p = io.popen(command)
    p:close()

    local flash_address_start = 0x80000000000000
    local flash_drive_config = {
        start = flash_address_start,
        length = rootfs_length,
        image_filename = input_path,
        shared = true,
    }

    machine:read_memory(flash_address_start, 20)

    machine:replace_memory_range(flash_drive_config)

    local flash_data = machine:read_memory(flash_address_start, 20)
    assert(flash_data == "test data 1234567890", "data read from replaced flash failed")
    os.remove(input_path)
end)

print("\n\n check for relevant register values after step 1")
do_test("register values should match", function(machine)
    local uarch_pc_before = machine:read_csr("uarch_pc")
    local uarch_cycle_before = machine:read_uarch_cycle()

    local log_type = {}
    machine:log_step_uarch(log_type)

    local uarch_pc_after = machine:read_csr("uarch_pc")
    local uarch_cycle_after = machine:read_uarch_cycle()

    assert(uarch_pc_before + 4 == uarch_pc_after, "wrong uarch_pc value")
    assert(uarch_cycle_before + 1 == uarch_cycle_after, "wrong uarch_cycle value")
end)

if machine_type ~= "local" then
    print("\n\n check remote get_machine")
    do_test("get_machine should get reference to working machine", function(machine)
        local machine_2 = remote.get_machine()
        assert(machine:get_root_hash() == machine_2:get_root_hash())
        machine_2:destroy()
        local ret, err = pcall(function()
            machine:get_root_hash()
        end)
        assert(ret == false)
        assert(err:match("no machine"))
    end)

    do_test("jsonrpc connection error 49 after rapid successive requests ", function(machine)
        -- On a Mac, this loop will break with  EADDRNOTAVAIL(49)
        -- Setting up the SO_LINGER to 0 fixed this issue
        for _ = 1, 16384 do
            local data = machine:read_memory(0, 4096)
            assert(#data == 4096)
        end
    end)
end

print("\n\nAll tests of machine lua API for type " .. machine_type .. "  passed")
