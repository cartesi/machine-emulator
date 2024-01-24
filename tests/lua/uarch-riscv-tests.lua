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

-- Tests Cases
-- format {"ram_image_file", number_of_uarch_cycles}
local riscv_tests = {
    { "rv64ui-uarch-simple.bin", 12 },
    { "rv64ui-uarch-add.bin", 441 },
    { "rv64ui-uarch-addi.bin", 216 },
    { "rv64ui-uarch-addiw.bin", 213 },
    { "rv64ui-uarch-addw.bin", 436 },
    { "rv64ui-uarch-and.bin", 516 },
    { "rv64ui-uarch-andi.bin", 187 },
    { "rv64ui-uarch-auipc.bin", 30 },
    { "rv64ui-uarch-beq.bin", 262 },
    { "rv64ui-uarch-bge.bin", 280 },
    { "rv64ui-uarch-bgeu.bin", 370 },
    { "rv64ui-uarch-blt.bin", 262 },
    { "rv64ui-uarch-bltu.bin", 348 },
    { "rv64ui-uarch-bne.bin", 262 },
    { "rv64ui-uarch-jal.bin", 26 },
    { "rv64ui-uarch-jalr.bin", 86 },
    { "rv64ui-uarch-lb.bin", 224 },
    { "rv64ui-uarch-lbu.bin", 224 },
    { "rv64ui-uarch-lh.bin", 240 },
    { "rv64ui-uarch-lhu.bin", 249 },
    { "rv64ui-uarch-lw.bin", 254 },
    { "rv64ui-uarch-lwu.bin", 288 },
    { "rv64ui-uarch-ld.bin", 406 },
    { "rv64ui-uarch-lui.bin", 36 },
    { "rv64ui-uarch-or.bin", 549 },
    { "rv64ui-uarch-ori.bin", 180 },
    { "rv64ui-uarch-sb.bin", 425 },
    { "rv64ui-uarch-sh.bin", 478 },
    { "rv64ui-uarch-sw.bin", 485 },
    { "rv64ui-uarch-sd.bin", 597 },
    { "rv64ui-uarch-sll.bin", 511 },
    { "rv64ui-uarch-slli.bin", 241 },
    { "rv64ui-uarch-slliw.bin", 248 },
    { "rv64ui-uarch-sllw.bin", 511 },
    { "rv64ui-uarch-slt.bin", 430 },
    { "rv64ui-uarch-slti.bin", 208 },
    { "rv64ui-uarch-sltiu.bin", 208 },
    { "rv64ui-uarch-sltu.bin", 447 },
    { "rv64ui-uarch-sra.bin", 483 },
    { "rv64ui-uarch-srai.bin", 229 },
    { "rv64ui-uarch-sraiw.bin", 275 },
    { "rv64ui-uarch-sraw.bin", 523 },
    { "rv64ui-uarch-srl.bin", 525 },
    { "rv64ui-uarch-srli.bin", 250 },
    { "rv64ui-uarch-srliw.bin", 257 },
    { "rv64ui-uarch-srlw.bin", 517 },
    { "rv64ui-uarch-sub.bin", 432 },
    { "rv64ui-uarch-subw.bin", 428 },
    { "rv64ui-uarch-xor.bin", 544 },
    { "rv64ui-uarch-xori.bin", 178 },
    { "rv64ui-uarch-fence.bin", 13 },
}

-- Print help and exit
local function help()
    io.stderr:write(string.format(
        [=[
Usage:
  %s [options] <command>
where options are:
  --test-path=<dir>
    path to test binaries
    (default: "./")
  --test=<pattern>
    select tests to run based on a Lua string <pattern>
    (default: ".*", i.e., all tests)
  --output-dir=<directory-path>
    write json logs to this  directory
  --proofs
    include proofs in the log
  --proofs-frequency=<number>
    write proof of every <number> uarch cycles
    (default: 1, i.e., all accesses)

and command can be:
  run
    run test and report errors

  list
    list tests selected by the test <pattern>

  json-step-logs
    generate json log files for every step of the selected tests
    the files are written to the directory specified by --output-dir
    these log files are used by Solidity unit tests

  json-reset-log
    generate the file uarch-reset.json containing the log of a uarch reset operation
    the file is written to the directory specified by --output-dir
    this log file is used by Solidity unit tests

]=],
        arg[0]
    ))
    os.exit()
end

local test_path = test_util.tests_uarch_path
local test_pattern = ".*"
local output_dir
local proofs = false
local proofs_frequency = 1
local total_steps_counter = 0

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
        "^%-%-output%-dir%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            output_dir = o
            return true
        end,
    },
    {
        "^%-%-test%-path%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            test_path = o
            return true
        end,
    },
    {
        "^%-%-test%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            test_pattern = o
            return true
        end,
    },
    {
        "^%-%-proofs$",
        function(o)
            if not o or #o < 1 then return false end
            proofs = true
            return true
        end,
    },
    {
        "^%-%-proofs%-frequency%=(.+)$",
        function(n)
            if not n then return false end
            proofs_frequency = assert(util.parse_number(n), "invalid proofs frequency " .. n)
            assert(proofs_frequency > 0, "proofs frequency must be > 0")
            return true
        end,
    },
    { ".*", function(all) error("unrecognized option " .. all) end },
}

local values = {}

-- Process command line options
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then break end
        end
    else
        values[#values + 1] = argument
    end
end

local command = assert(values[1], "missing command")
assert(test_path, "missing test path")

local function build_machine(test_name)
    local uarch_ram = {}
    if test_name then uarch_ram.image_filename = test_path .. "/" .. test_name end
    local config = {
        ram = {
            length = 0x20000,
        },
        uarch = {
            ram = uarch_ram,
        },
    }
    local runtime = {}
    return assert(cartesi.machine(config, runtime))
end

local function add_error(errors, ram_image, msg, ...)
    local e = string.format(msg, ...)
    if not errors[ram_image] then errors[ram_image] = {} end
    local ram_image_errors = errors[ram_image]
    ram_image_errors[#ram_image_errors + 1] = e
end

local TEST_STATUS_X = 1 -- When test finishes executing,the value of this register contains the test result code
local FAILED_TEST_CASE_X = 3 -- If test fails, the value of this register contains the failed test case
local TEST_SUCCEEDED = 0xbe1e7aaa -- Value indicating that test has passed
local TEST_FAILED = 0xdeadbeef -- Value indicating that test has failed

local function check_test_result(machine, ctx, errors)
    local test_status = machine:read_uarch_x(TEST_STATUS_X)
    if test_status == TEST_FAILED then
        local failed_test_case = machine:read_uarch_x(FAILED_TEST_CASE_X)
        add_error(errors, ctx.ram_image, "failed test case %d", failed_test_case)
        ctx.failed = true
    end
    if test_status ~= TEST_SUCCEEDED then
        add_error(errors, ctx.ram_image, "Unrecognized test status %x", test_status)
        ctx.failed = true
    end
    local cycle = machine:read_uarch_cycle()
    if cycle ~= ctx.expected_cycles then
        add_error(errors, ctx.ram_image, "Unexpected final cycle count: %d, expected: %d", cycle, ctx.expected_cycles)
        ctx.failed = true
    end
end

local function run(tests)
    local errors, error_count = {}, 0
    for _, test in ipairs(tests) do
        local ctx = {
            ram_image = test[1],
            expected_cycles = test[2],
            failed = false,
            cycles = 0,
        }
        local machine <close> = build_machine(ctx.ram_image)
        io.write(ctx.ram_image, ": ")
        machine:run_uarch(2 * ctx.expected_cycles)
        check_test_result(machine, ctx, errors)
        if ctx.failed then
            print("failed")
            error_count = error_count + 1
        else
            print("passed")
        end
    end
    if error_count > 0 then
        io.write(string.format("\nFAILED %d of %d tests:\n\n", error_count, #tests))
        for k, v in pairs(errors) do
            for _, e in ipairs(v) do
                io.write(string.format("\t%s: %s\n", k, e))
            end
        end
        os.exit(1, true)
    else
        io.write(string.format("\nPASSED all %d tests\n\n", #tests))
        os.exit(0, true)
    end
end

local function list(tests)
    for _, test in ipairs(tests) do
        print(test[1])
    end
end

local function select_test(test_name, patt)
    local i, j = test_name:find(patt)
    if i == 1 and j == #test_name then return true end
    i, j = test_name:find(patt, 1, true)
    return i == 1 and j == #test_name
end

local function make_json_log_file_name(test_name, suffix) return test_name .. (suffix or "") .. ".json" end

local function create_json_log_file(test_name, suffix)
    local file_path = output_dir .. "/" .. make_json_log_file_name(test_name, suffix)
    return assert(io.open(file_path, "w"), "error opening file " .. file_path)
end

local function open_steps_json_log(test_name) return create_json_log_file(test_name, "-steps") end

local function write_sibling_hashes_to_log(sibling_hashes, out, indent)
    util.indentout(out, indent, '"sibling_hashes": [\n')
    for i, h in ipairs(sibling_hashes) do
        util.indentout(out, indent + 1, '"%s"', util.hexhash(h))
        if sibling_hashes[i + 1] then
            out:write(",\n")
        else
            out:write("\n")
        end
    end
    util.indentout(out, indent, "]\n")
end

local function write_access_to_log(access, out, indent, last)
    util.indentout(out, indent, "{\n")
    util.indentout(out, indent + 1, '"type": "%s",\n', access.type)
    util.indentout(out, indent + 1, '"address": %u,\n', access.address)
    util.indentout(out, indent + 1, '"log2_size": %u,\n', access.log2_size)
    if access.type == "write" then
        local value = "null"
        if access.written then value = '"' .. util.hexstring(access.written) .. '"' end
        util.indentout(out, indent + 1, '"value": %s,', value)
        util.indentout(out, indent + 1, '"hash": "%s",', util.hexhash(access.written_hash))
        util.indentout(out, indent + 1, '"read_hash": "%s"', util.hexhash(access.read_hash))
    else
        local value = "null"
        if access.read then value = '"' .. util.hexstring(access.read) .. '"' end
        util.indentout(out, indent + 1, '"value": %s,', value)
        util.indentout(out, indent + 1, '"hash": "%s",', util.hexhash(access.read_hash))
        util.indentout(out, indent + 1, '"read_hash": "%s"', util.hexhash(access.read_hash))
    end
    if access.sibling_hashes then
        out:write(",\n")
        write_sibling_hashes_to_log(access.sibling_hashes, out, indent + 2)
    else
        out:write("\n")
    end
    util.indentout(out, indent, "}")
    if not last then out:write(",") end
    out:write("\n")
end

local function write_log_to_file(log, out, indent, last)
    local n = #log.accesses
    util.indentout(out, indent, "{\n")
    util.indentout(out, indent + 1, '"accesses": [\n')
    for i, access in ipairs(log.accesses) do
        write_access_to_log(access, out, indent + 2, i == n)
    end
    util.indentout(out, indent + 1, "]\n")
    util.indentout(out, indent, "}")
    if not last then out:write(",") end
    out:write("\n")
end

local function create_catalog_json_log(contexts)
    local out = create_json_log_file("catalog")
    util.indentout(out, 0, "[\n")
    local n = #contexts
    for i, ctx in ipairs(contexts) do
        local path = make_json_log_file_name(ctx.test_name, "-steps")
        util.indentout(
            out,
            1,
            '{"path": "%s", "steps": %d, "proofs":%s, "proofsFrequency":%d, '
                .. '"initialRootHash": "%s", "finalRootHash": "%s"}',
            path,
            ctx.step_count,
            proofs,
            proofs_frequency,
            util.hexhash(ctx.initial_root_hash),
            util.hexhash(ctx.final_root_hash)
        )
        if i < n then
            out:write(",\n")
        else
            out:write("\n")
        end
    end
    util.indentout(out, 0, "]\n")
    out:close()
end

local function should_log_proofs()
    if not proofs then return false end
    return (total_steps_counter % proofs_frequency) == 0
end

local function run_machine_writing_json_logs(machine, ctx)
    local test_name = ctx.test_name
    local max_cycle = ctx.expected_cycles * 2
    local out = open_steps_json_log(test_name)
    local indent = 0
    util.indentout(out, indent, '{ "steps":[\n')
    local step_count = 0
    while math.ult(machine:read_uarch_cycle(), max_cycle) do
        local log_type = { proofs = should_log_proofs() }
        local log = machine:log_uarch_step(log_type)
        total_steps_counter = total_steps_counter + 1
        step_count = step_count + 1
        local halted = machine:read_uarch_halt_flag()
        write_log_to_file(log, out, indent + 1, halted)
        if halted then break end
    end
    ctx.step_count = step_count
    util.indentout(out, indent, "]}\n")
    out:close()
end

local function json_step_logs(tests)
    assert(output_dir, "output-dir is required for json-logs")
    local errors, error_count = {}, 0
    local contexts = {}
    for _, test in ipairs(tests) do
        local ctx = {
            ram_image = test[1],
            test_name = test[1]:gsub(".bin$", ""),
            expected_cycles = test[2],
            failed = false,
            step_count = 0,
            accesses_count = 0,
        }
        contexts[#contexts + 1] = ctx
        local machine <close> = build_machine(ctx.ram_image)
        io.write(ctx.ram_image, ": ")
        ctx.initial_root_hash = machine:get_root_hash()
        run_machine_writing_json_logs(machine, ctx)
        ctx.final_root_hash = machine:get_root_hash()
        check_test_result(machine, ctx, errors)
        if ctx.failed then
            print("failed")
            error_count = error_count + 1
        else
            print("passed")
        end
    end
    if error_count > 0 then
        io.write(string.format("\nFAILED %d of %d tests:\n\n", error_count, #tests))
        for k, v in pairs(errors) do
            for _, e in ipairs(v) do
                io.write(string.format("\t%s: %s\n", k, e))
            end
        end
        os.exit(1, true)
    else
        io.write(string.format("\nPASSED all %d tests\n\n", #tests))
        create_catalog_json_log(contexts)
        os.exit(0, true)
    end
end

local function json_reset_log()
    local machine <close> = build_machine()
    local log = machine:log_uarch_reset({ proofs = proofs })
    local out = create_json_log_file("uarch-reset")
    write_log_to_file(log, out, 0, true)
    out:close()
end

local selected_tests = {}
for _, test in ipairs(riscv_tests) do
    if select_test(test[1], test_pattern) then selected_tests[#selected_tests + 1] = test end
end

if #selected_tests < 1 then
    error("no test selected")
elseif command == "run" then
    run(selected_tests)
elseif command == "list" then
    list(selected_tests)
elseif command == "json-step-logs" then
    json_step_logs(selected_tests)
elseif command == "json-reset-log" then
    json_reset_log()
else
    error("command not found")
end
