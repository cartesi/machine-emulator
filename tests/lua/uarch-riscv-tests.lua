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
local parallel = require("cartesi.parallel")

-- Tests Cases
-- format {"ram_image_file", number_of_uarch_cycles, expectd_error_pattern}
local riscv_tests = {
    { "rv64ui-uarch-simple.bin", 11 },
    { "rv64ui-uarch-add.bin", 440 },
    { "rv64ui-uarch-addi.bin", 215 },
    { "rv64ui-uarch-addiw.bin", 212 },
    { "rv64ui-uarch-addw.bin", 435 },
    { "rv64ui-uarch-and.bin", 515 },
    { "rv64ui-uarch-andi.bin", 186 },
    { "rv64ui-uarch-auipc.bin", 29 },
    { "rv64ui-uarch-beq.bin", 261 },
    { "rv64ui-uarch-bge.bin", 279 },
    { "rv64ui-uarch-bgeu.bin", 369 },
    { "rv64ui-uarch-blt.bin", 261 },
    { "rv64ui-uarch-bltu.bin", 347 },
    { "rv64ui-uarch-bne.bin", 261 },
    { "rv64ui-uarch-jal.bin", 25 },
    { "rv64ui-uarch-jalr.bin", 85 },
    { "rv64ui-uarch-lb.bin", 223 },
    { "rv64ui-uarch-lbu.bin", 223 },
    { "rv64ui-uarch-lh.bin", 239 },
    { "rv64ui-uarch-lhu.bin", 248 },
    { "rv64ui-uarch-lw.bin", 253 },
    { "rv64ui-uarch-lwu.bin", 287 },
    { "rv64ui-uarch-ld.bin", 405 },
    { "rv64ui-uarch-lui.bin", 35 },
    { "rv64ui-uarch-or.bin", 548 },
    { "rv64ui-uarch-ori.bin", 179 },
    { "rv64ui-uarch-sb.bin", 424 },
    { "rv64ui-uarch-sh.bin", 477 },
    { "rv64ui-uarch-sw.bin", 484 },
    { "rv64ui-uarch-sd.bin", 596 },
    { "rv64ui-uarch-sll.bin", 510 },
    { "rv64ui-uarch-slli.bin", 240 },
    { "rv64ui-uarch-slliw.bin", 247 },
    { "rv64ui-uarch-sllw.bin", 510 },
    { "rv64ui-uarch-slt.bin", 429 },
    { "rv64ui-uarch-slti.bin", 207 },
    { "rv64ui-uarch-sltiu.bin", 207 },
    { "rv64ui-uarch-sltu.bin", 446 },
    { "rv64ui-uarch-sra.bin", 482 },
    { "rv64ui-uarch-srai.bin", 228 },
    { "rv64ui-uarch-sraiw.bin", 274 },
    { "rv64ui-uarch-sraw.bin", 522 },
    { "rv64ui-uarch-srl.bin", 524 },
    { "rv64ui-uarch-srli.bin", 249 },
    { "rv64ui-uarch-srliw.bin", 256 },
    { "rv64ui-uarch-srlw.bin", 516 },
    { "rv64ui-uarch-sub.bin", 431 },
    { "rv64ui-uarch-subw.bin", 427 },
    { "rv64ui-uarch-xor.bin", 543 },
    { "rv64ui-uarch-xori.bin", 177 },
    { "rv64ui-uarch-fence.bin", 12 },
    { "rv64ui-uarch-ecall-putchar.bin", 14 },
    { "rv64ui-uarch-ecall-unsupported.bin", 1, "unsupported ecall functio" },
    { "rv64ui-uarch-ebreak.bin", 1, "uarch aborted" },
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
  --jobs=<N>
    run N tests in parallel
    (default: 1, i.e., run tests sequentially)
  --output-dir=<directory-path>
    write json logs to this  directory
  --create-reset-uarch-log
    create a json log file for a uarch reset operation
    valid only for the json-step-logs command
--create-send-cmio-response-log
    create a json log file for a send_cmio_response operation
    valid only for the json-step-logs command
and command can be:
  run
    run test and report errors

  list
    list tests selected by the test <pattern>

  json-step-logs
    generate json log files for every step of the selected tests
    the files are written to the directory specified by --output-dir
    these log files are used by Solidity unit tests
]=],
        arg[0]
    ))
    os.exit()
end

local test_path = test_util.tests_uarch_path
local test_pattern = ".*"
local output_dir
local jobs = 1
local create_uarch_reset_log = false
local create_send_cmio_response_log = false

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
        "^%-%-create%-reset%-uarch%-log$",
        function(all)
            if not all then
                return false
            end
            create_uarch_reset_log = true
            return true
        end,
    },
    {
        "^%-%-create%-send%-cmio%-response%-log$",
        function(all)
            if not all then
                return false
            end
            create_send_cmio_response_log = true
            return true
        end,
    },
    {
        "^%-%-output%-dir%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            output_dir = o
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
            return true
        end,
    },
    {
        "^%-%-test%=(.*)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            test_pattern = o
            return true
        end,
    },
    {
        "^%-%-jobs%=([0-9]+)$",
        function(o)
            if not o or #o < 1 then
                return false
            end
            jobs = tonumber(o)
            assert(jobs and jobs >= 1, "invalid number of jobs")
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

local values = {}

-- Process command line options
for _, argument in ipairs({ ... }) do
    if argument:sub(1, 1) == "-" then
        for _, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        values[#values + 1] = argument
    end
end

local command = assert(values[1], "missing command")
assert(test_path, "missing test path")

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end
local function fatal(fmt, ...)
    error(string.format(fmt, ...))
end

local function build_machine(test_name)
    local uarch_ram = {}
    if test_name then
        uarch_ram.image_filename = test_path .. "/" .. test_name
    end
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

local TEST_STATUS_X = 1 -- When test finishes executing,the value of this register contains the test result code
local FAILED_TEST_CASE_X = 3 -- If test fails, the value of this register contains the failed test case
local TEST_SUCCEEDED = 0xbe1e7aaa -- Value indicating that test has passed
local TEST_FAILED = 0xdeadbeef -- Value indicating that test has failed

local function read_all(path)
    local file <close> = assert(io.open(path, "rb"))
    local contents = file:read("*a")
    file:close()
    return contents
end

local function check_test_result(machine, ctx)
    local actual_cycle = machine:read_uarch_cycle()
    if ctx.uarch_run_success then
        if ctx.expected_error_pattern then
            fatal(
                "%s: failed. run_uarch was expected to fail with error `%s`, but it succeeded\n",
                ctx.ram_image,
                ctx.expected_error_pattern
            )
        end
    else
        if not ctx.expected_error_pattern then
            fatal("%s: failed. run_uarch failed unexpectedly with error: %s\n", ctx.ram_image, ctx.actual_error)
        end
        if not ctx.actual_error:match(ctx.expected_error_pattern) then
            fatal(
                "%s: failed. error `%s` does not match `%s`",
                ctx.ram_image,
                ctx.actual_error,
                ctx.expected_error_pattern
            )
        end
        if actual_cycle ~= ctx.expected_cycles then
            fatal(
                "%s: failed. unexpected cycle count: %d, expected: %d",
                ctx.ram_image,
                actual_cycle,
                ctx.expected_cycles
            )
        end
        return -- failed with the expected error at the expected cycle
    end
    local test_status = machine:read_reg("uarch_x" .. TEST_STATUS_X)
    if test_status == TEST_FAILED then
        local failed_test_case = machine:read_reg("uarch_x" .. FAILED_TEST_CASE_X)
        fatal("%s: failed. test case is: %d\n", failed_test_case)
    end
    if test_status ~= TEST_SUCCEEDED then
        fatal("%s: failed. unrecognized test status %x\n", ctx.ram_image, test_status)
    end
    if actual_cycle ~= ctx.expected_cycles then
        fatal(
            "%s: failed. unexpected final cycle count %d, expected: %d\n",
            ctx.ram_image,
            actual_cycle,
            ctx.expected_cycles
        )
    end
    stderr("%s: passed.\n", ctx.ram_image)
end

local function run(tests)
    local failures = parallel.run(tests, jobs, function(test)
        local ctx = {
            ram_image = test[1],
            expected_cycles = test[2],
            failed = true,
            cycles = 0,
            expected_error_pattern = test[3],
            actual_error = nil,
            uarch_run_success = false,
        }
        local machine <close> = build_machine(ctx.ram_image)
        local uarch_run_success, err = pcall(function()
            machine:run_uarch(2 * ctx.expected_cycles)
        end)
        ctx.uarch_run_success = uarch_run_success
        if not uarch_run_success then
            ctx.actual_error = err
        end
        check_test_result(machine, ctx)
    end)

    -- print summary
    if failures ~= nil then
        if failures > 0 then
            stderr(string.format("\nFAILED %d of %d tests\n\n", failures, #tests))
            os.exit(1)
        else
            stderr(string.format("\nPASSED all %d tests\n\n", #tests))
            os.exit(0)
        end
    end
end

local function list(tests)
    for _, test in ipairs(tests) do
        print(test[1])
    end
end

local function select_test(test_name, patt)
    local i, j = test_name:find(patt)
    if i == 1 and j == #test_name then
        return true
    end
    i, j = test_name:find(patt, 1, true)
    return i == 1 and j == #test_name
end

local function make_json_log_file_name(test_name, suffix)
    return test_name .. (suffix or "") .. ".json"
end

local function create_json_log_file(test_name, suffix)
    local file_path = output_dir .. "/" .. make_json_log_file_name(test_name, suffix)
    return assert(io.open(file_path, "w"), "error opening file " .. file_path)
end

local function open_steps_json_log(test_name)
    return create_json_log_file(test_name, "-steps")
end

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
    local read_value = "" -- Solidity JSON parser breaks, if this field is null
    if access.read then
        read_value = util.hexstring(access.read)
    end
    util.indentout(out, indent + 1, '"read_value": "%s",\n', read_value)
    util.indentout(out, indent + 1, '"read_hash": "%s",\n', util.hexhash(access.read_hash))
    local written_value = ""
    local written_hash = ""
    if access.type == "write" then
        written_hash = util.hexhash(access.written_hash)
        if access.written then
            written_value = util.hexstring(access.written)
        end
    end
    util.indentout(out, indent + 1, '"written_value": "%s",\n', written_value)
    util.indentout(out, indent + 1, '"written_hash": "%s"', written_hash)
    if access.sibling_hashes then
        out:write(",\n")
        write_sibling_hashes_to_log(access.sibling_hashes, out, indent + 2)
    else
        out:write("\n")
    end
    util.indentout(out, indent, "}")
    if not last then
        out:write(",")
    end
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
    if not last then
        out:write(",")
    end
    out:write("\n")
end

local function catalog_entry_file_name(name)
    return output_dir .. "/" .. make_json_log_file_name(name, "-catalog-entry")
end

local function write_catalog_json_log_entry(out, logFilename, ctx)
    util.indentout(
        out,
        1,
        '{"logFilename": "%s", "binaryFilename": "%s", "steps": %d, '
            .. '"initialRootHash": "%s", "finalRootHash": "%s"}',
        logFilename,
        ctx.ram_image or "",
        ctx.step_count,
        util.hexhash(ctx.initial_root_hash),
        util.hexhash(ctx.final_root_hash)
    )
end

local function create_catalog_json_log_entry(ctx)
    local out <close> = create_json_log_file(ctx.test_name, "-catalog-entry")
    local logFilename = make_json_log_file_name(ctx.test_name, "-steps")
    write_catalog_json_log_entry(out, logFilename, ctx)
    out:close()
end

local function run_machine_writing_json_logs(machine, ctx)
    local test_name = ctx.test_name
    local max_cycle = ctx.expected_cycles * 2
    local out = open_steps_json_log(test_name)
    local indent = 0
    util.indentout(out, indent, '{ "steps":[\n')
    local step_count = 0
    while math.ult(machine:read_uarch_cycle(), max_cycle) do
        local log = machine:log_step_uarch()
        step_count = step_count + 1
        local halted = machine:read_uarch_halt_flag()
        write_log_to_file(log, out, indent + 1, halted)
        if halted then
            break
        end
    end
    ctx.step_count = step_count
    ctx.uarch_run_success = true
    util.indentout(out, indent, "]}\n")
    out:close()
end

local function create_json_reset_log()
    local machine <close> = build_machine()
    local test_name = "reset-uarch"
    machine:set_uarch_halt_flag()
    local initial_root_hash = machine:get_root_hash()
    local log = machine:log_reset_uarch()
    local out = create_json_log_file(test_name .. "-steps")
    write_log_to_file(log, out, 0, true)
    out:close()
    local ctx = {
        initial_root_hash = initial_root_hash,
        final_root_hash = machine:get_root_hash(),
        ram_image = "",
        test_name = test_name,
        expected_cycles = 1,
        step_count = 1,
        failed = false,
        accesses_count = #log.accesses,
    }
    return ctx
end

local function create_json_send_cmio_response_log()
    local machine <close> = build_machine()
    local test_name = "send-cmio-response"
    local response_data = "This is a test cmio response"
    local reason = 1
    machine:set_iflags_Y()
    local initial_root_hash = machine:get_root_hash()
    local log = machine:log_send_cmio_response(reason, response_data)
    local out = create_json_log_file(test_name .. "-steps")
    write_log_to_file(log, out, 0, true)
    out:close()
    local ctx = {
        initial_root_hash = initial_root_hash,
        final_root_hash = machine:get_root_hash(),
        ram_image = "",
        test_name = test_name,
        expected_cycles = 1,
        step_count = 1,
        failed = false,
        accesses_count = #log.accesses,
    }
    return ctx
end

local function json_step_logs(tests)
    assert(output_dir, "output-dir is required for json-logs")
    -- filter out tests that intentionally produce runtime errors
    -- They represent bug conditions that are not supposed to be logged
    local loggable_tests = {}
    for _, test in ipairs(tests) do
        local expected_error_pattern = test[3]
        if not expected_error_pattern then
            loggable_tests[#loggable_tests + 1] = test
        end
    end

    -- note: function may run in a separate process
    local failures = parallel.run(loggable_tests, jobs, function(test)
        local ctx = {
            ram_image = test[1],
            test_name = test[1]:gsub(".bin$", ""),
            expected_cycles = test[2],
            failed = true,
            step_count = 0,
            accesses_count = 0,
        }
        local machine <close> = build_machine(ctx.ram_image)
        ctx.initial_root_hash = machine:get_root_hash()
        run_machine_writing_json_logs(machine, ctx)
        ctx.final_root_hash = machine:get_root_hash()
        check_test_result(machine, ctx)
        create_catalog_json_log_entry(ctx)
    end)

    -- create additional logs not in the `tests` list
    local contexts = {}
    if create_uarch_reset_log then
        local ctx = create_json_reset_log()
        contexts[#contexts + 1] = ctx
    end
    if create_send_cmio_response_log then
        local ctx = create_json_send_cmio_response_log()
        contexts[#contexts + 1] = ctx
    end

    -- build catalog

    -- gather catalog entries from files
    local out <close> = create_json_log_file("catalog")
    out:write("[\n")
    for _, test in ipairs(loggable_tests) do
        local test_name = test[1]:gsub(".bin$", "")
        local filename = catalog_entry_file_name(test_name)
        local contents = read_all(filename)
        out:write(contents)
        out:write(",\n")
        os.remove(filename)
    end

    -- gather remaining entries
    for i, ctx in ipairs(contexts) do
        local logFilename = make_json_log_file_name(ctx.test_name, "-steps")
        write_catalog_json_log_entry(out, logFilename, ctx)
        if i == #contexts then
            out:write("\n")
        else
            out:write(",\n")
        end
    end

    out:write("]\n")
    out:close()

    -- print summary
    if failures ~= nil then
        if failures > 0 then
            stderr("\nFAILED %d of %d tests\n\n", failures, #loggable_tests)
            os.exit(1)
        else
            stderr("\nPASSED all %d tests\n\n", #loggable_tests)
            os.exit(0)
        end
    end
end

local selected_tests = {}
for _, test in ipairs(riscv_tests) do
    if select_test(test[1], test_pattern) then
        selected_tests[#selected_tests + 1] = test
    end
end

if #selected_tests < 1 then
    error("no test selected")
elseif command == "run" then
    run(selected_tests)
elseif command == "list" then
    list(selected_tests)
elseif command == "json-step-logs" then
    json_step_logs(selected_tests)
else
    error("command not found")
end
