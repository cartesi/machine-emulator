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
local tests_util = require("cartesi.tests.util")
local parallel = require("cartesi.parallel")
local manifest_mod = require("cartesi.tests.step_log_manifest")

-- Tests Cases
-- format {"ram_image_file", number_of_uarch_cycles, expected_error_pattern}
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
    { "rv64ui-uarch-ecall-write-tlb.bin", 46 },
    { "rv64ui-uarch-ecall-unsupported.bin", 1, "unsupported ecall function" },
    { "rv64ui-uarch-ecall-removed-mark-page-dirty.bin", 1, "unsupported ecall function" },
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
  --output-dir=<dir>
    destination directory for the recorded fixtures
    (required for the record_* commands; each command writes one homogeneous
    fixture set directly into <dir>)
  --per-cycle-logs
    record_uarch_tests only: write one step log per uarch cycle into
    <output-dir>/<test-name>/NNNNN.log instead of the per-program batched log.
    Each per-test directory gets its own _manifest.csv with cycle rows.
and command can be:
  run
    run test and report errors

  verify
    record each test as a multi-cycle uarch step log and verify it round-trips
    through verify_step_uarch (C++ record/replay coverage; no fixtures kept)

  list
    list tests selected by the test <pattern>

  record_uarch_tests
    record one step log per uarch test into <output-dir>. Default granularity
    is one log per whole test (batched); pass --per-cycle-logs to emit one log
    per cycle instead. Writes <output-dir>/_manifest.csv with program rows
    (batched mode) or per-test subdirectories with cycle manifests (per-cycle).

  (uarch reset and send_cmio_response fixtures are machine-level dispute operations,
   not uarch instruction steps; see tests/lua/record-send-cmio-response.lua and record-reset-uarch.lua)
]=],
        arg[0]
    ))
    os.exit()
end

local test_path = tests_util.tests_uarch_path
local test_pattern = ".*"
local jobs = 1
local output_dir
local per_cycle_logs = false

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
            jobs = assert(tonumber(o))
            assert(jobs and jobs >= 1, "invalid number of jobs")
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
        "^%-%-per%-cycle%-logs$",
        function(all)
            if not all then
                return false
            end
            per_cycle_logs = true
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
    local data_filename
    if test_name then
        data_filename = test_path .. "/" .. test_name
    end
    local config = {
        ram = {
            length = 0x20000,
        },
        uarch = {
            ram = {
                backing_store = {
                    data_filename = data_filename,
                },
            },
        },
    }
    local runtime = {}
    return assert(cartesi.machine(config, runtime))
end

local TEST_STATUS_X = 1 -- When test finishes executing,the value of this register contains the test result code
local FAILED_TEST_CASE_X = 3 -- If test fails, the value of this register contains the failed test case
local TEST_SUCCEEDED = 0xbe1e7aaa -- Value indicating that test has passed
local TEST_FAILED = 0xdeadbeef -- Value indicating that test has failed

local function check_test_result(machine, ctx)
    local actual_cycle = machine:read_reg("uarch_cycle")
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

local function step_log_file_name(test_name)
    return test_name .. ".log"
end

-- Manifest schema + parallel-fragment helpers live in cartesi.tests.step_log_manifest
-- (shared with the machine-level generator). The cmio `data` column stays ASCII;
-- see that module for the CSV-safety contract.

-- Records a step log for one uarch test. Mutates ctx with the captured
-- root hashes; self-checks the recorded log via verify_step_uarch.
local function record_test_step_log(machine, ctx)
    ctx.log_file = step_log_file_name(ctx.test_name)
    ctx.kind = "program"
    ctx.name = ctx.log_file
    ctx.hash_function = "keccak256"
    local log_path = output_dir .. "/" .. ctx.log_file
    os.remove(log_path)
    ctx.initial_root_hash = machine:get_root_hash()
    -- 2x expected cycles so an overrun bug shows up in actual_cycle rather than
    -- being clipped silently at the expected boundary.
    ctx.requested_cycle_count = 2 * ctx.expected_cycles
    machine:log_step_uarch(ctx.requested_cycle_count, log_path)
    ctx.final_root_hash = machine:get_root_hash()
    ctx.uarch_run_success = true
    assert(
        cartesi.machine:verify_step_uarch(ctx.initial_root_hash, log_path, ctx.requested_cycle_count)
            == ctx.final_root_hash
    )
end

-- Records one step log per uarch cycle in <output_dir>/<test_name>/.
-- Runs cycle by cycle until the machine halts or uarch_cycle overflows.
-- Each log captures a single cycle's transition, matching the production dispute
-- path (one uarch_step per transition).
local function record_per_cycle_step_logs(ram_image, ctx)
    local per_cycle_dir = ctx.test_name
    local dir_abs = output_dir .. "/" .. per_cycle_dir
    tests_util.prepare_empty_output_dir(dir_abs)
    local manifest <close> = assert(io.open(dir_abs .. "/" .. manifest_mod.MANIFEST_NAME, "w"))
    manifest:write(manifest_mod.HEADER)
    local machine <close> = build_machine(ram_image)
    local cycle = 0
    local before_hash = machine:get_root_hash()
    while true do
        local cycle_name = string.format("%05d.log", cycle)
        local cycle_path = dir_abs .. "/" .. cycle_name
        local status = machine:log_step_uarch(1, cycle_path)
        if status == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE then
            local after_hash = machine:get_root_hash()
            manifest_mod.write_row(manifest, {
                kind = "cycle",
                name = cycle_name,
                hash_function = "keccak256",
                requested_cycle_count = 1,
                initial_root_hash = before_hash,
                final_root_hash = after_hash,
            })
            before_hash = after_hash
            cycle = cycle + 1
        else
            -- The machine was already halted (or cycle overflowed): no transition happened.
            -- Discard the no-op log so per-cycle replay only sees genuine cycles.
            os.remove(cycle_path)
            break
        end
    end
    -- Confirm the test passed, anchoring the fixture's validity at generation (the same
    -- check the batched recorder runs); consumers then only reproduce the recorded roots.
    ctx.uarch_run_success = true
    check_test_result(machine, ctx)
    ctx.per_cycle_dir = per_cycle_dir
    ctx.actual_cycle_count = cycle
end

-- uarch reset and send_cmio_response are machine-level dispute operations, not uarch
-- instruction steps; their fixtures come from tests/lua/record-send-cmio-response.lua
-- and record-reset-uarch.lua.

-- Record one binary step log per uarch test into <output_dir>. Granularity
-- chosen by --per-cycle-logs: default writes one log per whole test (batched);
-- with the flag, writes one log per cycle into <output_dir>/<test_name>/.
-- Tests with an expected_error_pattern (runtime-error tests) are skipped.
local function record_uarch_tests(tests)
    assert(output_dir, "--output-dir is required for record_uarch_tests")
    local loggable_tests = {}
    for _, test in ipairs(tests) do
        if not test[3] then
            loggable_tests[#loggable_tests + 1] = test
        end
    end

    if per_cycle_logs then
        -- Per-cycle mode: each test produces <output_dir>/<test_name>/<NNNNN>.log
        -- plus its own _manifest.csv. No top-level manifest; consumers discover the
        -- per-test dirs directly from the directory listing (Solidity uses vm.readDir).
        -- Require an empty root so no stale program dir survives into that discovery.
        tests_util.prepare_empty_output_dir(output_dir)
        local failures = parallel.run(loggable_tests, jobs, function(test)
            local ctx = {
                ram_image = test[1],
                test_name = test[1]:gsub("%.bin$", ""),
                expected_cycles = test[2],
            }
            record_per_cycle_step_logs(ctx.ram_image, ctx)
        end)
        if failures ~= nil and failures > 0 then
            stderr("\nFAILED %d of %d tests\n\n", failures, #loggable_tests)
            os.exit(1)
        end
        stderr("\nPASSED all %d tests (per-cycle)\n\n", #loggable_tests)
        os.exit(0)
    end

    -- Batched mode: each test produces <output_dir>/<test_name>.log; manifest
    -- rows accumulate from worker fragments, then merge into <output_dir>/_manifest.csv.
    tests_util.prepare_empty_output_dir(output_dir)
    local failures = parallel.run(loggable_tests, jobs, function(test)
        local ctx = {
            ram_image = test[1],
            test_name = test[1]:gsub("%.bin$", ""),
            expected_cycles = test[2],
            uarch_run_success = false,
        }
        local machine <close> = build_machine(ctx.ram_image)
        record_test_step_log(machine, ctx)
        check_test_result(machine, ctx)
        manifest_mod.write_fragment(output_dir, ctx.test_name, ctx)
    end)
    if failures ~= nil and failures > 0 then
        stderr("\nFAILED %d of %d tests\n\n", failures, #loggable_tests)
        os.exit(1)
    end

    local test_names = {}
    for _, test in ipairs(loggable_tests) do
        test_names[#test_names + 1] = test[1]:gsub("%.bin$", "")
    end
    manifest_mod.concat_fragments(output_dir, test_names)

    stderr("\nPASSED all %d tests\n\n", #loggable_tests)
    os.exit(0)
end

local function select_test(test_name, patt)
    local i, j = test_name:find(patt)
    if i == 1 and j == #test_name then
        return true
    end
    i, j = test_name:find(patt, 1, true)
    return i == 1 and j == #test_name
end

-- Records each test as a multi-cycle uarch step log and verifies it round-trips through
-- verify_step_uarch: C++ record/replay coverage of the step-proof path over the rv64ui-uarch
-- corpus. Logs go to a private temp dir and are discarded (no fixtures persist); runtime-error
-- tests have no valid log to replay and are skipped, matching record_uarch_tests.
local function verify(tests)
    local loggable_tests = {}
    for _, test in ipairs(tests) do
        if not test[3] then
            loggable_tests[#loggable_tests + 1] = test
        end
    end
    -- os.tmpname reserves a unique name (and may create an empty file); turn it into our temp dir.
    output_dir = os.tmpname()
    os.remove(output_dir)
    tests_util.prepare_empty_output_dir(output_dir)
    local failures = parallel.run(loggable_tests, jobs, function(test)
        local ctx = {
            ram_image = test[1],
            test_name = test[1]:gsub("%.bin$", ""),
            expected_cycles = test[2],
            uarch_run_success = false,
        }
        local machine <close> = build_machine(ctx.ram_image)
        record_test_step_log(machine, ctx) -- records the log and self-checks it via verify_step_uarch
        check_test_result(machine, ctx)
        os.remove(output_dir .. "/" .. ctx.log_file)
    end)
    -- Each worker removed its own log, so the temp dir is now empty: os.remove drops it (a plain
    -- rmdir, no recursion). A failed worker may leave its log behind; leaking the temp dir is
    -- acceptable -- recorders never recursively delete.
    os.remove(output_dir)
    if failures ~= nil then
        if failures > 0 then
            stderr(string.format("\nFAILED %d of %d tests\n\n", failures, #loggable_tests))
            os.exit(1)
        end
        stderr(string.format("\nPASSED all %d tests (record/replay)\n\n", #loggable_tests))
        os.exit(0)
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
elseif command == "verify" then
    verify(selected_tests)
elseif command == "list" then
    list(selected_tests)
elseif command == "record_uarch_tests" then
    record_uarch_tests(selected_tests)
else
    error("command not found")
end
