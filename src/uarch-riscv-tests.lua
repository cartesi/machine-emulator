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

local cartesi = require"cartesi"
local util = require"cartesi.util"

-- Tests Cases
-- format {"ram_image_file", number_of_uarch_cycles}
local tests = {
    {"rv64ui-uarch-simple.bin", 12},
    {"rv64ui-uarch-add.bin", 441},
    {"rv64ui-uarch-addi.bin", 216},
    {"rv64ui-uarch-addiw.bin", 213},
    {"rv64ui-uarch-addw.bin", 436},
    {"rv64ui-uarch-and.bin", 516},
    {"rv64ui-uarch-andi.bin", 187},
    {"rv64ui-uarch-auipc.bin", 30},
    {"rv64ui-uarch-beq.bin", 262},
    {"rv64ui-uarch-bge.bin", 280},
    {"rv64ui-uarch-bgeu.bin", 370},
    {"rv64ui-uarch-blt.bin", 262},
    {"rv64ui-uarch-bltu.bin", 348},
    {"rv64ui-uarch-bne.bin", 262},
    {"rv64ui-uarch-jal.bin", 26},
    {"rv64ui-uarch-jalr.bin", 86},
    {"rv64ui-uarch-lb.bin", 224},
    {"rv64ui-uarch-lbu.bin", 224},
    {"rv64ui-uarch-lh.bin", 240},
    {"rv64ui-uarch-lhu.bin", 249},
    {"rv64ui-uarch-lw.bin", 254},
    {"rv64ui-uarch-lwu.bin", 288},
    {"rv64ui-uarch-ld.bin", 406},
    {"rv64ui-uarch-lui.bin", 36},
    {"rv64ui-uarch-or.bin", 549},
    {"rv64ui-uarch-ori.bin", 180},
    {"rv64ui-uarch-sb.bin", 425},
    {"rv64ui-uarch-sh.bin", 478},
    {"rv64ui-uarch-sw.bin", 485},
    {"rv64ui-uarch-sd.bin", 597},
    {"rv64ui-uarch-sll.bin", 511},
    {"rv64ui-uarch-slli.bin", 241},
    {"rv64ui-uarch-slliw.bin", 248},
    {"rv64ui-uarch-sllw.bin", 511},
    {"rv64ui-uarch-slt.bin", 430},
    {"rv64ui-uarch-slti.bin", 208},
    {"rv64ui-uarch-sltiu.bin", 208},
    {"rv64ui-uarch-sltu.bin", 447},
    {"rv64ui-uarch-sra.bin", 483},
    {"rv64ui-uarch-srai.bin", 229},
    {"rv64ui-uarch-sraiw.bin", 275},
    {"rv64ui-uarch-sraw.bin", 523},
    {"rv64ui-uarch-srl.bin", 525},
    {"rv64ui-uarch-srli.bin", 250},
    {"rv64ui-uarch-srliw.bin", 257},
    {"rv64ui-uarch-srlw.bin", 517},
    {"rv64ui-uarch-sub.bin", 432},
    {"rv64ui-uarch-subw.bin", 428},
    {"rv64ui-uarch-xor.bin", 544},
    {"rv64ui-uarch-xori.bin", 178},
    {"rv64ui-uarch-fence.bin", 13},
}


-- Print help and exit
local function help()
    io.stderr:write(string.format([=[
Usage:
  %s [options] <command>
where options are:
  --test-path=<dir>
    path to test binaries
    (default: "./")
  --test=<pattern>
    select tests to run based on a Lua string <pattern>
    (default: ".*", i.e., all tests)
  --output=<filename>
    write the output of hash and step commands to the file at
    <filename>. If the argument is not present the output is written
    to stdout.
    (default: none)
  --json-test-list
    write the output of the list command as json
and command can be:
  run
    run test and report errors
  
  list
    list tests selected by the test <pattern>
]=], arg[0]))
    os.exit()
end

local test_path = "./"
local test_pattern = ".*"
local output = nil
local json_list = false
local cleanup = {}

local options = {
    { "^%-%-h$", function(all)
        if not all then return false end
        help()
    end },
    { "^%-%-help$", function(all)
        if not all then return false end
        help()
    end },     
    { "^%-%-output%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        output = o
        return true
    end },
    { "^%-%-json%-test%-list$", function(all)
        if not all then return false end
        json_list = true
        return true
    end },
    { "^%-%-test%-path%=(.*)$", function(o)
        if not o or #o < 1 then return false end
        test_path = o
        return true
    end },
    { "^%-%-test%=(.*)$", function(o, a)
        if not o or #o < 1 then return false end
        test_pattern = o
        return true
    end },
    { ".*", function(all)
        error("unrecognized option " .. all)
    end }
}

local values = {}

-- Process command line options
for i, argument in ipairs({...}) do
    if argument:sub(1,1) == "-" then
        for j, option in ipairs(options) do
            if option[2](argument:match(option[1])) then
                break
            end
        end
    else
        values[#values+1] = argument
    end
end

local command = assert(values[1], "missing command")
assert(test_path, "missing test path")

local function nothing()
end

local function build_machine(test_name)
    local config = {
        rom = {
            image_filename = test_path .. "/bootstrap.bin"
        },
        ram = {
            length = 0x20000
        },
        uarch = {
            ram = {
                image_filename = test_path .. "/" .. test_name,
                length = 0x20000
            }
        }
    }
    local runtime = { }
    return assert(cartesi.machine(config, runtime))
end


local function add_error(errors, ram_image, msg, ...)
    local e = string.format(msg, ...)
    if not errors[ram_image] then errors[ram_image] = {} end
    local ram_image_errors = errors[ram_image]
    ram_image_errors[#ram_image_errors + 1] = e
end

local TEST_STATUS_X      = 1           -- When test finishes executing, the value of this register contains the test result code
local FAILED_TEST_CASE_X = 3           -- If test fails, the value of this register contains the failed test case
local TEST_SUCEEDED      = 0xbe1e7aaa  -- Value indicating that test has passed
local TEST_FAILED        = 0xdeadbeef  -- Value indicating that test has failed 

local function check_test_result(machine, ctx, errors)
    local test_status = machine:read_uarch_x(TEST_STATUS_X)
    if test_status == TEST_FAILED then
        local failed_test_case = machine:read_uarch_x(FAILED_TEST_CASE_X)
        add_error(errors, ctx.ram_image, "failed test case %d", failed_test_case)
        ctx.failed = true
    end
    if test_status ~= TEST_SUCEEDED then
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
            cycles = 0
        }
        local machine = build_machine(ctx.ram_image)
        io.write(ctx.ram_image, ": ")
        machine:run_uarch(2 * ctx.expected_cycles)
        check_test_result(machine, ctx, errors)
        if ctx.failed then
            print("failed")
            error_count = error_count + 1
        else
            print("passed")
        end
        machine:destroy()
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
    if json_list then
        local out = io.stdout
        local indentout = util.indentout
        out:write("{\n  \"tests\": [\n")
        for i, test in ipairs(tests) do
            if i ~= 1 then out:write(",\n") end
            indentout(out, 2, "{\n")
            indentout(out, 3, "\"file\": \"" .. test[1] .. "\",\n")
            indentout(out, 3, "\"cycle\": " .. test[2] .. "\n")
            indentout(out, 2, "}")
        end
        out:write("\n  ]\n}\n")
    else
        for _, test in ipairs(tests) do
            print(test[1])
        end
    end
end

local function select(test_name, test_pattern)
    local i, j = test_name:find(test_pattern)
    if i == 1 and j == #test_name then return true end
    i, j = test_name:find(test_pattern, 1, true)
    return i == 1 and j == #test_name
end

local selected_tests = {}
for _, test in ipairs(tests) do
    if select(test[1], test_pattern) then
        selected_tests[#selected_tests+1] = test
    end
end

if #selected_tests < 1 then error("no test selected")
elseif command == "run" then run(selected_tests)
elseif command == "list" then list(selected_tests)
else error("command not found") end