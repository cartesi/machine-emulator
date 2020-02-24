#!/usr/bin/env luapp5.3

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

local tests = {
  {"rv64mi-p-access.bin", 110},
  {"rv64mi-p-breakpoint.bin", 61},
  {"rv64mi-p-csr.bin", 173},
  {"rv64mi-p-illegal.bin", 410},
  {"rv64mi-p-ma_addr.bin", 682},
  {"rv64mi-p-ma_fetch.bin", 196},
  {"rv64mi-p-mcsr.bin", 69},
  {"rv64mi-p-sbreak.bin", 74},
  {"rv64mi-p-scall.bin", 63},
  {"rv64si-p-csr.bin", 126},
  {"rv64si-p-dirty.bin", 143},
  {"rv64si-p-ma_fetch.bin", 154},
  {"rv64si-p-sbreak.bin", 69},
  {"rv64si-p-scall.bin", 76},
  {"rv64si-p-wfi.bin", 57},
  {"rv64ua-p-amoadd_d.bin", 74},
  {"rv64ua-p-amoadd_w.bin", 71},
  {"rv64ua-p-amoand_d.bin", 71},
  {"rv64ua-p-amoand_w.bin", 70},
  {"rv64ua-p-amomax_d.bin", 70},
  {"rv64ua-p-amomax_w.bin", 70},
  {"rv64ua-p-amomaxu_d.bin", 70},
  {"rv64ua-p-amomaxu_w.bin", 70},
  {"rv64ua-p-amomin_d.bin", 70},
  {"rv64ua-p-amomin_w.bin", 70},
  {"rv64ua-p-amominu_d.bin", 70},
  {"rv64ua-p-amominu_w.bin", 70},
  {"rv64ua-p-amoor_d.bin", 69},
  {"rv64ua-p-amoor_w.bin", 69},
  {"rv64ua-p-amoswap_d.bin", 71},
  {"rv64ua-p-amoswap_w.bin", 70},
  {"rv64ua-p-amoxor_d.bin", 72},
  {"rv64ua-p-amoxor_w.bin", 74},
  {"rv64ua-p-lrsc.bin", 6246},
  {"rv64ua-v-amoadd_d.bin", 10731},
  {"rv64ua-v-amoadd_w.bin", 10728},
  {"rv64ua-v-amoand_d.bin", 10740},
  {"rv64ua-v-amoand_w.bin", 10739},
  {"rv64ua-v-amomax_d.bin", 10721},
  {"rv64ua-v-amomax_w.bin", 10721},
  {"rv64ua-v-amomaxu_d.bin", 10721},
  {"rv64ua-v-amomaxu_w.bin", 10721},
  {"rv64ua-v-amomin_d.bin", 10721},
  {"rv64ua-v-amomin_w.bin", 10721},
  {"rv64ua-v-amominu_d.bin", 11211},
  {"rv64ua-v-amominu_w.bin", 11211},
  {"rv64ua-v-amoor_d.bin", 10720},
  {"rv64ua-v-amoor_w.bin", 10720},
  {"rv64ua-v-amoswap_d.bin", 10740},
  {"rv64ua-v-amoswap_w.bin", 10739},
  {"rv64ua-v-amoxor_d.bin", 10723},
  {"rv64ua-v-amoxor_w.bin", 10725},
  {"rv64ua-v-lrsc.bin", 16895},
  {"rv64ui-p-add.bin", 475},
  {"rv64ui-p-addi.bin", 250},
  {"rv64ui-p-addiw.bin", 247},
  {"rv64ui-p-addw.bin", 470},
  {"rv64ui-p-and.bin", 550},
  {"rv64ui-p-andi.bin", 221},
  {"rv64ui-p-auipc.bin", 64},
  {"rv64ui-p-beq.bin", 296},
  {"rv64ui-p-bge.bin", 314},
  {"rv64ui-p-bgeu.bin", 404},
  {"rv64ui-p-blt.bin", 296},
  {"rv64ui-p-bltu.bin", 382},
  {"rv64ui-p-bne.bin", 296},
  {"rv64ui-p-fence_i.bin", 299},
  {"rv64ui-p-jal.bin", 60},
  {"rv64ui-p-jalr.bin", 113},
  {"rv64ui-p-lb.bin", 250},
  {"rv64ui-p-lbu.bin", 250},
  {"rv64ui-p-ld.bin", 384},
  {"rv64ui-p-lh.bin", 262},
  {"rv64ui-p-lhu.bin", 269},
  {"rv64ui-p-lui.bin", 70},
  {"rv64ui-p-lw.bin", 272},
  {"rv64ui-p-lwu.bin", 298},
  {"rv64ui-p-or.bin", 583},
  {"rv64ui-p-ori.bin", 214},
  {"rv64ui-p-sb.bin", 435},
  {"rv64ui-p-sh.bin", 488},
  {"rv64ui-p-sw.bin", 495},
  {"rv64ui-p-sd.bin", 607},
  {"rv64ui-p-simple.bin", 46},
  {"rv64ui-p-sll.bin", 545},
  {"rv64ui-p-slli.bin", 275},
  {"rv64ui-p-slliw.bin", 246},
  {"rv64ui-p-sllw.bin", 505},
  {"rv64ui-p-slt.bin", 464},
  {"rv64ui-p-slti.bin", 242},
  {"rv64ui-p-sltiu.bin", 242},
  {"rv64ui-p-sltu.bin", 481},
  {"rv64ui-p-sra.bin", 517},
  {"rv64ui-p-srai.bin", 263},
  {"rv64ui-p-sraiw.bin", 273},
  {"rv64ui-p-sraw.bin", 517},
  {"rv64ui-p-srl.bin", 559},
  {"rv64ui-p-srli.bin", 284},
  {"rv64ui-p-srliw.bin", 255},
  {"rv64ui-p-srlw.bin", 511},
  {"rv64ui-p-sub.bin", 466},
  {"rv64ui-p-subw.bin", 462},
  {"rv64ui-p-xor.bin", 578},
  {"rv64ui-p-xori.bin", 212},
  {"rv64ui-v-add.bin", 6915},
  {"rv64ui-v-addi.bin", 6690},
  {"rv64ui-v-addiw.bin", 6687},
  {"rv64ui-v-addw.bin", 6910},
  {"rv64ui-v-and.bin", 11689},
  {"rv64ui-v-andi.bin", 6661},
  {"rv64ui-v-auipc.bin", 6503},
  {"rv64ui-v-beq.bin", 6736},
  {"rv64ui-v-bge.bin", 6754},
  {"rv64ui-v-bgeu.bin", 6844},
  {"rv64ui-v-blt.bin", 6736},
  {"rv64ui-v-bltu.bin", 6822},
  {"rv64ui-v-bne.bin", 6736},
  {"rv64ui-v-fence_i.bin", 13155},
  {"rv64ui-v-jal.bin", 6500},
  {"rv64ui-v-jalr.bin", 6553},
  {"rv64ui-v-lb.bin", 11389},
  {"rv64ui-v-lbu.bin", 11389},
  {"rv64ui-v-ld.bin", 11523},
  {"rv64ui-v-lh.bin", 11401},
  {"rv64ui-v-lhu.bin", 11408},
  {"rv64ui-v-lui.bin", 6510},
  {"rv64ui-v-lw.bin", 11411},
  {"rv64ui-v-lwu.bin", 11437},
  {"rv64ui-v-or.bin", 11722},
  {"rv64ui-v-ori.bin", 6654},
  {"rv64ui-v-sb.bin", 11086},
  {"rv64ui-v-sd.bin", 15957},
  {"rv64ui-v-sh.bin", 11139},
  {"rv64ui-v-simple.bin", 6486},
  {"rv64ui-v-sll.bin", 11684},
  {"rv64ui-v-slli.bin", 6715},
  {"rv64ui-v-slliw.bin", 6686},
  {"rv64ui-v-sllw.bin", 11644},
  {"rv64ui-v-slt.bin", 6904},
  {"rv64ui-v-slti.bin", 6682},
  {"rv64ui-v-sltiu.bin", 6682},
  {"rv64ui-v-sltu.bin", 11620},
  {"rv64ui-v-sra.bin", 11656},
  {"rv64ui-v-srai.bin", 6703},
  {"rv64ui-v-sraiw.bin", 6713},
  {"rv64ui-v-sraw.bin", 11656},
  {"rv64ui-v-srl.bin", 11698},
  {"rv64ui-v-srli.bin", 6724},
  {"rv64ui-v-srliw.bin", 6695},
  {"rv64ui-v-srlw.bin", 11650},
  {"rv64ui-v-sub.bin", 6906},
  {"rv64ui-v-subw.bin", 6902},
  {"rv64ui-v-sw.bin", 11146},
  {"rv64ui-v-xor.bin", 11717},
  {"rv64ui-v-xori.bin", 6652},
  {"rv64um-p-div.bin", 106},
  {"rv64um-p-divu.bin", 112},
  {"rv64um-p-divuw.bin", 104},
  {"rv64um-p-divw.bin", 101},
  {"rv64um-p-mul.bin", 465},
  {"rv64um-p-mulh.bin", 473},
  {"rv64um-p-mulhsu.bin", 473},
  {"rv64um-p-mulhu.bin", 505},
  {"rv64um-p-mulw.bin", 404},
  {"rv64um-p-rem.bin", 105},
  {"rv64um-p-remu.bin", 106},
  {"rv64um-p-remuw.bin", 101},
  {"rv64um-p-remw.bin", 107},
  {"rv64um-v-div.bin", 6546},
  {"rv64um-v-divu.bin", 6552},
  {"rv64um-v-divuw.bin", 6544},
  {"rv64um-v-divw.bin", 6541},
  {"rv64um-v-mul.bin", 6905},
  {"rv64um-v-mulh.bin", 6913},
  {"rv64um-v-mulhsu.bin", 6913},
  {"rv64um-v-mulhu.bin", 6945},
  {"rv64um-v-mulw.bin", 6844},
  {"rv64um-v-rem.bin", 6545},
  {"rv64um-v-remu.bin", 6546},
  {"rv64um-v-remuw.bin", 6541},
  {"rv64um-v-remw.bin", 6547},
-- regression tests
  {"sd_pma_overflow.bin", 16},
  {"xpie_exceptions.bin", 51},
}

-- Print help and exit
local function help()
    io.stderr:write(string.format([=[
Usage:

  %s [options] <command>

where options are:

  --test-path=<dir>            path to test binaries
                               (default: "./")

  --test=<pattern>             select tests to run based on a Lua string <pattern>
                               (default: ".*", i.e., all tests)

  --skip=<number>              stop execution every <number> of cycles and perform action

and command can be:

  run                          run test and report if payload and cycles match expected

  hash                         output root hash at every <number> of cycles

  step                         output json log of step at every <number> of cycles

  list                         list tests selected by the test <pattern>

  machine                      prints a command for running the test machine

]=], arg[0]))
    os.exit()
end

local test_path = "./"
local test_pattern = ".*"
local skip = nil

-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
local options = {
    { "^%-%-help$", function(all)
        if all then
            help()
            return true
        else
            return false
        end
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
    { "^(%-%-skip%=(%d*)(.*))$", function(all, n, e)
        if not n then return false end
        assert(e == "", "invalid option " .. all)
        n = assert(tonumber(n), "invalid option " .. all)
        assert(n >= 1, "invalid option " .. all)
        skip = n
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

local function run_machine(machine, expected_cycles, callback)
    callback = callback or nothing
    callback()
    if skip then
        for cycle = math.min(skip, 2*expected_cycles), 2*expected_cycles, skip do
            machine:run(cycle)
            callback()
            if machine:read_iflags_H() then break end
        end
    else
        machine:run(2*expected_cycles)
        callback()
    end
    local payload = (machine:read_tohost() & (~1 >> 16)) >> 1
    local final_cycle = machine:read_mcycle()
    return final_cycle, payload
end

local function build_machine(test_name)
    return assert(cartesi.machine{
        machine = cartesi.get_name(),
        rom = {
            backing = test_path .. "/bootstrap.bin"
        },
        ram = {
            length = 32 << 20,
            backing = test_path .. "/" .. test_name
        }
    })
end

local function print_machine(test_name, expected_cycles)
    print(
        string.format(
            "./cartesi-machine.lua --no-root-backing --batch --memory-size=32 --rom-image='%s' --ram-image='%s' --max-mcycle=%d",
            test_path .. "/bootstrap.bin",
            test_path .. "/" .. test_name,
            2*expected_cycles
        )
    )
end

local function run(tests)
    local errors = {}
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        io.write(ram_image, " ")
        local machine = build_machine(ram_image)
        local cycles, payload = run_machine(machine, expected_cycles)
        if payload ~= 0 then
            local e = string.format("%s returned non-zero payload %d", ram_image, payload)
            errors[#errors+1] = e
            print(e)
        elseif cycles ~= expected_cycles then
            local e = string.format("%s terminated with mcycle = %d, expected %d",
                ram_image, cycles, expected_cycles)
            errors[#errors+1] = e
            print(e)
        else
            print(" passed")
        end
        machine:destroy()
    end
    if #errors > 0 then
        io.write(string.format("FAILED %d tests\n", #errors))
        for i, e in ipairs(errors) do
            io.write("\t", e, "\n")
        end
        os.exit(1, true)
    else
        print("passed all tests")
        os.exit(0, true)
    end
end

local function hexhash(h)
    return (string.gsub(h, ".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

local function hash(tests)
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local machine = build_machine(ram_image)
        local cycles, payload = run_machine(machine, expected_cycles, function()
            machine:update_merkle_tree()
            print(machine:read_mcycle(), hexhash(machine:get_root_hash()))
        end)
        if payload ~= 0 or cycles ~= expected_cycles then
            os.exit(1, true)
        end
        machine:destroy()
    end
end

local function print_machines(tests)
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        print_machine(ram_image, expected_cycles)
    end
end

local function intstring(v)
    local a = ""
    for i = 0, 7 do
        a = a .. string.format("%02x", (v >> i*8) & 0xff)
    end
    return a
end

local function print_json_log_sibling_hashes(sibling_hashes, log2_size, out, indent)
    out:write('[\n')
    for i, h in ipairs(sibling_hashes) do
        out:write(indent,'"', hexhash(h), '"')
        if sibling_hashes[i+1] then out:write(',\n') end
    end
    out:write(' ]')
end

local function print_json_log_proof(proof, out, indent)
    out:write('{\n')
    out:write(indent, '"address": ', proof.address, ',\n')
    out:write(indent, '"log2_size": ', proof.log2_size, ',\n')
    out:write(indent, '"target_hash": "', hexhash(proof.target_hash), '",\n')
    out:write(indent, '"sibling_hashes": ')
    print_json_log_sibling_hashes(proof.sibling_hashes, proof.log2_size, out,
        indent .. "  ")
    out:write(",\n", indent, '"root_hash": "', hexhash(proof.root_hash), '" }')
end

local function print_json_log_notes(notes, out, indent)
    local indent2 = indent .. "  "
    local n = #notes
    out:write('[\n')
    for i, note in ipairs(notes) do
        out:write(indent2, '"', note, '"')
        if i < n then out:write(',\n') end
    end
    out:write(indent, '],\n')
end

local function print_json_log_brackets(brackets, out, indent)
    local n = #brackets
    out:write('[ ')
    for i, bracket in ipairs(brackets) do
        out:write('{\n')
        out:write(indent, '  "type": "', bracket.type, '",\n')
        out:write(indent, '  "where": ', bracket.where, ',\n')
        out:write(indent, '  "text": "', bracket.text, '"')
        out:write(' }\n')
        if i < n then out:write(', ') end
    end
    out:write(' ]')
end

local function print_json_log_access(access, out, indent)
    out:write('{\n')
    out:write(indent, '"type": "', access.type, '",\n')
    out:write(indent, '"read": "', intstring(access.read), '",\n')
    out:write(indent, '"written": "', intstring(access.written or 0), '",\n')
    out:write(indent, '"proof": ')
    print_json_log_proof(access.proof, out, indent .. "  ")
    out:write(' }')
end

local function print_json_log_accesses(accesses, out, indent)
    local indent2 = indent .. "  "
    local n = #accesses
    out:write('[ ')
    for i, access in ipairs(accesses) do
        print_json_log_access(access, out, indent2)
        if i < n then out:write(',\n', indent) end
    end
    out:write(indent, ' ],\n')
end

local function print_json_log(log, init_cycles, final_cycles, out, indent)
    out:write('{\n')
    out:write(indent, '"init_cycles": ', init_cycles, ',\n')
    out:write(indent, '"final_cycles": ', final_cycles, ',\n')
    out:write(indent, '"accesses": ')
    print_json_log_accesses(log.accesses, out, indent)
    out:write(indent, '"notes": ')
    print_json_log_notes(log.notes, out, indent)
    out:write('  "brackets": ')
    print_json_log_brackets(log.brackets, out, indent)
    out:write(' }')
end

local function step(tests)
    io.stdout:write("[ ")
    for i, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local machine = build_machine(ram_image)
        io.stdout:write(" {\n")
        io.stdout:write('  "test": "', ram_image, '",\n')
        io.stdout:write('  "skip": ', skip, ',\n')
        io.stdout:write('  "steps": [ ')
        local cycles, payload = run_machine(machine, expected_cycles, function()
            local init_cycles = machine:read_mcycle()
            local log = machine:step()
            local final_cycles = machine:read_mcycle()
            print_json_log(log, init_cycles, final_cycles, io.stdout, "    ")
            if not machine:read_iflags_H() then io.stdout:write(', ') end
        end)
        io.stdout:write(" ]")
        if tests[i+1] then io.stdout:write(" }, ")
        else io.stdout:write(" } ") end
        if payload ~= 0 or cycles ~= expected_cycles then
            os.exit(1, true)
        end
        machine:destroy()
    end
    io.stdout:write(" ]\n")
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
elseif command == "hash" then hash(selected_tests)
elseif command == "step" then step(selected_tests)
elseif command == "list" then
    for _, test in ipairs(selected_tests) do
        print(test[1])
    end
elseif command == "machine" then print_machines(selected_tests)
else error("command not found") end
