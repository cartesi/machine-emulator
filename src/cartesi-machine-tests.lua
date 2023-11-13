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

-- Tests Cases
-- format {"ram_image_file", number_of_cycles, halt_payload, yield_payloads}
local riscv_tests = {
    { "rv64mi-p-access.bin", 140 },
    { "rv64mi-p-breakpoint.bin", 111 },
    { "rv64mi-p-csr.bin", 293 },
    { "rv64mi-p-illegal.bin", 357 },
    { "rv64mi-p-ld-misaligned.bin", 365 },
    { "rv64mi-p-lh-misaligned.bin", 117 },
    { "rv64mi-p-lw-misaligned.bin", 177 },
    { "rv64mi-p-ma_addr.bin", 738 },
    { "rv64mi-p-ma_fetch.bin", 134 },
    { "rv64mi-p-mcsr.bin", 99 },
    { "rv64mi-p-sbreak.bin", 107 },
    { "rv64mi-p-scall.bin", 91 },
    { "rv64mi-p-sd-misaligned.bin", 385 },
    { "rv64mi-p-sh-misaligned.bin", 125 },
    { "rv64mi-p-sw-misaligned.bin", 181 },
    { "rv64si-p-csr.bin", 192 },
    { "rv64si-p-dirty.bin", 173 },
    { "rv64si-p-icache-alias.bin", 223 },
    { "rv64si-p-ma_fetch.bin", 121 },
    { "rv64si-p-sbreak.bin", 101 },
    { "rv64si-p-scall.bin", 108 },
    { "rv64si-p-wfi.bin", 87 },
    { "rv64ua-p-amoadd_d.bin", 104 },
    { "rv64ua-p-amoadd_w.bin", 101 },
    { "rv64ua-p-amoand_d.bin", 101 },
    { "rv64ua-p-amoand_w.bin", 100 },
    { "rv64ua-p-amomax_d.bin", 100 },
    { "rv64ua-p-amomax_w.bin", 100 },
    { "rv64ua-p-amomaxu_d.bin", 100 },
    { "rv64ua-p-amomaxu_w.bin", 100 },
    { "rv64ua-p-amomin_d.bin", 100 },
    { "rv64ua-p-amomin_w.bin", 100 },
    { "rv64ua-p-amominu_d.bin", 100 },
    { "rv64ua-p-amominu_w.bin", 100 },
    { "rv64ua-p-amoor_d.bin", 99 },
    { "rv64ua-p-amoor_w.bin", 99 },
    { "rv64ua-p-amoswap_d.bin", 101 },
    { "rv64ua-p-amoswap_w.bin", 100 },
    { "rv64ua-p-amoxor_d.bin", 102 },
    { "rv64ua-p-amoxor_w.bin", 104 },
    { "rv64ua-p-lrsc.bin", 6276 },
    { "rv64ua-v-amoadd_d.bin", 10593 },
    { "rv64ua-v-amoadd_w.bin", 10590 },
    { "rv64ua-v-amoand_d.bin", 10602 },
    { "rv64ua-v-amoand_w.bin", 10601 },
    { "rv64ua-v-amomax_d.bin", 10583 },
    { "rv64ua-v-amomax_w.bin", 10583 },
    { "rv64ua-v-amomaxu_d.bin", 10583 },
    { "rv64ua-v-amomaxu_w.bin", 10583 },
    { "rv64ua-v-amomin_d.bin", 10583 },
    { "rv64ua-v-amomin_w.bin", 10583 },
    { "rv64ua-v-amominu_d.bin", 10589 },
    { "rv64ua-v-amominu_w.bin", 10589 },
    { "rv64ua-v-amoor_d.bin", 10582 },
    { "rv64ua-v-amoor_w.bin", 10582 },
    { "rv64ua-v-amoswap_d.bin", 10602 },
    { "rv64ua-v-amoswap_w.bin", 10601 },
    { "rv64ua-v-amoxor_d.bin", 10585 },
    { "rv64ua-v-amoxor_w.bin", 10587 },
    { "rv64ua-v-lrsc.bin", 16759 },
    { "rv64ui-p-add.bin", 505 },
    { "rv64ui-p-addi.bin", 280 },
    { "rv64ui-p-addiw.bin", 277 },
    { "rv64ui-p-addw.bin", 500 },
    { "rv64ui-p-and.bin", 580 },
    { "rv64ui-p-andi.bin", 251 },
    { "rv64ui-p-auipc.bin", 94 },
    { "rv64ui-p-beq.bin", 326 },
    { "rv64ui-p-bge.bin", 344 },
    { "rv64ui-p-bgeu.bin", 434 },
    { "rv64ui-p-blt.bin", 326 },
    { "rv64ui-p-bltu.bin", 412 },
    { "rv64ui-p-bne.bin", 326 },
    { "rv64ui-p-fence_i.bin", 336 },
    { "rv64ui-p-jal.bin", 90 },
    { "rv64ui-p-jalr.bin", 150 },
    { "rv64ui-p-lb.bin", 288 },
    { "rv64ui-p-lbu.bin", 288 },
    { "rv64ui-p-ld.bin", 470 },
    { "rv64ui-p-lh.bin", 304 },
    { "rv64ui-p-lhu.bin", 313 },
    { "rv64ui-p-lui.bin", 100 },
    { "rv64ui-p-lw.bin", 318 },
    { "rv64ui-p-lwu.bin", 352 },
    { "rv64ui-p-or.bin", 613 },
    { "rv64ui-p-ori.bin", 244 },
    { "rv64ui-p-sb.bin", 489 },
    { "rv64ui-p-sh.bin", 542 },
    { "rv64ui-p-sw.bin", 549 },
    { "rv64ui-p-sd.bin", 661 },
    { "rv64ui-p-simple.bin", 76 },
    { "rv64ui-p-sll.bin", 575 },
    { "rv64ui-p-slli.bin", 305 },
    { "rv64ui-p-slliw.bin", 312 },
    { "rv64ui-p-sllw.bin", 575 },
    { "rv64ui-p-slt.bin", 494 },
    { "rv64ui-p-slti.bin", 272 },
    { "rv64ui-p-sltiu.bin", 272 },
    { "rv64ui-p-sltu.bin", 511 },
    { "rv64ui-p-sra.bin", 547 },
    { "rv64ui-p-srai.bin", 293 },
    { "rv64ui-p-sraiw.bin", 339 },
    { "rv64ui-p-sraw.bin", 587 },
    { "rv64ui-p-srl.bin", 589 },
    { "rv64ui-p-srli.bin", 314 },
    { "rv64ui-p-srliw.bin", 321 },
    { "rv64ui-p-srlw.bin", 581 },
    { "rv64ui-p-sub.bin", 496 },
    { "rv64ui-p-subw.bin", 492 },
    { "rv64ui-p-xor.bin", 608 },
    { "rv64ui-p-xori.bin", 242 },
    { "rv64ui-v-add.bin", 6773 },
    { "rv64ui-v-addi.bin", 6548 },
    { "rv64ui-v-addiw.bin", 6545 },
    { "rv64ui-v-addw.bin", 6768 },
    { "rv64ui-v-and.bin", 6848 },
    { "rv64ui-v-andi.bin", 6519 },
    { "rv64ui-v-auipc.bin", 6361 },
    { "rv64ui-v-beq.bin", 6594 },
    { "rv64ui-v-bge.bin", 6612 },
    { "rv64ui-v-bgeu.bin", 6702 },
    { "rv64ui-v-blt.bin", 6594 },
    { "rv64ui-v-bltu.bin", 6680 },
    { "rv64ui-v-bne.bin", 6594 },
    { "rv64ui-v-fence_i.bin", 10850 },
    { "rv64ui-v-jal.bin", 6358 },
    { "rv64ui-v-jalr.bin", 6418 },
    { "rv64ui-v-lb.bin", 11259 },
    { "rv64ui-v-lbu.bin", 11259 },
    { "rv64ui-v-ld.bin", 11441 },
    { "rv64ui-v-lh.bin", 11275 },
    { "rv64ui-v-lhu.bin", 11284 },
    { "rv64ui-v-lui.bin", 6368 },
    { "rv64ui-v-lw.bin", 11289 },
    { "rv64ui-v-lwu.bin", 11323 },
    { "rv64ui-v-or.bin", 6881 },
    { "rv64ui-v-ori.bin", 6512 },
    { "rv64ui-v-sb.bin", 10972 },
    { "rv64ui-v-sd.bin", 15847 },
    { "rv64ui-v-sh.bin", 11025 },
    { "rv64ui-v-simple.bin", 6344 },
    { "rv64ui-v-sll.bin", 6843 },
    { "rv64ui-v-slli.bin", 6573 },
    { "rv64ui-v-slliw.bin", 6580 },
    { "rv64ui-v-sllw.bin", 6843 },
    { "rv64ui-v-slt.bin", 6762 },
    { "rv64ui-v-slti.bin", 6540 },
    { "rv64ui-v-sltiu.bin", 6540 },
    { "rv64ui-v-sltu.bin", 6779 },
    { "rv64ui-v-sra.bin", 6815 },
    { "rv64ui-v-srai.bin", 6561 },
    { "rv64ui-v-sraiw.bin", 6607 },
    { "rv64ui-v-sraw.bin", 11558 },
    { "rv64ui-v-srl.bin", 6857 },
    { "rv64ui-v-srli.bin", 6582 },
    { "rv64ui-v-srliw.bin", 6589 },
    { "rv64ui-v-srlw.bin", 6849 },
    { "rv64ui-v-sub.bin", 6764 },
    { "rv64ui-v-subw.bin", 6760 },
    { "rv64ui-v-sw.bin", 11032 },
    { "rv64ui-v-xor.bin", 6876 },
    { "rv64ui-v-xori.bin", 6510 },
    { "rv64um-p-div.bin", 136 },
    { "rv64um-p-divu.bin", 142 },
    { "rv64um-p-divuw.bin", 134 },
    { "rv64um-p-divw.bin", 131 },
    { "rv64um-p-mul.bin", 495 },
    { "rv64um-p-mulh.bin", 503 },
    { "rv64um-p-mulhsu.bin", 503 },
    { "rv64um-p-mulhu.bin", 535 },
    { "rv64um-p-mulw.bin", 434 },
    { "rv64um-p-rem.bin", 135 },
    { "rv64um-p-remu.bin", 136 },
    { "rv64um-p-remuw.bin", 131 },
    { "rv64um-p-remw.bin", 137 },
    { "rv64um-v-div.bin", 6404 },
    { "rv64um-v-divu.bin", 6410 },
    { "rv64um-v-divuw.bin", 6402 },
    { "rv64um-v-divw.bin", 6399 },
    { "rv64um-v-mul.bin", 6763 },
    { "rv64um-v-mulh.bin", 6771 },
    { "rv64um-v-mulhsu.bin", 6771 },
    { "rv64um-v-mulhu.bin", 6803 },
    { "rv64um-v-mulw.bin", 6702 },
    { "rv64um-v-rem.bin", 6403 },
    { "rv64um-v-remu.bin", 6404 },
    { "rv64um-v-remuw.bin", 6399 },
    { "rv64um-v-remw.bin", 6405 },
    -- C extension tests
    { "rv64uc-p-rvc.bin", 295 },
    { "rv64uc-v-rvc.bin", 15497 },
    -- float tests
    { "rv64uf-p-fadd.bin", 210 },
    { "rv64uf-p-fclass.bin", 147 },
    { "rv64uf-p-fcmp.bin", 260 },
    { "rv64uf-p-fcvt.bin", 152 },
    { "rv64uf-p-fcvt_w.bin", 550 },
    { "rv64uf-p-fdiv.bin", 171 },
    { "rv64uf-p-fmadd.bin", 236 },
    { "rv64uf-p-fmin.bin", 314 },
    { "rv64uf-p-ldst.bin", 106 },
    { "rv64uf-p-move.bin", 255 },
    { "rv64uf-p-recoding.bin", 113 },
    { "rv64uf-v-fadd.bin", 11179 },
    { "rv64uf-v-fclass.bin", 6413 },
    { "rv64uf-v-fcmp.bin", 11229 },
    { "rv64uf-v-fcvt.bin", 11121 },
    { "rv64uf-v-fcvt_w.bin", 16222 },
    { "rv64uf-v-fdiv.bin", 11140 },
    { "rv64uf-v-fmadd.bin", 11205 },
    { "rv64uf-v-fmin.bin", 11283 },
    { "rv64uf-v-ldst.bin", 10621 },
    { "rv64uf-v-move.bin", 6521 },
    { "rv64uf-v-recoding.bin", 11082 },
    { "rv64ud-p-fadd.bin", 210 },
    { "rv64ud-p-fclass.bin", 153 },
    { "rv64ud-p-fcmp.bin", 260 },
    { "rv64ud-p-fcvt.bin", 192 },
    { "rv64ud-p-fcvt_w.bin", 610 },
    { "rv64ud-p-fdiv.bin", 184 },
    { "rv64ud-p-fmadd.bin", 236 },
    { "rv64ud-p-fmin.bin", 314 },
    { "rv64ud-p-ldst.bin", 125 },
    { "rv64ud-p-move.bin", 1030 },
    { "rv64ud-p-recoding.bin", 138 },
    { "rv64ud-p-structural.bin", 203 },
    { "rv64ud-v-fadd.bin", 11179 },
    { "rv64ud-v-fclass.bin", 6419 },
    { "rv64ud-v-fcmp.bin", 11229 },
    { "rv64ud-v-fcvt.bin", 11161 },
    { "rv64ud-v-fcvt_w.bin", 16282 },
    { "rv64ud-v-fdiv.bin", 11153 },
    { "rv64ud-v-fmadd.bin", 11205 },
    { "rv64ud-v-fmin.bin", 11283 },
    { "rv64ud-v-ldst.bin", 10616 },
    { "rv64ud-v-move.bin", 11999 },
    { "rv64ud-v-recoding.bin", 10659 },
    { "rv64ud-v-structural.bin", 6469 },
    { "fclass.bin", 453 },
    { "fcvt.bin", 17610 },
    { "fcmp.bin", 46783 },
    { "funary.bin", 2830 },
    { "fbinary_s.bin", 204280 },
    { "fbinary_d.bin", 204280 },
    { "fternary_s.bin", 216780 },
    { "fternary_d.bin", 216780 },
    -- cartesi tests
    { "ebreak.bin", 17 },
    { "pte_reserved_exception.bin", 30 },
    { "sd_pma_overflow.bin", 12 },
    { "xpie_exceptions.bin", 47 },
    { "dont_write_x0.bin", 64 },
    { "mcycle_write.bin", 14 },
    { "lrsc_semantics.bin", 31 },
    { "csr_counters.bin", 737 },
    { "csr_semantics.bin", 378 },
    { "amo.bin", 162 },
    { "access.bin", 97 },
    { "interrupts.bin", 8209 },
    { "mtime_interrupt.bin", 16404 },
    { "illegal_insn.bin", 972 },
    { "version_check.bin", 26 },
    { "translate_vaddr.bin", 343 },
    { "htif_invalid_ops.bin", 109 },
    { "clint_ops.bin", 133 },
    { "shadow_ops.bin", 114 },
    { "compressed.bin", 410 },
}

local log_proofs = false
local log_annotations = false

-- Microarchitecture configuration
local uarch

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

  --log-proofs
    include proofs in logs

  --log-annotations
    include annotations in logs

  --periodic-action=<number-period>[,<number-start>]
    stop execution every <number> of uarch cycles and perform action. If
    <number-start> is given, the periodic action will start at that
    uarch cycle. Only take effect with hash and step commands.
    (default: none)

  --remote-protocol=<protocol>
    select protocol to use with remote cartesi machine.
    can be "jsonrpc" or "grpc" (default: "grpc").

  --remote-address=<address>
    use a remote cartesi machine listenning to <address> instead of
    running a local cartesi machine.
    (if remote-protocol="grpc", option requires --checkin-address)

  --checkin-address=<address>
    address of the local checkin server to run

  --output=<filename>
    write the output of hash and step commands to the file at
    <filename>. If the argument is not present the output is written
    to stdout.
    (default: none)

  --json-test-list
    write the output of the list command as json

  --uarch-ram-image=<filename>
    name of file containing microarchitecture RAM image.

and command can be:

  run
    run test and report if payload and cycles match expected

    run_uarch
    run test in the microarchitecture and report if payload and cycles match expected

  run_host_and_uarch
    run test in two machines: host and microarchitecture based; checking if root hashes match after each mcycle.

  hash
    output root hash at every <number> of cycles

  step
    output json log of step at every <number> of cycles

  dump
    dump machine initial state memory ranges on current directory

  list
    list tests selected by the test <pattern>

  machine
    prints a command for running the test machine

<number> can be specified in decimal (e.g., 16) or hexadeximal (e.g., 0x10),
with a suffix multiplier (i.e., Ki, Mi, Gi for 2^10, 2^20, 2^30, respectively),
or a left shift (e.g., 2 << 20).

<address> is one of the following formats:
  <host>:<port>
   unix:<path>

<host> can be a host name, IPv4 or IPv6 address.

]=],
        arg[0]
    ))
    os.exit()
end

local test_path = "./"
local test_pattern = ".*"
local protocol
local remote_protocol = "grpc"
local remote_address
local checkin_address
local remote
local output
local jobs = 1
local json_list = false
local periodic_action = false
local periodic_action_period = math.maxinteger
local periodic_action_start = 0
local concurrency_update_merkle_tree = util.parse_number(os.getenv("CARTESI_CONCURRENCY_UPDATE_MERKLE_TREE")) or 0
local cleanup = {}

-- List of supported options
-- Options are processed in order
-- For each option,
--   first entry is the pattern to match
--   second entry is a callback
--     if callback returns true, the option is accepted.
--     if callback returns false, the option is rejected.
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
        "^%-%-remote%-protocol%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            remote_protocol = o
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
        "^%-%-output%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            output = o
            return true
        end,
    },
    {
        "^%-%-json%-test%-list$",
        function(all)
            if not all then return false end
            json_list = true
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
        "^%-%-jobs%=([0-9]+)$",
        function(o)
            if not o or #o < 1 then return false end
            jobs = tonumber(o)
            assert(jobs and jobs >= 1, "invalid number of jobs")
            return true
        end,
    },
    {
        "^%-%-log%-proofs$",
        function(o)
            if not o then return false end
            log_proofs = true
            return true
        end,
    },
    {
        "^%-%-log%-annotations$",
        function(o)
            if not o then return false end
            log_annotations = true
            return true
        end,
    },
    {
        "^(%-%-periodic%-action%=(.*))$",
        function(all, v)
            if not v then return false end
            string.gsub(v, "^([^%,]+),(.+)$", function(p, s)
                periodic_action_period = assert(util.parse_number(p), "invalid period " .. all)
                periodic_action_start = assert(util.parse_number(s), "invalid start " .. all)
            end)
            if periodic_action_period == math.maxinteger then
                periodic_action_period = assert(util.parse_number(v), "invalid period " .. all)
                periodic_action_start = 0
            end
            assert(periodic_action_period > 0, "invalid period " .. periodic_action_period)
            periodic_action = true
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
    {
        "^%-%-uarch%-ram%-image%=(.*)$",
        function(o)
            if not o or #o < 1 then return false end
            uarch = uarch or {}
            uarch.ram = uarch.ram or {}
            uarch.ram.image_filename = o
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

if remote_address then
    protocol = require("cartesi." .. remote_protocol)
    if remote_protocol == "grpc" then assert(checkin_address, "checkin address missing") end
end

local function advance_machine(machine, max_mcycle) return machine:run(max_mcycle) end

local function run_machine(machine, ctx, max_mcycle, advance_machine_fn)
    advance_machine_fn = advance_machine_fn or advance_machine
    local mcycle = machine:read_mcycle()
    while math.ult(mcycle, max_mcycle) do
        advance_machine_fn(machine, max_mcycle)
        mcycle = machine:read_mcycle()
        if machine:read_iflags_H() then break end
    end
    ctx.read_htif_tohost_data = machine:read_htif_tohost_data()
    return machine:read_mcycle()
end

local function advance_machine_with_uarch(machine)
    if machine:run_uarch() == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then machine:reset_uarch() end
end

local function run_machine_with_uarch(machine, ctx, max_mcycle)
    return run_machine(machine, ctx, max_mcycle, advance_machine_with_uarch)
end

local function connect()
    local remote_stub = protocol.stub(remote_address, checkin_address)
    local version =
        assert(remote_stub.get_version(), "could not connect to remote cartesi machine at " .. remote_address)
    local shutdown = function() remote_stub.shutdown() end
    local mt = { __gc = function() pcall(shutdown) end }
    setmetatable(cleanup, mt)
    return remote_stub, version
end

local function build_machine(test_name)
    local config = {
        processor = {
            -- Request automatic default values for versioning CSRs
            mimpid = -1,
            marchid = -1,
            mvendorid = -1,
        },
        ram = {
            length = 32 << 20,
            image_filename = test_path .. "/" .. test_name,
        },
        htif = {
            console_getchar = false,
            yield_automatic = true,
            yield_manual = true,
        },
        rollup = {
            rx_buffer = { start = 0x60000000, length = 2 << 20 },
            tx_buffer = { start = 0x60200000, length = 2 << 20 },
            input_metadata = { start = 0x60400000, length = 4096 },
            voucher_hashes = { start = 0x60600000, length = 2 << 20 },
            notice_hashes = { start = 0x60800000, length = 2 << 20 },
        },
        flash_drive = { {
            start = 0x80000000000000,
            length = 0x40000,
        } },
    }
    if uarch then config.uarch = uarch end
    local runtime = {
        concurrency = {
            update_merkle_tree = concurrency_update_merkle_tree,
        },
    }
    if remote_address then
        if not remote then remote = connect() end
        return assert(remote.machine(config, runtime))
    end
    return assert(cartesi.machine(config, runtime))
end

local function destroy_machine(machine) machine:destroy() end

local function print_machine(test_name, expected_cycles)
    if not uarch then
        print(string.format(
            "./cartesi-machine.lua \
 --ram-length=32Mi\
 --ram-image='%s'\
 --no-bootargs\
 --max-mcycle=%d ",
            test_path .. "/" .. test_name,
            2 * expected_cycles
        ))
    else
        print(string.format(
            "./cartesi-machine.lua \
 --ram-length=32Mi\
 --ram-image='%s'\
 --no-bootargs\
 --uarch-ram-image=%s\
 --max-mcycle=%d ",
            test_path .. "/" .. test_name,
            uarch.ram.image_filename,
            2 * expected_cycles
        ))
    end
end

local function add_error(ctx, msg, ...)
    local e = string.format(msg, ...)
    ctx.failed = true
    ctx.errors[#ctx.errors + 1] = e
end

local function check_test_result(ctx)
    io.write(ctx.ram_image, ": ")
    if #ctx.expected_yield_payloads ~= (ctx.yield_payload_index - 1) then
        add_error(ctx, "yielded %d times, expected %d", ctx.yield_payload_index - 1, #ctx.expected_yield_payloads)
    end
    if ctx.read_htif_tohost_data >> 1 ~= ctx.expected_halt_payload then
        add_error(
            ctx,
            "returned halt payload %d, expected %d",
            ctx.read_htif_tohost_data >> 1,
            ctx.expected_halt_payload
        )
    end
    if ctx.cycles ~= ctx.expected_cycles then
        add_error(ctx, "terminated with mcycle = %d, expected %d", ctx.cycles, ctx.expected_cycles)
    end
    if ctx.failed then
        print("failed")
        for _, e in pairs(ctx.errors) do
            print(string.format("%s: %s", ctx.ram_image, e))
        end
    else
        print("passed")
    end
end

local function run_parallel(contexts)
    local unistd = require("posix.unistd")
    local syswait = require("posix.sys.wait")
    local pids = {}
    local running_jobs = 0
    -- sort to run slower tests first to maximize utilization of CPU cores
    table.sort(contexts, function(a, b) return b.expected_cycles < a.expected_cycles end)
    for _, ctx in ipairs(contexts) do
        do -- run test in parallel
            local pid = assert(unistd.fork())
            if pid == 0 then -- child
                local machine = ctx.target.build(ctx.ram_image)
                ctx.cycles = ctx.target.run(machine, ctx, 2 * ctx.expected_cycles)
                check_test_result(ctx)
                ctx.target.destroy(machine)
                unistd._exit(0)
            else -- parent
                pids[pid] = true
                running_jobs = running_jobs + 1
            end
        end
        while running_jobs >= jobs do
            -- wait a child to finish
            local pid, reason, exitcode = syswait.wait(-1)
            if pid and pid > 0 and reason ~= "running" then
                if not (reason == "exited" and exitcode == 0) then add_error("unexpected child process exit") end
                pids[pid] = nil
                running_jobs = running_jobs - 1
                break
            end
        end
    end
    -- wait all children
    for pid in pairs(pids) do
        local retpid, reason, exitcode = syswait.wait(pid)
        if not (retpid == pid and reason == "exited" and exitcode == 0) then
            add_error("unexpected child process exit")
        end
        pids[pid] = nil
        running_jobs = running_jobs - 1
    end
    assert(running_jobs == 0 and next(pids) == nil)
end

local function run_sync(contexts)
    for _, ctx in pairs(contexts) do
        local machine = ctx.target.build(ctx.ram_image)
        ctx.cycles = ctx.target.run(machine, ctx, 2 * ctx.expected_cycles)
        check_test_result(ctx)
        ctx.target.destroy(machine)
    end
end

local function run_tests(tests, target)
    -- construct contexts
    local contexts = {}
    for _, test in ipairs(tests) do
        contexts[#contexts + 1] = {
            target = target,
            ram_image = test[1],
            expected_cycles = test[2],
            expected_halt_payload = test[3] or 0,
            expected_yield_payloads = test[4] or {},
            yield_payload_index = 1,
            failed = false,
            cycles = 0,
            errors = {},
        }
    end
    -- run
    if jobs > 1 then
        run_parallel(contexts)
    else
        run_sync(contexts)
    end
    -- collect results
    local error_count = 0
    for _, ctx in pairs(contexts) do
        if ctx.failed then error_count = error_count + 1 end
    end
    -- print summary
    if error_count > 0 then
        io.write(string.format("\nFAILED %d of %d tests\n\n", error_count, #tests))
        os.exit(1, true)
    else
        io.write(string.format("\nPASSED all %d tests\n\n", #tests))
        os.exit(0, true)
    end
end

local function hash(tests)
    local out = io.stdout
    if output then out = assert(io.open(output, "w"), "error opening file: " .. output) end
    for _, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local expected_payload = test[3] or 0
        local machine = build_machine(ram_image)
        local total_cycles = 0
        local max_mcycle = 2 * expected_cycles
        while math.ult(machine:read_mcycle(), max_mcycle) do
            local initial_cycle = machine:read_uarch_cycle()
            local next_action_cycle = math.maxinteger
            if periodic_action then
                next_action_cycle = periodic_action_start
                if next_action_cycle <= total_cycles then
                    next_action_cycle = next_action_cycle
                        + (
                            (((total_cycles - periodic_action_start) // periodic_action_period) + 1)
                            * periodic_action_period
                        )
                end
            end
            local status = machine:run_uarch(initial_cycle + (next_action_cycle - total_cycles))
            local final_cycle = machine:read_uarch_cycle()
            total_cycles = total_cycles + (final_cycle - initial_cycle)
            if not periodic_action or total_cycles == next_action_cycle then
                out:write(machine:read_mcycle(), " ", final_cycle, " ", util.hexhash(machine:get_root_hash()), "\n")
                total_cycles = total_cycles + 1
            end
            if status == cartesi.UARCH_BREAK_REASON_UARCH_HALTED then
                machine:reset_uarch()
                if machine:read_iflags_H() then break end
            end
        end
        if machine:read_htif_tohost_data() >> 1 ~= expected_payload or machine:read_mcycle() ~= expected_cycles then
            os.exit(1, true)
        end
        out:write(
            machine:read_mcycle(),
            " ",
            machine:read_uarch_cycle(),
            " ",
            util.hexhash(machine:get_root_hash()),
            "\n"
        )
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

local function step(tests)
    local out = io.stdout
    if output then out = assert(io.open(output, "w"), "error opening file: " .. output) end
    local indentout = util.indentout
    local log_type = { annotations = log_annotations, proofs = log_proofs }
    out:write("[\n")
    for i, test in ipairs(tests) do
        local ram_image = test[1]
        local expected_cycles = test[2]
        local expected_payload = test[3] or 0
        local machine = build_machine(ram_image)
        indentout(out, 1, "{\n")
        indentout(out, 2, '"test": "%s",\n', ram_image)
        if periodic_action then
            indentout(out, 2, '"period": %u,\n', periodic_action_period)
            indentout(out, 2, '"start": %u,\n', periodic_action_start)
        end
        indentout(out, 2, '"steps": [\n')
        local total_logged_steps = 0
        local total_uarch_cycles = 0
        local max_mcycle = 2 * expected_cycles
        while math.ult(machine:read_mcycle(), max_mcycle) do
            local uarch_cycle_increment = 0
            local next_action_uarch_cycle
            if periodic_action then
                next_action_uarch_cycle = periodic_action_start
                if next_action_uarch_cycle <= total_uarch_cycles then
                    next_action_uarch_cycle = next_action_uarch_cycle
                        + (
                            (((total_uarch_cycles - periodic_action_start) // periodic_action_period) + 1)
                            * periodic_action_period
                        )
                end
                uarch_cycle_increment = next_action_uarch_cycle - total_uarch_cycles
            end
            local init_uarch_cycle = machine:read_uarch_cycle()
            machine:run_uarch(machine:read_uarch_cycle() + uarch_cycle_increment)
            local final_uarch_cycle = machine:read_uarch_cycle()
            total_uarch_cycles = total_uarch_cycles + (final_uarch_cycle - init_uarch_cycle)
            if machine:read_uarch_halt_flag() then
                machine:reset_uarch()
                if machine:read_iflags_H() then break end
            end
            if not periodic_action or total_uarch_cycles == next_action_uarch_cycle then
                local init_mcycle = machine:read_mcycle()
                init_uarch_cycle = machine:read_uarch_cycle()
                local log = machine:log_uarch_step(log_type)
                local final_mcycle = machine:read_mcycle()
                final_uarch_cycle = machine:read_uarch_cycle()
                if total_logged_steps > 0 then out:write(",\n") end
                util.dump_json_log(log, init_mcycle, init_uarch_cycle, final_mcycle, final_uarch_cycle, out, 3)
                total_uarch_cycles = total_uarch_cycles + 1
                total_logged_steps = total_logged_steps + 1
                if machine:read_uarch_halt_flag() then
                    machine:reset_uarch()
                    if machine:read_iflags_H() then break end
                end
            end
        end
        indentout(out, 2, "]\n")
        if tests[i + 1] then
            indentout(out, 1, "},\n")
        else
            indentout(out, 1, "}\n")
        end
        if machine:read_htif_tohost_data() >> 1 ~= expected_payload or machine:read_mcycle() ~= expected_cycles then
            os.exit(1, true)
        end
        machine:destroy()
    end
    out:write("]\n")
end

local function dump(tests)
    local ram_image = tests[1][1]
    local machine = build_machine(ram_image)
    for _, v in machine:get_memory_ranges() do
        local filename = string.format("%016x--%016x.bin", v.start, v.length)
        local file <close> = assert(io.open(filename, "w"))
        assert(file:write(machine:read_memory(v.start, v.length)))
    end
    machine:destroy()
end

local function list(tests)
    if json_list then
        local out = io.stdout
        local indentout = util.indentout
        out:write('{\n  "tests": [\n')
        for i, test in ipairs(tests) do
            if i ~= 1 then out:write(",\n") end
            indentout(out, 2, "{\n")
            indentout(out, 3, '"file": "' .. test[1] .. '",\n')
            indentout(out, 3, '"mcycle": ' .. test[2] .. "\n")
            indentout(out, 2, "}")
        end
        out:write("\n  ]\n}\n")
    else
        for _, test in ipairs(tests) do
            print(test[1])
        end
    end
end

local function select_test(test_name, patt)
    local i, j = test_name:find(patt)
    if i == 1 and j == #test_name then return true end
    i, j = test_name:find(patt, 1, true)
    return i == 1 and j == #test_name
end

local selected_tests = {}
for _, test in ipairs(riscv_tests) do
    if select_test(test[1], test_pattern) then selected_tests[#selected_tests + 1] = test end
end

local function build_both_machines(test_name)
    return {
        host = build_machine(test_name),
        uarch = build_machine(test_name),
    }
end

local function destroy_both_machines(target)
    destroy_machine(target.host)
    destroy_machine(target.uarch)
end

local function run_host_and_uarch_machines(target, ctx, max_mcycle)
    local host_machine = target.host
    local uarch_machine = target.uarch
    local host_cycles = host_machine:read_mcycle()
    local uarch_cycles = uarch_machine:read_mcycle()
    assert(host_cycles == uarch_cycles)
    if host_cycles ~= uarch_cycles then
        add_error(ctx, "host_cycles ~= uarch_cycles: %d ~= %d", host_cycles, uarch_cycles)
        return 0
    end
    while math.ult(host_cycles, max_mcycle) do
        local host_hash = host_machine:get_root_hash()
        local uarch_hash = uarch_machine:get_root_hash()
        if host_hash ~= uarch_hash then
            add_error(
                ctx,
                "Hash mismatch at mcycle %d: %s ~= %s",
                host_cycles,
                util.hexhash(host_hash),
                util.hexhash(uarch_hash)
            )
            break
        end
        host_machine:run(1 + host_cycles)
        advance_machine_with_uarch(uarch_machine)
        host_cycles = host_machine:read_mcycle()
        uarch_cycles = uarch_machine:read_mcycle()
        if host_cycles ~= uarch_cycles then
            add_error(ctx, "host_cycles ~= uarch_cycles: %d ~= %d", host_cycles, uarch_cycles)
            break
        end
        local host_iflags_H = host_machine:read_iflags_H()
        local uarch_iflags_H = uarch_machine:read_iflags_H()
        if host_iflags_H ~= uarch_iflags_H then
            add_error(
                ctx,
                "host_iflags_H ~= uarch_iflags_H: %s ~= %s",
                tostring(host_iflags_H),
                tostring(uarch_iflags_H)
            )
            break
        end
        if host_iflags_H then break end
    end
    local host_htif_tohost_data = host_machine:read_htif_tohost_data()
    local uarch_htif_tohost_data = uarch_machine:read_htif_tohost_data()
    if host_htif_tohost_data ~= uarch_htif_tohost_data then
        add_error(
            ctx,
            "host_htif_tohost_data ~= uarch_htif_tohost_data: %d ~= %d",
            host_htif_tohost_data,
            uarch_htif_tohost_data
        )
    end
    ctx.read_htif_tohost_data = host_htif_tohost_data
    return host_cycles
end

local targets = {
    -- Run test on host-based emulator
    host = {
        build = build_machine,
        run = run_machine,
        destroy = destroy_machine,
    },
    -- Run test on microarchitecture-based emulator
    uarch = {
        build = build_machine,
        run = run_machine_with_uarch,
        destroy = destroy_machine,
    },
    -- Run test on both architectures: macro and micro; comparing root hashes after every mcycle
    host_and_uarch = {
        build = build_both_machines,
        run = run_host_and_uarch_machines,
        destroy = destroy_both_machines,
    },
}

if #selected_tests < 1 then
    error("no test selected")
elseif command == "run" then
    run_tests(selected_tests, targets.host)
elseif command == "run_uarch" then
    run_tests(selected_tests, targets.uarch)
elseif command == "run_host_and_uarch" then
    run_tests(selected_tests, targets.host_and_uarch)
elseif command == "hash" then
    hash(selected_tests)
elseif command == "step" then
    step(selected_tests)
elseif command == "dump" then
    dump(selected_tests)
elseif command == "list" then
    list(selected_tests)
elseif command == "machine" then
    print_machines(selected_tests)
else
    error("command not found")
end
