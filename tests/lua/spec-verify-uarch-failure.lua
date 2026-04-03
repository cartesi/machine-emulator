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

--[[
Tests that verify_step_uarch and verify_send_cmio_response correctly reject
corrupted access logs. This exercises the validation error paths in
uarch-replay-state-access.h and replay-send-cmio-state-access.h.
]]

local cartesi = require("cartesi")
local lester = require("cartesi.third-party.lester")
local test_util = require("cartesi.tests.util")

local describe, it, expect = lester.describe, lester.it, lester.expect

local uarch_test_path = test_util.tests_uarch_path

-- Uarch halt program: li a7,halt; ecall
local UARCH_HALT_INSN = (cartesi.UARCH_ECALL_FN_HALT << 20) | 0x00893
local uarch_default_program = {
    0x07b00513, -- li a0,123
    UARCH_HALT_INSN, -- li a7,halt
    0x00000073, -- ecall
}

local function create_test_uarch_program(instructions)
    local file_path = os.tmpname()
    local f <close> = assert(io.open(file_path, "wb"))
    for _, insn in pairs(instructions) do
        f:write(string.pack("I4", insn))
    end
    return file_path
end

-- A hash guaranteed to be wrong for any valid proof
local bad_hash = string.rep("\xba", cartesi.HASH_SIZE)

-- Build a machine with the default uarch test program (li a0,123; halt ecall)
local function build_default_machine()
    local data_filename = create_test_uarch_program(uarch_default_program)
    local machine = cartesi.machine({
        ram = { length = 0x20000 },
        uarch = {
            ram = {
                length = 0x1000,
                backing_store = { data_filename = data_filename },
            },
        },
    }, {})
    os.remove(data_filename)
    return machine
end

-- Build a machine with the ecall-write-tlb test binary for TLB write tests
local function build_tlb_machine()
    return cartesi.machine({
        ram = { length = 0x20000 },
        uarch = {
            ram = {
                backing_store = {
                    data_filename = uarch_test_path .. "/rv64ui-uarch-ecall-write-tlb.bin",
                },
            },
        },
    }, {})
end

-- Build a machine suitable for log_send_cmio_response
local function build_cmio_machine()
    return cartesi.machine({
        ram = { length = 0x20000 },
        uarch = {},
    }, {})
end

-- Helper: get a fresh step log, apply a corruption, verify it fails with expected error
local function step_should_fail(machine_builder, expected_error, corrupt)
    local machine <close> = machine_builder()
    local initial_hash = machine:get_root_hash()
    local log = machine:log_step_uarch()
    local final_hash = machine:get_root_hash()
    corrupt(log)
    expect.fail(function()
        machine:verify_step_uarch(initial_hash, log, final_hash)
    end, expected_error)
end

-- Helper: get a fresh cmio log, apply a corruption, verify it fails with expected error
local function cmio_should_fail(expected_error, corrupt, options)
    options = options or {}
    local machine <close> = build_cmio_machine()
    machine:write_reg("iflags_Y", 1)
    local reason = options.reason or 1
    local data = options.data or "test cmio data"
    local initial_hash = machine:get_root_hash()
    local log = machine:log_send_cmio_response(reason, data)
    local final_hash = machine:get_root_hash()
    corrupt(log)
    expect.fail(function()
        machine:verify_send_cmio_response(reason, data, initial_hash, log, final_hash)
    end, expected_error)
end

-- Find the index of an access to a TLB slot (by address range)
local function find_tlb_access(log)
    for i = 1, #log.accesses do
        local a = log.accesses[i]
        if
            a.address >= cartesi.AR_SHADOW_TLB_START
            and a.address < cartesi.AR_SHADOW_TLB_START + cartesi.AR_SHADOW_TLB_LENGTH
        then
            return i
        end
    end
    return nil
end

-- Helper: step through the TLB test until we find a TLB write, corrupt it, verify failure
local function tlb_step_should_fail(expected_error, corrupt)
    local machine <close> = build_tlb_machine()
    for _ = 1, 46 do
        local initial_hash = machine:get_root_hash()
        local log = machine:log_step_uarch()
        local final_hash = machine:get_root_hash()
        local tlb_idx = find_tlb_access(log)
        if tlb_idx then
            corrupt(log, tlb_idx)
            expect.fail(function()
                machine:verify_step_uarch(initial_hash, log, final_hash)
            end, expected_error)
            return
        end
        if machine:read_reg("uarch_halt_flag") ~= 0 then
            break
        end
    end
    error("did not find a TLB write access in the ecall-write-tlb test")
end

--------------------------------------------------------------------------------

describe("verify_step_uarch", function()
    describe("basic step", function()
        it("should reject empty access log", function()
            step_should_fail(build_default_machine, "log is missing access", function(log)
                log.accesses = {}
            end)
        end)

        it("should reject extra access at end", function()
            step_should_fail(build_default_machine, "access log was not fully consumed", function(log)
                log.accesses[#log.accesses + 1] = log.accesses[1]
            end)
        end)

        it("should reject wrong type on 1st read access", function()
            step_should_fail(build_default_machine, "expected 1st access to read uarch.cycle", function(log)
                log.accesses[1].type = "write"
            end)
        end)

        it("should reject unexpected written data on read access", function()
            step_should_fail(build_default_machine, "unexpected written data in 1st access read access", function(log)
                log.accesses[1].written = log.accesses[1].read
            end)
        end)

        it("should reject unexpected written hash on read access", function()
            step_should_fail(build_default_machine, "unexpected written hash in 1st access read access", function(log)
                log.accesses[1].written_hash = log.accesses[1].read_hash
            end)
        end)

        it("should reject wrong address on read access", function()
            step_should_fail(build_default_machine, "expected 1st access to read uarch.cycle at address", function(log)
                log.accesses[1].address = 0
            end)
        end)

        it("should reject wrong log2_size on read access", function()
            step_should_fail(build_default_machine, "expected 1st access to uarch.cycle to read 2^", function(log)
                log.accesses[1].log2_size = 2
            end)
        end)

        it("should reject corrupt sibling hash on read access", function()
            step_should_fail(
                build_default_machine,
                "siblings and read hash do not match root hash before 1st access",
                function(log)
                    log.accesses[1].sibling_hashes[1] = bad_hash
                end
            )
        end)

        it("should reject missing read data", function()
            step_should_fail(build_default_machine, "missing read data for uarch.cycle in 1st access", function(log)
                log.accesses[1].read = nil
            end)
        end)

        it("should reject corrupt read data", function()
            step_should_fail(
                build_default_machine,
                "read data for uarch.cycle does not match read hash in 1st access",
                function(log)
                    log.accesses[1].read = string.rep("\xff", #log.accesses[1].read)
                end
            )
        end)

        it("should reject wrong type on last write access", function()
            step_should_fail(build_default_machine, "expected", function(log)
                log.accesses[#log.accesses].type = "read"
            end)
        end)

        it("should reject wrong address on write access", function()
            step_should_fail(build_default_machine, "at address", function(log)
                log.accesses[#log.accesses].address = 0
            end)
        end)

        it("should reject wrong log2_size on write access", function()
            step_should_fail(build_default_machine, "to write 2^", function(log)
                log.accesses[#log.accesses].log2_size = 2
            end)
        end)

        it("should reject corrupt siblings on write access", function()
            step_should_fail(build_default_machine, "siblings and read hash do not match root hash", function(log)
                log.accesses[#log.accesses].sibling_hashes[1] = bad_hash
            end)
        end)

        it("should reject missing read data on write access", function()
            step_should_fail(build_default_machine, "missing read data for", function(log)
                log.accesses[#log.accesses].read = nil
            end)
        end)

        it("should reject corrupt read data on write access", function()
            step_should_fail(build_default_machine, "read data for", function(log)
                log.accesses[#log.accesses].read = string.rep("\xff", #log.accesses[#log.accesses].read)
            end)
        end)

        it("should reject missing written_hash on write access", function()
            step_should_fail(build_default_machine, "missing written hash of", function(log)
                log.accesses[#log.accesses].written_hash = nil
            end)
        end)

        it("should reject wrong written_hash on write access", function()
            step_should_fail(build_default_machine, "written hash for", function(log)
                log.accesses[#log.accesses].written_hash = bad_hash
            end)
        end)

        it("should reject corrupt written data on write access", function()
            step_should_fail(build_default_machine, "written data for", function(log)
                log.accesses[#log.accesses].written = string.rep("\xff", #log.accesses[#log.accesses].written)
            end)
        end)

        it("should reject wrong type on 2nd access", function()
            step_should_fail(build_default_machine, "expected 2nd access to", function(log)
                log.accesses[2].type = "write"
            end)
        end)

        it("should reject wrong type on 3rd access", function()
            step_should_fail(build_default_machine, "expected 3rd access to", function(log)
                log.accesses[3].type = "write"
            end)
        end)

        it("should reject wrong type on 4th access", function()
            step_should_fail(build_default_machine, "expected 4th access to", function(log)
                if log.accesses[4].type == "read" then
                    log.accesses[4].type = "write"
                else
                    log.accesses[4].type = "read"
                end
            end)
        end)

        it("should reject wrong root_hash_after", function()
            local machine <close> = build_default_machine()
            local initial_hash = machine:get_root_hash()
            local log = machine:log_step_uarch()
            expect.fail(function()
                machine:verify_step_uarch(initial_hash, log, bad_hash)
            end, "mismatch in root hash after replay")
        end)
    end)

    describe("TLB write via ecall", function()
        it("should reject wrong type", function()
            tlb_step_should_fail("expected", function(log, idx)
                log.accesses[idx].type = "read"
            end)
        end)

        it("should reject wrong address", function()
            tlb_step_should_fail("at address", function(log, idx)
                log.accesses[idx].address = 0
            end)
        end)

        it("should reject corrupt siblings", function()
            tlb_step_should_fail("siblings and read hash do not match root hash", function(log, idx)
                log.accesses[idx].sibling_hashes[1] = bad_hash
            end)
        end)

        it("should reject missing written_hash", function()
            tlb_step_should_fail("missing written hash of tlb.slot", function(log, idx)
                log.accesses[idx].written_hash = nil
            end)
        end)

        it("should reject wrong written_hash", function()
            tlb_step_should_fail("written hash for tlb.slot does not match expected hash", function(log, idx)
                log.accesses[idx].written_hash = bad_hash
            end)
        end)

        it("should reject corrupt read data", function()
            tlb_step_should_fail("read data for tlb.slot does not match read hash", function(log, idx)
                local size = 1 << log.accesses[idx].log2_size
                if log.accesses[idx].read then
                    log.accesses[idx].read = string.rep("\xff", #log.accesses[idx].read)
                else
                    log.accesses[idx].read = string.rep("\xff", size)
                end
            end)
        end)

        it("should reject corrupt written data", function()
            tlb_step_should_fail("written data for tlb.slot does not match written hash", function(log, idx)
                local size = 1 << log.accesses[idx].log2_size
                if log.accesses[idx].written then
                    log.accesses[idx].written = string.rep("\xff", #log.accesses[idx].written)
                else
                    log.accesses[idx].written = string.rep("\xff", size)
                end
            end)
        end)
    end)
end)

-- The access pattern for send_cmio_response with non-empty data is:
--   1: read iflags.Y       (check_read)
--   2: write cmio rx buffer (do_write_memory_with_padding)
--   3: write htif.fromhost  (check_write)
--   4: write iflags.Y       (check_write)

describe("verify_send_cmio_response", function()
    describe("log structure", function()
        it("should reject empty access log", function()
            cmio_should_fail("the access log has no accesses", function(log)
                log.accesses = {}
            end)
        end)

        it("should reject extra access at end", function()
            cmio_should_fail("access log was not fully consumed", function(log)
                log.accesses[#log.accesses + 1] = log.accesses[1]
            end)
        end)

        it("should reject truncated log (missing last access)", function()
            cmio_should_fail("too few accesses in log", function(log)
                log.accesses[#log.accesses] = nil
            end)
        end)

        it("should reject truncated log (missing buffer write)", function()
            -- Keep only the first access (read iflags.Y), so do_write_memory_with_padding
            -- hits "too few accesses in log"
            cmio_should_fail("too few accesses in log", function(log)
                while #log.accesses > 1 do
                    log.accesses[#log.accesses] = nil
                end
            end)
        end)

        it("should reject truncated log (missing check_read)", function()
            -- With zero-length data, accesses are: read iflags.Y, write htif.fromhost, write iflags.Y
            -- Keep only the first two so check_write for iflags.Y hits "too few accesses"
            cmio_should_fail("too few accesses in log", function(log)
                log.accesses[#log.accesses] = nil
            end, { data = "" })
        end)

        it("should reject wrong root_hash_after", function()
            local machine <close> = build_cmio_machine()
            machine:write_reg("iflags_Y", 1)
            local reason = 1
            local data = "test"
            local initial_hash = machine:get_root_hash()
            local log = machine:log_send_cmio_response(reason, data)
            expect.fail(function()
                machine:verify_send_cmio_response(reason, data, initial_hash, log, bad_hash)
            end, "mismatch in root hash after replay")
        end)
    end)

    describe("check_read (access 1: read iflags.Y)", function()
        it("should reject wrong type", function()
            cmio_should_fail("expected 1st access to read iflags.Y", function(log)
                log.accesses[1].type = "write"
            end)
        end)

        it("should reject wrong address", function()
            cmio_should_fail("expected 1st access to read iflags.Y address", function(log)
                log.accesses[1].address = 0
            end)
        end)

        it("should reject wrong log2_size", function()
            cmio_should_fail("expected 1st access to read 2^", function(log)
                log.accesses[1].log2_size = 2
            end)
        end)

        it("should reject missing read data", function()
            cmio_should_fail("missing read iflags.Y data at 1st access", function(log)
                log.accesses[1].read = nil
            end)
        end)

        it("should reject wrong read data size", function()
            cmio_should_fail("expected read iflags.Y data to contain 2^", function(log)
                log.accesses[1].read = "\0"
            end)
        end)

        it("should reject read data that does not hash to read_hash", function()
            cmio_should_fail("logged read data of iflags.Y data does not hash to the logged read hash", function(log)
                log.accesses[1].read = string.rep("\xff", #log.accesses[1].read)
            end)
        end)

        it("should reject corrupt sibling hash", function()
            cmio_should_fail("Mismatch in root hash of 1st access", function(log)
                log.accesses[1].sibling_hashes[1] = bad_hash
            end)
        end)
    end)

    describe("do_write_memory_with_padding (access 2: write cmio rx buffer)", function()
        it("should reject wrong type", function()
            cmio_should_fail("expected 2nd access to write cmio rx buffer", function(log)
                log.accesses[2].type = "read"
            end)
        end)

        it("should reject wrong address", function()
            cmio_should_fail("expected address of 2nd access to match address of cmio rx buffer", function(log)
                log.accesses[2].address = 0
            end)
        end)

        it("should reject wrong log2_size", function()
            cmio_should_fail("expected 2nd access to write 2^", function(log)
                log.accesses[2].log2_size = 2
            end)
        end)

        it("should reject corrupt read data", function()
            cmio_should_fail("hash of read data and read hash at 2nd access does not match", function(log)
                local size = 1 << log.accesses[2].log2_size
                log.accesses[2].read = string.rep("\xff", size)
            end)
        end)

        it("should reject missing written_hash", function()
            cmio_should_fail("write 2nd access has no written hash", function(log)
                log.accesses[2].written_hash = nil
            end)
        end)

        it("should reject wrong written_hash", function()
            cmio_should_fail(
                "logged written hash of cmio rx buffer does not match the hash of data argument",
                function(log)
                    log.accesses[2].written_hash = bad_hash
                end
            )
        end)

        it("should reject corrupt written data", function()
            cmio_should_fail("written hash and written data mismatch at 2nd access", function(log)
                local size = 1 << log.accesses[2].log2_size
                log.accesses[2].written = string.rep("\xff", size)
            end)
        end)

        it("should reject corrupt sibling hash", function()
            cmio_should_fail("Mismatch in root hash of 2nd access", function(log)
                log.accesses[2].sibling_hashes[1] = bad_hash
            end)
        end)
    end)

    describe("check_write (access 3: write htif.fromhost)", function()
        it("should reject wrong type", function()
            cmio_should_fail("expected 3rd access to write htif.fromhost", function(log)
                log.accesses[3].type = "read"
            end)
        end)

        it("should reject wrong address", function()
            cmio_should_fail("expected 3rd access to write htif.fromhost to address", function(log)
                log.accesses[3].address = 0
            end)
        end)

        it("should reject wrong log2_size", function()
            cmio_should_fail("expected 3rd access to write 2^", function(log)
                log.accesses[3].log2_size = 2
            end)
        end)

        it("should reject missing read data", function()
            cmio_should_fail("missing read htif.fromhost data at 3rd access", function(log)
                log.accesses[3].read = nil
            end)
        end)

        it("should reject wrong read data size", function()
            cmio_should_fail("expected overwritten data from htif.fromhost to contain 2^", function(log)
                log.accesses[3].read = "\0"
            end)
        end)

        it("should reject read data that does not hash to read_hash", function()
            cmio_should_fail("logged read data of htif.fromhost does not hash to the logged read hash", function(log)
                log.accesses[3].read = string.rep("\xff", #log.accesses[3].read)
            end)
        end)

        it("should reject missing written_hash", function()
            cmio_should_fail("missing written htif.fromhost hash at 3rd access", function(log)
                log.accesses[3].written_hash = nil
            end)
        end)

        it("should reject missing written data", function()
            cmio_should_fail("missing written htif.fromhost data at 3rd access", function(log)
                log.accesses[3].written = nil
            end)
        end)

        it("should reject wrong written data size", function()
            cmio_should_fail("expected written htif.fromhost data to contain 2^", function(log)
                log.accesses[3].written = "\0"
            end)
        end)

        it("should reject written data that does not hash to written_hash", function()
            cmio_should_fail(
                "logged written data of htif.fromhost does not hash to the logged written hash",
                function(log)
                    log.accesses[3].written = string.rep("\xff", #log.accesses[3].written)
                end
            )
        end)

        it("should reject value that does not match logged written value", function()
            cmio_should_fail("value being written to htif.fromhost does not match", function(log)
                local a = log.accesses[3]
                local new_written = string.rep("\x42", #a.written)
                a.written = new_written
                a.written_hash = cartesi.keccak256(new_written)
            end)
        end)

        it("should reject written data that differs from read in unexpected way", function()
            cmio_should_fail("doesn't differ from the logged read data only by the written word", function(log)
                local a = log.accesses[3]
                -- htif.fromhost is at offset 16 within the 32-byte leaf,
                -- so we corrupt byte 0 (outside the written word) while keeping the word intact
                local corrupted = string.char(a.written:byte(1) ~ 0xff) .. a.written:sub(2)
                a.written = corrupted
                a.written_hash = cartesi.keccak256(corrupted)
            end)
        end)

        it("should reject corrupt sibling hash", function()
            cmio_should_fail("Mismatch in root hash of 3rd access", function(log)
                log.accesses[3].sibling_hashes[1] = bad_hash
            end)
        end)
    end)

    describe("ordinal coverage (4th access: write iflags.Y)", function()
        it("should reject wrong type on 4th access", function()
            cmio_should_fail("expected 4th access to write iflags.Y", function(log)
                log.accesses[4].type = "read"
            end)
        end)
    end)

    describe("zero-length data (no buffer write)", function()
        it("should reject wrong type on 2nd access", function()
            cmio_should_fail("expected 2nd access to write htif.fromhost", function(log)
                log.accesses[2].type = "read"
            end, { data = "" })
        end)

        it("should reject wrong type on 3rd access", function()
            cmio_should_fail("expected 3rd access to write iflags.Y", function(log)
                log.accesses[3].type = "read"
            end, { data = "" })
        end)
    end)
end)
