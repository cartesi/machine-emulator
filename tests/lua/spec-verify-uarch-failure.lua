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
lester.parse_args()
local tests_util = require("cartesi.tests.util")

local describe, it, expect = lester.describe, lester.it, lester.expect

local uarch_test_path = tests_util.tests_uarch_path

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
    corrupt(log)
    expect.fail(function()
        machine:verify_step_uarch(initial_hash, log)
    end, expected_error)
end

-- Helper: get a fresh cmio log, apply a corruption, verify it fails with expected error.
-- With options.advance, the machine waits for an advance-state input, whose log also
-- records the revert root hash.
local function cmio_should_fail(expected_error, corrupt, options)
    options = options or {}
    local machine <close> = build_cmio_machine()
    machine:write_reg("iflags_Y", 1)
    local reason = 1
    if options.advance then
        machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
        machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
        machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_ACCEPTED)
        reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    end
    local data = options.data or "test cmio data"
    local initial_hash = machine:get_root_hash()
    local revert_root_hash = initial_hash
    local log = machine:log_send_cmio_response(reason, data, revert_root_hash)
    corrupt(log)
    expect.fail(function()
        machine:verify_send_cmio_response(reason, data, initial_hash, log, revert_root_hash)
    end, expected_error)
end

local function change_sibling_count(log, adjustment)
    local siblings = log.accesses[1].sibling_hashes
    if adjustment < 0 then
        table.remove(siblings)
    else
        siblings[#siblings + 1] = bad_hash
    end
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
        local tlb_idx = find_tlb_access(log)
        if tlb_idx then
            corrupt(log, tlb_idx)
            expect.fail(function()
                machine:verify_step_uarch(initial_hash, log)
            end, expected_error)
            return
        end
        if machine:read_reg("uarch_halt") ~= 0 then
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

        it("should reject a log2_size that does not fit an int on read access", function()
            -- Truncated to an int, it would be 3, the right size for this access
            step_should_fail(build_default_machine, 'log2_size" is out of bounds', function(log)
                log.accesses[1].log2_size = (1 << 32) + 3
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

        it("should return the root hash after the step for the caller to check", function()
            local machine <close> = build_default_machine()
            local initial_hash = machine:get_root_hash()
            local log = machine:log_step_uarch()
            local final_hash = machine:get_root_hash()
            local obtained_hash = machine:verify_step_uarch(initial_hash, log)
            expect.equal(obtained_hash, final_hash)
            expect.not_equal(obtained_hash, bad_hash)
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
--   1: read iflags.Y          (check_read)
--   2: write cmio rx buffer   (check_write_memory_with_padding)
--   3: write htif.fromhost    (check_write)
--   4: write iflags.Y         (check_write)
-- For an advance-state response, the reads that check the machine state and the
-- writes that record the mcycle limit and the revert root hash come first:
--   1: read iflags.Y          (check_read)
--   2: read htif.tohost       (check_read)
--   3: read mcycle            (check_read)
--   4: write imcyclemax       (check_write)
--   5: write revert root hash (check_write_memory_with_padding)
--   6: write cmio rx buffer   (check_write_memory_with_padding)
--   7: write htif.fromhost    (check_write)
--   8: write iflags.Y         (check_write)

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

        it("should reject truncated log (missing rx buffer write)", function()
            -- Keep only the first access (read iflags.Y), so check_write_memory_with_padding
            -- hits "too few accesses in log"
            cmio_should_fail("too few accesses in log", function(log)
                while #log.accesses > 1 do
                    log.accesses[#log.accesses] = nil
                end
            end)
        end)

        it("should reject truncated log (missing check_read)", function()
            -- With zero-length data, accesses are: read iflags.Y, write htif.fromhost,
            -- write iflags.Y
            -- Keep only the first two so check_write for iflags.Y hits "too few accesses"
            cmio_should_fail("too few accesses in log", function(log)
                log.accesses[#log.accesses] = nil
            end, { data = "" })
        end)

        it("should return the root hash after the response for the caller to check", function()
            local machine <close> = build_cmio_machine()
            machine:write_reg("iflags_Y", 1)
            local reason = 1
            local data = "test"
            local initial_hash = machine:get_root_hash()
            local revert_root_hash = initial_hash
            local log = machine:log_send_cmio_response(reason, data, revert_root_hash)
            local final_hash = machine:get_root_hash()
            local obtained_hash = machine:verify_send_cmio_response(reason, data, initial_hash, log, revert_root_hash)
            expect.equal(obtained_hash, final_hash)
            expect.not_equal(obtained_hash, bad_hash)
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

    describe("check_write_memory_with_padding (advance-state access 5: write revert root hash)", function()
        it("should reject wrong type", function()
            cmio_should_fail("expected 5th access to write revert root hash", function(log)
                log.accesses[5].type = "read"
            end, { advance = true })
        end)

        it("should reject wrong address", function()
            cmio_should_fail("expected address of 5th access to match address of revert root hash", function(log)
                log.accesses[5].address = 0
            end, { advance = true })
        end)

        it("should reject wrong log2_size", function()
            cmio_should_fail("expected 5th access to write 2^", function(log)
                log.accesses[5].log2_size = 2
            end, { advance = true })
        end)

        it("should reject wrong written_hash", function()
            cmio_should_fail(
                "logged written hash of revert root hash does not match the hash of data argument",
                function(log)
                    log.accesses[5].written_hash = bad_hash
                end,
                { advance = true }
            )
        end)

        it("should reject corrupt sibling hash", function()
            cmio_should_fail("Mismatch in root hash of 5th access", function(log)
                log.accesses[5].sibling_hashes[1] = bad_hash
            end, { advance = true })
        end)
    end)

    describe("check_write_memory_with_padding (access 2: write cmio rx buffer)", function()
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

describe("access proof sibling count", function()
    for _, adjustment in ipairs({ -1, 1 }) do
        local count = adjustment < 0 and "missing" or "extra"
        local expected_error = "access sibling hash count is inconsistent with proof size"

        it("should reject " .. count .. " siblings in uarch step logs", function()
            step_should_fail(build_default_machine, expected_error, function(log)
                change_sibling_count(log, adjustment)
            end)
        end)

        it("should reject " .. count .. " siblings in CMIO response logs", function()
            cmio_should_fail(expected_error, function(log)
                change_sibling_count(log, adjustment)
            end)
        end)

        it("should reject " .. count .. " siblings in uarch reset logs", function()
            local machine <close> = build_cmio_machine()
            local initial_hash = machine:get_root_hash()
            local log = machine:log_reset_uarch()
            change_sibling_count(log, adjustment)
            expect.fail(function()
                machine:verify_reset_uarch(initial_hash, log)
            end, expected_error)
        end)
    end
end)

describe("uarch TLB writes with an invalid set index", function()
    -- A uarch program that issues the WRITE_TLB ecall for slot 0 of a set the TLB does not have
    local programs = {
        ["3"] = { 0x00300513 }, -- li a0,3
        ["0x40000"] = { 0x00040537 }, -- lui a0,0x40
    }
    for name, set_index_program in pairs(programs) do
        local program = { table.unpack(set_index_program) }
        program[#program + 1] = 0x00000593 -- li a1,0
        program[#program + 1] = 0x00001637 -- lui a2,0x1
        program[#program + 1] = (cartesi.UARCH_ECALL_FN_WRITE_TLB << 20) | 0x00893 -- li a7,write_tlb
        program[#program + 1] = 0x00000073 -- ecall
        local function build_machine()
            local data_filename = create_test_uarch_program(program)
            local machine = cartesi.machine({
                ram = { length = 0x20000 },
                uarch = { ram = { length = 0x1000, backing_store = { data_filename = data_filename } } },
            }, {})
            os.remove(data_filename)
            return machine
        end
        it("should fail cleanly when running, logging and collecting set index " .. name, function()
            for _, step in ipairs({
                {
                    function(machine)
                        machine:run_uarch(16)
                    end,
                    "invalid TLB index",
                },
                {
                    function(machine)
                        for _ = 1, 16 do
                            machine:log_step_uarch()
                        end
                    end,
                    "invalid TLB index",
                },
                -- The collector refuses the custom uarch program before running it
                {
                    function(machine)
                        local revert_tail = { string.rep("\0", cartesi.HASH_SIZE), string.rep("\0", cartesi.HASH_SIZE) }
                        machine:collect_uarch_cycle_root_hashes(1, 0, revert_tail)
                    end,
                    "microarchitecture is not pristine",
                },
            }) do
                local machine <close> = build_machine()
                expect.fail(function()
                    step[1](machine)
                end, step[2])
            end
        end)
    end
end)

describe("uarch TLB writes with an out-of-range slot index", function()
    -- A uarch program that issues the WRITE_TLB ecall for set 0, slot 0, with vaddr_page 0x1000
    local program = {
        0x00000513, -- li a0,0
        0x00000593, -- li a1,0
        0x00001637, -- lui a2,0x1
        (cartesi.UARCH_ECALL_FN_WRITE_TLB << 20) | 0x00893, -- li a7,write_tlb
        0x00000073, -- ecall
    }
    local ECALL_CYCLE = 4
    -- The slot index whose slot address lands on the start of guest RAM
    local slot_index = (cartesi.AR_RAM_START - cartesi.AR_SHADOW_TLB_START) // cartesi.SHADOW_TLB_SLOT_SIZE
    -- Machines stopped at the ecall, with the given TLB set and slot indices in a0 and a1
    local function build_machine(set_index, slot)
        local data_filename = create_test_uarch_program(program)
        local machine = cartesi.machine({
            ram = { length = 0x20000 },
            uarch = { ram = { length = 0x1000, backing_store = { data_filename = data_filename } } },
        }, {})
        os.remove(data_filename)
        machine:run_uarch(ECALL_CYCLE)
        machine:write_reg("uarch_x10", set_index)
        machine:write_reg("uarch_x11", slot)
        return machine
    end
    -- Rebuilds the accesses of the genuine in-range log against the given machine, with the TLB slot write
    -- moved to the address the indices in its a0 and a1 select, wrapped to 64 bits as an unchecked verifier
    -- would compute it. Returns the log and the root hashes before and after it.
    local function rebuild_log(machine, genuine_log)
        local set_index, slot = machine:read_reg("uarch_x10"), machine:read_reg("uarch_x11")
        local slot_size = cartesi.SHADOW_TLB_SLOT_SIZE
        local tlb_address = cartesi.AR_SHADOW_TLB_START + (set_index * cartesi.TLB_SET_SIZE + slot) * slot_size
        local slot_image = string.pack(
            "<I8I8I8I8",
            machine:read_reg("uarch_x12"),
            machine:read_reg("uarch_x13"),
            machine:read_reg("uarch_x14"),
            0
        )
        local word_registers = {
            [cartesi.machine:get_reg_address("uarch_pc")] = "uarch_pc",
            [cartesi.machine:get_reg_address("uarch_cycle")] = "uarch_cycle",
        }
        -- Every access is proven at the hash-tree word that holds it
        local word_log2_size = cartesi.HASH_TREE_LOG2_WORD_SIZE
        local word_size = 1 << word_log2_size
        local before = machine:get_root_hash()
        local log = { log_type = genuine_log.log_type, accesses = {} }
        for i, genuine in ipairs(genuine_log.accesses) do
            local access = { type = genuine.type, log2_size = genuine.log2_size, address = genuine.address }
            local is_slot_write = genuine.address == cartesi.AR_SHADOW_TLB_START and genuine.log2_size == word_log2_size
            if is_slot_write then
                expect.equal(cartesi.keccak256(slot_image), genuine.written_hash)
                access.address = tlb_address
            end
            local word = access.address & ~(word_size - 1)
            access.read_hash = machine:get_node_hash(word, word_log2_size)
            access.sibling_hashes = machine:get_proof(word, word_log2_size).sibling_hashes
            if genuine.read then
                access.read = machine:read_memory(word, word_size)
            end
            if genuine.written_hash then
                if is_slot_write then
                    machine:write_memory(access.address, slot_image)
                else
                    local value = string.unpack("<I8", genuine.written, (genuine.address & (word_size - 1)) + 1)
                    machine:write_reg(assert(word_registers[access.address]), value)
                end
                access.written_hash = machine:get_node_hash(word, word_log2_size)
                if genuine.written then
                    access.written = machine:read_memory(word, word_size)
                end
            end
            log.accesses[i] = access
        end
        return log, before, machine:get_root_hash()
    end

    local genuine_log
    do
        local machine <close> = build_machine(0, 0)
        genuine_log = machine:log_step_uarch()
    end

    for _, set_index in ipairs({ 0, 1 << 51 }) do
        local name = string.format("set index 0x%x", set_index)
        it("should fail cleanly when running and logging slot index " .. slot_index .. " with " .. name, function()
            for _, step in ipairs({ "run_uarch", "log_step_uarch" }) do
                local machine <close> = build_machine(set_index, slot_index)
                expect.fail(function()
                    if step == "run_uarch" then
                        machine:run_uarch(ECALL_CYCLE + 1)
                    else
                        machine:log_step_uarch()
                    end
                end, "invalid TLB index")
            end
        end)
        it("should reject a log that writes the slot to guest RAM with " .. name, function()
            local machine <close> = build_machine(set_index, slot_index)
            local log, before, after = rebuild_log(machine, genuine_log)
            expect.equal(log.accesses[find_tlb_access(genuine_log)].address, cartesi.AR_RAM_START)
            expect.fail(function()
                cartesi.machine:verify_step_uarch(before, log, after)
            end, "invalid TLB index")
        end)
    end
end)

describe("verify_reset_uarch at a rejected input", function()
    for _, corruption in ipairs({ "revert root data", "revert root siblings", "missing revert root access" }) do
        it("should reject " .. corruption, function()
            local machine <close> = build_cmio_machine()
            local revert_root_hash = machine:get_root_hash()
            machine:write_revert_root_hash(revert_root_hash)
            machine:write_reg("iflags_Y", 1)
            machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
            machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
            machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
            machine:write_reg("uarch_halt", 1)
            local initial_hash = machine:get_root_hash()
            local log = machine:log_reset_uarch()
            expect.equal(machine:verify_reset_uarch(initial_hash, log), revert_root_hash)
            expect.not_equal(machine:get_root_hash(), revert_root_hash)

            local revert_index
            for i, access in ipairs(log.accesses) do
                if access.address == cartesi.AR_SHADOW_REVERT_ROOT_HASH_START then
                    revert_index = i
                    break
                end
            end
            assert(revert_index, "reset log did not authenticate the revert root")
            local access = log.accesses[revert_index]
            if corruption == "revert root data" then
                access.read = bad_hash
            elseif corruption == "revert root siblings" then
                access.sibling_hashes[1] = bad_hash
            else
                table.remove(log.accesses, revert_index)
            end
            expect.fail(function()
                machine:verify_reset_uarch(initial_hash, log)
            end)
        end)
    end
end)

describe("verify_step_uarch on a misaligned uarch pc", function()
    -- A before-state with a misaligned uarch pc, and a log of the reads that precede the instruction fetch
    local function new_misaligned_case()
        local machine <close> = build_default_machine()
        machine:write_reg("uarch_pc", machine:read_reg("uarch_pc") + 2)
        local root_hash = machine:get_root_hash()
        local log2_word_size = cartesi.HASH_TREE_LOG2_WORD_SIZE
        local function read_access(reg)
            local address = machine:get_reg_address(reg)
            local word_address = address & ~((1 << log2_word_size) - 1)
            local proof = machine:get_proof(word_address, log2_word_size)
            return {
                type = "read",
                address = address,
                log2_size = 3,
                read_hash = proof.target_hash,
                read = machine:read_memory(word_address, 1 << log2_word_size),
                sibling_hashes = proof.sibling_hashes,
            }
        end
        local log = {
            log_type = { has_annotations = false, has_large_data = false },
            accesses = { read_access("uarch_cycle"), read_access("uarch_halt"), read_access("uarch_pc") },
        }
        return root_hash, log
    end

    it("should reject the log instead of aborting", function()
        local root_hash, log = new_misaligned_case()
        expect.fail(function()
            cartesi.machine:verify_step_uarch(root_hash, log)
        end, "misaligned readUint32 address")
    end)

    it("should reject the log through a JSON-RPC server, which keeps serving", function()
        local jsonrpc = require("cartesi.jsonrpc")
        local remote <close> = jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN)
        local root_hash, log = new_misaligned_case()
        expect.fail(function()
            remote:verify_step_uarch(root_hash, log)
        end, "misaligned readUint32 address")
        expect.truthy(remote:get_server_version())
    end)
end)

describe("verification through a JSON-RPC machine object", function()
    local jsonrpc = require("cartesi.jsonrpc")
    local sibling_count_error = "access sibling hash count is inconsistent with proof size"
    local corruptions = {
        {
            "empty siblings",
            sibling_count_error,
            function(log)
                log.accesses[1].sibling_hashes = {}
            end,
        },
        {
            "missing siblings",
            sibling_count_error,
            function(log)
                change_sibling_count(log, -1)
            end,
        },
        {
            "extra siblings",
            sibling_count_error,
            function(log)
                change_sibling_count(log, 1)
            end,
        },
        {
            "written data on a read access",
            "unexpected written data in 1st access read access",
            function(log)
                log.accesses[1].written = log.accesses[1].read
            end,
        },
        {
            "written hash on a read access",
            "unexpected written hash in 1st access read access",
            function(log)
                log.accesses[1].written_hash = log.accesses[1].read_hash
            end,
        },
    }
    for _, corruption in ipairs(corruptions) do
        local name, expected_error, corrupt = table.unpack(corruption)
        it("should reject " .. name .. " in uarch step logs as the local verifier does", function()
            local remote <close> = jsonrpc.spawn_server():set_cleanup_call(jsonrpc.SHUTDOWN)
            local machine <close> = build_default_machine()
            local initial_hash = machine:get_root_hash()
            local log = machine:log_step_uarch()
            corrupt(log)
            expect.fail(function()
                remote:verify_step_uarch(initial_hash, log)
            end, expected_error)
        end)
    end
end)

lester.report()
lester.exit()
