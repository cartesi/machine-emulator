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

-- Records the send_cmio_response step-log fixtures (5 payload sizes) + their _manifest.csv.
-- Fixtures use keccak256, the Solidity verifier's hash function.
--
-- Writes <output-dir>/{send-cmio-response-<size>.log, _manifest.csv}.

local cartesi = require("cartesi")
local manifest_mod = require("cartesi.tests.step_log_manifest")
local test_util = require("cartesi.tests.util")

local HASH_FUNCTION = "keccak256"

-- Fixed sentinel revert root hash stored in the revert-root-hash shadow slot. Tests assert it
-- round-trips through the send_cmio_response post-state.
local REVERT_ROOT_HASH = string.rep("\xab", 32)

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function help()
    stderr("Usage: %s --output-dir=<dir>\n", arg[0])
    os.exit()
end

local output_dir
for _, argument in ipairs(arg) do
    local o = argument:match("^%-%-output%-dir%=(.*)$")
    if o then
        output_dir = o
    elseif argument == "-h" or argument == "--help" then
        help()
    else
        error("unrecognized option " .. argument)
    end
end
assert(output_dir, "--output-dir is required")

local function build_machine()
    return assert(cartesi.machine({
        ram = { length = 0x20000 },
        uarch = { ram = { backing_store = {} } },
    }))
end

-- Records one send_cmio_response step log of `data_length` bytes. The payload is a
-- repeated ASCII pattern; the Solidity verifier hashes it on-chain via
-- HashTree.merkleTreeHashPadded.
-- An advance-state reason additionally exercises the imcyclemax budget grant in the
-- transpiled verifier; a near-max mcycle exercises the grant's saturation arm.
local function create_send_cmio_response_step_log(data_length, label, reason, mcycle)
    local machine <close> = build_machine()
    local data = string.rep("a", data_length)
    -- Seed the rx-buffer page non-zero so a replayer that skips zero-padding can't match the
    -- post-state hash by coincidence.
    machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, string.rep("X", 4096))
    local name = "send-cmio-response-" .. label .. ".log"
    local log_path = output_dir .. "/" .. name
    os.remove(log_path)
    if mcycle then machine:write_reg("mcycle", mcycle) end
    machine:write_reg("iflags_Y", 1)
    reason = reason or 1
    local ctx = {
        kind = "send_cmio_response",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = 0,
        reason = reason,
        data = data,
        data_length = #data,
        revert_root_hash = REVERT_ROOT_HASH,
    }
    ctx.initial_root_hash = machine:get_root_hash()
    machine:log_send_cmio_response(REVERT_ROOT_HASH, reason, data, log_path)
    ctx.final_root_hash = machine:get_root_hash()
    cartesi.machine:verify_send_cmio_response(
        REVERT_ROOT_HASH,
        reason,
        data,
        ctx.initial_root_hash,
        log_path,
        ctx.final_root_hash
    )
    return ctx
end

-- Records a no-op send_cmio_response: a response to a machine that yielded manual and rejected the
-- previous input leaves the state unchanged. Exercises the transpiled no-op path in the Solidity verifier.
local function create_send_cmio_response_noop_step_log()
    local machine <close> = build_machine()
    local data = "This is a test cmio response"
    local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    machine:write_reg("iflags_Y", 1)
    machine:write_reg("htif_tohost_dev", cartesi.HTIF_DEV_YIELD)
    machine:write_reg("htif_tohost_cmd", cartesi.HTIF_YIELD_CMD_MANUAL)
    machine:write_reg("htif_tohost_reason", cartesi.HTIF_YIELD_MANUAL_REASON_RX_REJECTED)
    local name = "send-cmio-response-noop.log"
    local log_path = output_dir .. "/" .. name
    os.remove(log_path)
    local ctx = {
        kind = "send_cmio_response",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = 0,
        reason = reason,
        data = data,
        data_length = #data,
        revert_root_hash = REVERT_ROOT_HASH,
    }
    ctx.initial_root_hash = machine:get_root_hash()
    machine:log_send_cmio_response(REVERT_ROOT_HASH, reason, data, log_path)
    ctx.final_root_hash = machine:get_root_hash()
    assert(ctx.final_root_hash == ctx.initial_root_hash, "no-op must leave the root hash unchanged")
    cartesi.machine:verify_send_cmio_response(
        REVERT_ROOT_HASH,
        reason,
        data,
        ctx.initial_root_hash,
        log_path,
        ctx.final_root_hash
    )
    return ctx
end

-- Sizes spanning the boundaries the Solidity verifier dispatches on:
--   0      -- skips the rx-buffer write entirely (iflags.Y still flips).
--   1      -- sub-leaf payload, smallest non-empty write.
--   4096   -- one page exactly; sub-page path top boundary.
--   4097   -- mixed supra-page payload (page + 1 spilling into the next page).
--   65536  -- aligned supra-page payload covering 16 pages.
local CMIO_FIXTURE_SIZES = {
    { 0, "0" },
    { 1, "1" },
    { 4096, "4096" },
    { 4097, "4097" },
    { 65536, "65536" },
}

test_util.prepare_empty_output_dir(output_dir)
local manifest <close> = assert(io.open(output_dir .. "/" .. manifest_mod.MANIFEST_NAME, "w"))
manifest:write(manifest_mod.HEADER)
-- A response larger than the rx buffer replays as a pure no-op: the verifier returns
-- before touching any state, including the advance-state budget grant. The manifest
-- stores only the repeat unit; dataLength tells the replayer how far to expand it.
local function create_oversized_send_cmio_response_step_log()
    local machine <close> = build_machine()
    local data = string.rep("a", (1 << cartesi.AR_CMIO_RX_BUFFER_LOG2_SIZE) + 1)
    machine:write_memory(cartesi.AR_CMIO_RX_BUFFER_START, string.rep("X", 4096))
    local name = "send-cmio-response-oversized.log"
    local log_path = output_dir .. "/" .. name
    os.remove(log_path)
    machine:write_reg("iflags_Y", 1)
    local reason = cartesi.HTIF_YIELD_REASON_ADVANCE_STATE
    local ctx = {
        kind = "send_cmio_response",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = 0,
        reason = reason,
        data = "a",
        data_length = #data,
        revert_root_hash = REVERT_ROOT_HASH,
    }
    ctx.initial_root_hash = machine:get_root_hash()
    machine:log_send_cmio_response(REVERT_ROOT_HASH, reason, data, log_path)
    ctx.final_root_hash = machine:get_root_hash()
    assert(ctx.initial_root_hash == ctx.final_root_hash, "oversized response must be a no-op")
    cartesi.machine:verify_send_cmio_response(
        REVERT_ROOT_HASH,
        reason,
        data,
        ctx.initial_root_hash,
        log_path,
        ctx.final_root_hash
    )
    return ctx
end

for _, sz in ipairs(CMIO_FIXTURE_SIZES) do
    manifest_mod.write_row(manifest, create_send_cmio_response_step_log(sz[1], sz[2]))
end
manifest_mod.write_row(
    manifest,
    create_send_cmio_response_step_log(32, "advance-grant", cartesi.HTIF_YIELD_REASON_ADVANCE_STATE)
)
manifest_mod.write_row(
    manifest,
    create_send_cmio_response_step_log(32, "advance-grant-saturated", cartesi.HTIF_YIELD_REASON_ADVANCE_STATE, -1)
)
manifest_mod.write_row(manifest, create_send_cmio_response_noop_step_log())
manifest_mod.write_row(manifest, create_oversized_send_cmio_response_step_log())
stderr("\nsend_cmio_response step logs (%d sizes + no-op) written to %s\n", #CMIO_FIXTURE_SIZES, output_dir)
