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

-- Generates the send_cmio_response reject fixtures (keccak256). Run record-send-cmio-response.lua
-- first: it writes the base logs this script reads from --fixtures-dir, tampers, and writes to
-- --output-dir.
--
-- Only faults in the log bytes become rows. A fault in the data argument has no log to tamper --
-- an oversized response, or a length disagreeing with the log's node -- so each language tests
-- those directly instead.

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")
local manifest = require("cartesi.tests.step_log_manifest")

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function help()
    stderr("Usage: %s --fixtures-dir=<dir> --output-dir=<dir>\n", arg[0])
    os.exit()
end

local fixtures_dir, output_dir
for _, argument in ipairs(arg) do
    local f = argument:match("^%-%-fixtures%-dir%=(.*)$")
    local o = argument:match("^%-%-output%-dir%=(.*)$")
    if f then
        fixtures_dir = f
    elseif o then
        output_dir = o
    elseif argument == "-h" or argument == "--help" then
        help()
    else
        error("unrecognized option " .. argument)
    end
end
assert(fixtures_dir, "--fixtures-dir is required")
assert(output_dir, "--output-dir is required")

-- A small sub-page response (no node) drives the belief checks; a supra-page response
-- (carries a node summarising the padded write) drives the node post-hash check.
local CMIO_SMALL = fixtures_dir .. "/send-cmio-response/send-cmio-response-1.log"
local CMIO_SUPRA = fixtures_dir .. "/send-cmio-response/send-cmio-response-4097.log"
local CMIO_REASON = 1
local BOGUS = string.rep("\186", 32)
-- Must match the value record-send-cmio-response.lua stored in the base logs' revert-root-hash slot,
-- so the replay rewrites the same byte and the rejection fires on the injected fault, not a mismatch.
local REVERT_ROOT_HASH = string.rep("\xab", 32)

-- Payload mirrors the positive recorder: dataLength copies of 'a'.
local function payload(n)
    return ("a"):rep(n)
end

local function flip_first_byte(s)
    return string.char(s:byte(1) ~ 0xff) .. s:sub(2)
end

-- iflags.Y must be set for a cmio response; clearing its shadow word makes the replay a no-op.
local IFLAGS_Y_ADDR = cartesi.machine:get_reg_address("iflags_Y")
local IFLAGS_PAGE = IFLAGS_Y_ADDR >> 12
local IFLAGS_OFF = IFLAGS_Y_ADDR & 0xfff

local function clear_iflags_y(log)
    for _, page in ipairs(log.pages) do
        if page.index == IFLAGS_PAGE then
            page.data = page.data:sub(1, IFLAGS_OFF) .. string.rep("\0", 8) .. page.data:sub(IFLAGS_OFF + 9)
            return
        end
    end
    error("iflags page not found in cmio base log")
end

-- Claimed before/after roots for a base fixture, from its directory's manifest row.
local function base_claims(base_path)
    local dir, name = base_path:match("^(.*)/([^/]+)$")
    return manifest.read_claims(dir, name)
end

-- Each case: tag, base file, payload length, and a mutate(log) that tampers the log in
-- place and returns the claimed {before, after} the manifest hands the verifier.
local cases = {
    {
        tag = "root_before_mismatch",
        base = CMIO_SMALL,
        data_length = 1,
        mutate = function(_)
            return { before = BOGUS }
        end,
    },
    {
        tag = "root_after_mismatch",
        base = CMIO_SMALL,
        data_length = 1,
        mutate = function(_)
            return { after = BOGUS }
        end,
    },
    {
        tag = "root_before_mismatch",
        name = "cmio_node_tampered",
        base = CMIO_SUPRA,
        data_length = 4097,
        -- The node slot feeds the pre-root fold, so a tampered node hash no longer
        -- reconstructs the claimed root hash before.
        mutate = function(log)
            log.nodes[1].hash = flip_first_byte(log.nodes[1].hash)
        end,
    },
    {
        -- Clearing iflags.Y in a recorded cmio log makes the replay a no-op (send_cmio_response cannot
        -- fail), so the obtained post-state stays at the tampered pre-state and never matches the
        -- claimed root hash after. The forged "transition from a non-yielding machine" is rejected by
        -- the caller's comparison.
        tag = "root_after_mismatch",
        name = "cmio_iflags_cleared",
        base = CMIO_SMALL,
        data_length = 1,
        mutate = function(log)
            clear_iflags_y(log)
            return { before = test_util.recompute_step_log_root(log, "keccak256") }
        end,
    },
}

test_util.prepare_empty_output_dir(output_dir)
local out <close> = assert(io.open(output_dir .. "/" .. manifest.MANIFEST_NAME, "w"))
out:write(manifest.HEADER)

for _, case in ipairs(cases) do
    local log = test_util.read_step_log_file(case.base)
    local claims = base_claims(case.base)
    local claim = case.mutate(log) or {}
    local name = (case.name or case.tag) .. ".log"
    test_util.write_step_log_file(log, output_dir .. "/" .. name)
    manifest.write_row(out, {
        kind = "send_cmio_response",
        name = name,
        hash_function = "keccak256",
        requested_cycle_count = claims.cycle,
        initial_root_hash = claim.before or claims.before,
        final_root_hash = claim.after or claims.after,
        reason = CMIO_REASON,
        data_length = case.data_length,
        data = payload(case.data_length),
        revert_root_hash = REVERT_ROOT_HASH,
        expect_error = case.tag,
    })
    stderr("adversarial cmio: %-26s\n", case.tag)
end

stderr("\nwrote %d adversarial cmio step logs to %s\n", #cases, output_dir)
