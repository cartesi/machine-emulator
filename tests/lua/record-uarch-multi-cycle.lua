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

-- Records a pair of valid uarch step logs from the same starting state: one covering a single
-- cycle, one covering two. Both replay and self-verify in C++. The Solidity verifier runs exactly
-- one uarch step, so replaying the two-cycle log on chain must land on the one-cycle log's root.
-- That is the property VerifyUarchMultiCycle pins; neither log is adversarial.
-- Fixtures use keccak256, the Solidity verifier's hash function.
--
-- Writes <output-dir>/{one-cycle.log, two-cycle.log, _manifest.csv}.

local cartesi = require("cartesi")
local util = require("cartesi.util")
local test_util = require("cartesi.tests.util")
local manifest_mod = require("cartesi.tests.step_log_manifest")

local HASH_FUNCTION = "keccak256"
local LOGS = { { 1, "one-cycle.log" }, { 2, "two-cycle.log" } }

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

local function record(cycle_count, name)
    local machine <close> = build_machine()
    local log_path = output_dir .. "/" .. name
    local initial_root_hash = machine:get_root_hash()
    local log, status = machine:log_step_uarch(cycle_count)
    assert(
        status == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE,
        "expected the uarch to advance the full cycle budget, not halt early"
    )
    local final_root_hash = machine:get_root_hash()
    assert(cartesi.machine:verify_step_uarch(initial_root_hash, log, cycle_count) == final_root_hash)
    util.write_file(log, log_path)
    return {
        kind = "cycle",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = cycle_count,
        initial_root_hash = initial_root_hash,
        final_root_hash = final_root_hash,
    }
end

test_util.prepare_empty_output_dir(output_dir)
local out <close> = assert(io.open(output_dir .. "/" .. manifest_mod.MANIFEST_NAME, "w"))
out:write(manifest_mod.HEADER)
for _, entry in ipairs(LOGS) do
    manifest_mod.write_row(out, record(entry[1], entry[2]))
end
stderr("wrote %d uarch step logs to %s\n", #LOGS, output_dir)
