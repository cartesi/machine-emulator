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

-- Records one valid multi-cycle uarch step log that the Solidity verifier must reject. The log
-- replays correctly in C++ (self-verified here via verify_step_uarch), but Verify.verifyStep is
-- scoped to exactly one uarch step, so it rejects this log with RequestedCycleCountMustBeOne. The
-- log is valid, not adversarial -- it documents the on-chain single-step scope boundary.
-- Fixtures use keccak256, the Solidity verifier's hash function.
--
-- Writes <output-dir>/{two-cycle.log, _manifest.csv}.

local cartesi = require("cartesi")
local test_util = require("cartesi.tests.util")
local manifest_mod = require("cartesi.tests.step_log_manifest")

local HASH_FUNCTION = "keccak256"
local CYCLE_COUNT = 2

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

local function create_two_cycle_uarch_step_log()
    local machine <close> = build_machine()
    local name = "two-cycle.log"
    local log_path = output_dir .. "/" .. name
    local initial_root_hash = machine:get_root_hash()
    local status = machine:log_step_uarch(CYCLE_COUNT, log_path)
    assert(
        status == cartesi.UARCH_BREAK_REASON_REACHED_TARGET_UARCH_CYCLE,
        "expected the uarch to advance the full cycle budget, not halt early"
    )
    local final_root_hash = machine:get_root_hash()
    -- Valid in C++: a multi-cycle log replays and verifies. Solidity rejects it only on scope.
    assert(cartesi.machine:verify_step_uarch(initial_root_hash, log_path, CYCLE_COUNT) == final_root_hash)
    return {
        kind = "program",
        name = name,
        hash_function = HASH_FUNCTION,
        requested_cycle_count = CYCLE_COUNT,
        initial_root_hash = initial_root_hash,
        final_root_hash = final_root_hash,
    }
end

test_util.prepare_empty_output_dir(output_dir)
local out <close> = assert(io.open(output_dir .. "/" .. manifest_mod.MANIFEST_NAME, "w"))
out:write(manifest_mod.HEADER)
manifest_mod.write_row(out, create_two_cycle_uarch_step_log())
stderr("wrote a %d-cycle solidity-scope uarch step log to %s\n", CYCLE_COUNT, output_dir)
