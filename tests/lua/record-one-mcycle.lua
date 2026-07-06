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

-- Standalone generator for the single 1-mcycle machine step log the risc0
-- prove -> compress -> on-chain (Groth16) pipeline proves. A minimal zero-RAM machine
-- keeps it dependency-free (no images or test binaries): the first fetched instruction
-- traps, which is one well-defined mcycle. Defaults to sha256, the risc0 guest's hash.
--
-- Writes <output-dir>/one-mcycle.log plus <output-dir>/_manifest.csv.

local cartesi = require("cartesi")
local manifest_mod = require("cartesi.tests.step_log_manifest")
local test_util = require("cartesi.tests.util")

local function stderr(fmt, ...)
    io.stderr:write(string.format(fmt, ...))
end

local function help()
    stderr("Usage: %s --output-dir=<dir> [--hash-function=sha256|keccak256]\n", arg[0])
    os.exit()
end

local output_dir
local hash_function = "sha256"
for _, argument in ipairs(arg) do
    local o = argument:match("^%-%-output%-dir%=(.*)$")
    local h = argument:match("^%-%-hash%-function%=(.*)$")
    if o then
        output_dir = o
    elseif h then
        hash_function = h
    elseif argument == "-h" or argument == "--help" then
        help()
    else
        error("unrecognized option " .. argument)
    end
end
assert(output_dir, "--output-dir is required")

local machine <close> = assert(cartesi.machine({
    hash_tree = { hash_function = hash_function },
    ram = { length = 0x100000 },
    uarch = { ram = { backing_store = {} } },
}))

test_util.prepare_empty_output_dir(output_dir)
local name = "one-mcycle.log"
local log_path = output_dir .. "/" .. name
os.remove(log_path)

local ctx = {
    kind = "machine",
    name = name,
    hash_function = hash_function,
    requested_cycle_count = 1,
}
ctx.initial_root_hash = machine:get_root_hash()
machine:log_step(1, log_path)
ctx.final_root_hash = machine:get_root_hash()
cartesi.machine:verify_step(ctx.initial_root_hash, log_path, 1, ctx.final_root_hash)

local manifest <close> = assert(io.open(output_dir .. "/" .. manifest_mod.MANIFEST_NAME, "w"))
manifest:write(manifest_mod.HEADER)
manifest_mod.write_row(manifest, ctx)
stderr("\n1-mcycle step log written to %s\n", log_path)
