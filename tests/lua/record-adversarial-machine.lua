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

-- Generates the big-machine (sha256) reject fixtures: recorded machine step logs tampered so the
-- shared replayer rejects them at decode. Replayed by the RISC0 guest and the C++/Lua host. Writes
-- <output-dir>/<case>.log plus <output-dir>/_manifest.csv.

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

-- A fixed base log: the mutations below assume its shape (multiple pages, many siblings), so the
-- base is chosen, not derived from the manifest. It is part of the full positive fixture set.
local BASE = fixtures_dir .. "/cartesi-machine-tests/step-rv64mi-p-access.log"
do
    local f = io.open(BASE, "rb")
    if not f then
        error(
            "adversarial base fixture not found: "
                .. BASE
                .. "\nGenerate the full fixture set first "
                .. "(a MACHINE_TEST filter that excludes rv64mi-p-access removes it)."
        )
    end
    f:close()
end

local cases = {
    {
        tag = "bad_signature",
        mutate = function(log)
            log.signature = "\0" .. log.signature:sub(2)
        end,
    },
    {
        tag = "unsupported_hash_function",
        mutate = function(log)
            log.hash_function = 99
        end, -- not keccak=0 / sha256=1
    },
    {
        tag = "nonzero_scratch_hash",
        mutate = function(log)
            log.pages[1].scratch_hash = string.rep("\255", 32)
        end,
    },
    {
        tag = "initial_root_mismatch",
        -- Tamper a page byte without re-rooting: the header's pre-root no longer matches.
        mutate = function(log)
            local p = log.pages[#log.pages]
            p.data = string.char(p.data:byte(1) ~ 0xff) .. p.data:sub(2)
        end,
    },
    {
        tag = "page_count_zero",
        -- A valid log always witnesses at least one page; an empty page set is malformed.
        mutate = function(log)
            log.pages = {}
        end,
    },
    {
        tag = "page_count_exceeds_size",
        -- Header claims far more pages than the body can hold.
        mutate = function(log)
            log.override_page_count = 0xffffffffff
        end,
    },
    {
        tag = "sibling_count_mismatch",
        -- Declared sibling count no longer matches the bytes left after pages and nodes.
        mutate = function(log)
            log.override_sibling_count = #log.siblings + 1
        end,
    },
    {
        tag = "page_index_not_increasing",
        -- Pages must be strictly ascending by index; duplicate the first index onto the second.
        mutate = function(log)
            log.pages[2].index = log.pages[1].index
        end,
    },
    {
        tag = "too_few_siblings",
        -- Drop a sibling the tree walk needs; the fold runs out of sibling hashes.
        mutate = function(log)
            table.remove(log.siblings)
        end,
    },
}

test_util.prepare_empty_output_dir(output_dir)
local out <close> = assert(io.open(output_dir .. "/" .. manifest.MANIFEST_NAME, "w"))
out:write(manifest.HEADER)

for _, case in ipairs(cases) do
    local log = test_util.read_step_log_file(BASE)
    case.mutate(log)
    local name = case.tag .. ".log"
    test_util.write_step_log_file(log, output_dir .. "/" .. name)
    manifest.write_row(out, {
        kind = "machine",
        name = name,
        hash_function = "sha256",
        requested_cycle_count = log.requested_cycle_count,
        initial_root_hash = log.root_hash_before,
        final_root_hash = log.root_hash_after,
        expect_error = case.tag,
    })
    stderr("adversarial machine: %-26s\n", case.tag)
end

stderr("\nwrote %d adversarial machine step logs to %s\n", #cases, output_dir)
