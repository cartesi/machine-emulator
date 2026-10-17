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

-- Shared step-log fixture manifest (CSV, one per fixture directory).
-- Every row is a call recipe plus an expected outcome: the arguments to pass to
-- the verifier and either success (blank expect_error) or the named rejection it
-- must revert with. For valid rows the columns are recorded truth, captured from
-- the live recording machine. For reject rows they are deliberately wrong call
-- arguments.
--
-- The cmio `data` column is the payload's repeat unit as plain ASCII: consumers
-- cycle it and trim to dataLength (full payloads are the identity case). Safe
-- only because the recorder controls the unit and emits no CSV-breaking byte
-- (comma, newline, or quote).

local M = {}

M.MANIFEST_NAME = "_manifest.csv"

-- Column order of every manifest row; the header line and row parsing derive from it.
local COLUMNS = {
    "kind",
    "name",
    "expectError",
    "hashFunction",
    "requestedCycleCount",
    "rootHashBefore",
    "rootHashAfter",
    "reason",
    "dataLength",
    "data",
    "revertRootHash",
}

M.HEADER = table.concat(COLUMNS, ",") .. "\n"

-- Local twins of cartesi.tohex/fromhex: risc0/Makefile runs this file as a CLI with bare lua5.4.
local function tohex(bytes)
    return "0x" .. (bytes:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local function fromhex(hex)
    return (hex:gsub("%x%x", function(byte)
        return string.char(tonumber(byte, 16))
    end))
end

-- Splits a row into fields keyed by column name.
local function parse_row(line)
    local fields = {}
    for field in (line .. ","):gmatch("([^,]*),") do
        fields[#fields + 1] = field
    end
    assert(#fields == #COLUMNS, "manifest row must have " .. #COLUMNS .. " columns")
    local row = {}
    for i, column in ipairs(COLUMNS) do
        row[column] = fields[i]
    end
    return row
end

-- Recorded cycle count and before/after roots (as binary) for the fixture named
-- `name`, from its directory's manifest row.
function M.read_claims(dir, name)
    local manifest = dir .. "/" .. M.MANIFEST_NAME
    local src <close> = assert(io.open(manifest, "r"))
    assert(src:read("L") == M.HEADER, "manifest schema mismatch in " .. manifest)
    for line in src:lines() do
        local row = parse_row(line)
        if row.name == name then
            local before = assert(row.rootHashBefore:match("^0x(%x+)$"), "malformed rootHashBefore for " .. name)
            local after = assert(row.rootHashAfter:match("^0x(%x+)$"), "malformed rootHashAfter for " .. name)
            return {
                cycle = tonumber(row.requestedCycleCount),
                before = fromhex(before),
                after = fromhex(after),
            }
        end
    end
    error("row for " .. name .. " not found in " .. manifest)
end

-- Columns inapplicable to a kind stay blank.
function M.format_row(ctx)
    return string.format(
        "%s,%s,%s,%s,%d,%s,%s,%s,%s,%s,%s\n",
        ctx.kind,
        ctx.name,
        ctx.expect_error or "",
        ctx.hash_function,
        ctx.requested_cycle_count,
        tohex(ctx.initial_root_hash),
        tohex(ctx.final_root_hash),
        ctx.reason and tostring(ctx.reason) or "",
        ctx.data_length and tostring(ctx.data_length) or "",
        ctx.data or "",
        ctx.revert_root_hash and tohex(ctx.revert_root_hash) or ""
    )
end

function M.write_row(out, ctx)
    out:write(M.format_row(ctx))
end

-- Parallel recording: each worker writes its row to its own file; the main process
-- concatenates the row files in caller order into the manifest.
function M.row_file_path(dir, key)
    return dir .. "/" .. key .. "-manifest-row.csv"
end

function M.write_row_file(dir, key, ctx)
    local out <close> = assert(io.open(M.row_file_path(dir, key), "w"))
    M.write_row(out, ctx)
end

-- Writes dir/_manifest.csv: header followed by each key's row file (consuming it).
function M.concat_row_files(dir, keys)
    local manifest <close> = assert(io.open(dir .. "/" .. M.MANIFEST_NAME, "w"))
    manifest:write(M.HEADER)
    for _, key in ipairs(keys) do
        local path = M.row_file_path(dir, key)
        local row_file <close> = assert(io.open(path, "rb"))
        manifest:write(row_file:read("*a"))
        os.remove(path)
    end
end

-- Run directly, this file is a CLI that prints a fixture's recorded claims as shell
-- assignments to eval:
--   lua5.4 step_log_manifest.lua claims <fixture-dir> <name>
if arg ~= nil and arg[0] ~= nil and arg[0]:find("step_log_manifest%.lua$") ~= nil then
    local command, fixture_dir, fixture_name = arg[1], arg[2], arg[3]
    if command ~= "claims" or fixture_dir == nil or fixture_name == nil then
        io.stderr:write("usage: lua5.4 step_log_manifest.lua claims <fixture-dir> <name>\n")
        os.exit(1)
    end
    local claims = M.read_claims(fixture_dir, fixture_name)
    io.write(
        "CYCLE_COUNT=",
        claims.cycle,
        "\nHASH_BEFORE=",
        tohex(claims.before):sub(3),
        "\nHASH_AFTER=",
        tohex(claims.after):sub(3),
        "\n"
    )
    os.exit(0)
end

return M
