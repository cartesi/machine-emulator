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
-- the live recording machine -- not re-read from the log header, so a corrupted
-- header is caught (verifier Layer 2). For reject rows they are deliberately
-- wrong call arguments.
--
-- The cmio `data` column is the payload's repeat unit as plain ASCII: consumers
-- cycle it and trim to dataLength (full payloads are the identity case). Safe
-- only because the recorder controls the unit and emits no CSV-breaking byte
-- (comma, newline, or quote).

local M = {}

M.MANIFEST_NAME = "_manifest.csv"
M.HEADER = "kind,name,expectError,hashFunction,requestedCycleCount,rootHashBefore,rootHashAfter,reason,"
    .. "dataLength,data,revertRootHash\n"

local function hexhash(h)
    return (h:gsub(".", function(c)
        return string.format("%02x", string.byte(c))
    end))
end

-- Columns inapplicable to a kind stay blank. revert_root_hash is the value written to the
-- revert-root-hash shadow slot (cmio + reset rows). expect_error names the rejection a corrupt
-- fixture must trigger (the reject fixtures); blank means the log must replay successfully.
function M.format_row(ctx)
    return string.format(
        "%s,%s,%s,%s,%d,0x%s,0x%s,%s,%s,%s,%s\n",
        ctx.kind,
        ctx.name,
        ctx.expect_error or "",
        ctx.hash_function,
        ctx.requested_cycle_count,
        hexhash(ctx.initial_root_hash),
        hexhash(ctx.final_root_hash),
        ctx.reason and tostring(ctx.reason) or "",
        ctx.data_length and tostring(ctx.data_length) or "",
        ctx.data or "",
        ctx.revert_root_hash and ("0x" .. hexhash(ctx.revert_root_hash)) or ""
    )
end

function M.write_row(out, ctx)
    out:write(M.format_row(ctx))
end

-- Parallel-safe: each worker writes its own fragment; the main process
-- concatenates fragments in caller order into the manifest.
function M.fragment_path(dir, key)
    return dir .. "/" .. key .. "-manifest-fragment.csv"
end

function M.write_fragment(dir, key, ctx)
    local out <close> = assert(io.open(M.fragment_path(dir, key), "w"))
    M.write_row(out, ctx)
end

-- Writes dir/_manifest.csv: header followed by each key's fragment (consuming it).
function M.concat_fragments(dir, keys)
    local manifest <close> = assert(io.open(dir .. "/" .. M.MANIFEST_NAME, "w"))
    manifest:write(M.HEADER)
    for _, key in ipairs(keys) do
        local path = M.fragment_path(dir, key)
        local frag <close> = assert(io.open(path, "rb"))
        manifest:write(frag:read("*a"))
        os.remove(path)
    end
end

return M
