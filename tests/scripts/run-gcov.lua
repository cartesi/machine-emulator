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

--[[
Runs gcov on each .gcda file individually and merges the resulting .gcov files.

llvm-cov gcov overwrites .gcov files when processing multiple .gcda files that
share headers, losing coverage data from earlier runs. This script works around
the problem by processing each .gcda separately, saving the .gcov files aside
after each run, then merging all versions by taking the maximum count per line.

GNU gcov does not have this problem (it accumulates counts), but this script
works correctly with both.

Usage:
  lua5.4 run-gcov.lua <src-dir> <gcov-command>

  <src-dir>       directory containing .gcda files (output .gcov files go here)
  <gcov-command>  gcov command to use (e.g. "gcov" or "llvm-cov gcov")
]]

local src_dir = arg[1]
local gcov_cmd = arg[2]

if not src_dir or not gcov_cmd then
    io.stderr:write("Usage: lua5.4 run-gcov.lua <src-dir> <gcov-command>\n")
    os.exit(1)
end

local function popen(fmt, ...)
    local cmd = string.format(fmt, ...)
    local pipe = assert(io.popen(cmd))
    return function()
        local line = pipe:read("*l")
        if not line then
            pipe:close()
        end
        return line
    end
end

local function write_lines(path, lines)
    local f <close> = assert(io.open(path, "w"))
    f:write(table.concat(lines, "\n"), "\n")
end

-- Collect all .gcda basenames
local gcda_files = {}
local n = 0
for f in popen("ls %s/*.gcda 2>/dev/null", src_dir) do
    n = n + 1
    gcda_files[n] = f:match("([^/]+)$")
end

if n == 0 then
    io.stderr:write("run-gcov: no .gcda files found\n")
    os.exit(1)
end

-- Per source file, we track:
--   headers: array of header/function lines (lines with lineno 0 or "function" prefix)
--   source_lines: { [lineno] = { text = "...", count = number|nil } }
--   max_lineno: highest line number seen
local merged = {}

-- Process each .gcda file from src_dir
for _, gcda in ipairs(gcda_files) do
    -- Run gcov from src_dir so Source: paths and filenames are consistent
    os.execute(string.format(
        "cd %s && %s --demangled-names --relative-only --branch-probabilities %s 2>/dev/null >/dev/null",
        src_dir, gcov_cmd, gcda
    ))

    -- Read and merge each .gcov file produced
    for gcov_path in popen("ls %s/*.gcov 2>/dev/null", src_dir) do
        local gcov_name = gcov_path:match("([^/]+)$")

        if not merged[gcov_name] then
            merged[gcov_name] = { headers = {}, source_lines = {}, max_lineno = 0 }
        end
        local m = merged[gcov_name]

        for line in io.lines(gcov_path) do
            -- Parse the line number from the gcov format: "count:lineno:text"
            local lineno_str = line:match("^[^:]*:%s*(%d+):")
            local lineno = lineno_str and tonumber(lineno_str)

            if not lineno or lineno == 0 then
                -- Header line (Source:, Graph:, Data:, Runs:) or function record.
                -- Keep Source: from the first version; skip duplicates of others.
                if line:match("^%s*%-:%s*0:Source:") then
                    if #m.headers == 0 then
                        m.headers[1] = line
                    end
                elseif line:match("^function ") then
                    -- Accumulate unique function records
                    local func_name = line:match("^function (%S+)")
                    local already = false
                    for _, h in ipairs(m.headers) do
                        if h:match("^function " .. func_name:gsub("([%(%)%.%+%-%*%?%[%]%^%$%%])", "%%%1") .. " ") then
                            already = true
                            break
                        end
                    end
                    if not already then
                        m.headers[#m.headers + 1] = line
                    end
                end
                -- Skip Graph:, Data:, Runs: lines
            else
                -- Source line: merge by adding counts
                if lineno > m.max_lineno then
                    m.max_lineno = lineno
                end
                local existing = m.source_lines[lineno]
                local count = line:match("^%s*(%d+):")
                local new_count = count and tonumber(count)
                -- Extract the source text after "count:lineno:"
                local rest = line:match("^[^:]*:%s*%d+:(.*)")

                if not existing then
                    m.source_lines[lineno] = { text = line, count = new_count, rest = rest }
                elseif new_count then
                    if existing.count then
                        -- Both have counts: add them
                        existing.count = existing.count + new_count
                        existing.text = string.format("%9d:%5d:%s", existing.count, lineno, existing.rest or "")
                    else
                        -- New has count, existing doesn't: use new
                        existing.text = line
                        existing.count = new_count
                        existing.rest = rest
                    end
                elseif not existing.count then
                    -- Both uncovered: prefer ##### over -
                    if line:match("^%s*#####:") and existing.text:match("^%s*%-:") then
                        existing.text = line
                    end
                end
            end
        end

        -- Remove the .gcov file so it doesn't interfere with the next .gcda
        os.remove(gcov_path)
    end
end

-- Write merged .gcov files back to src_dir
local file_count = 0
for gcov_name, m in pairs(merged) do
    file_count = file_count + 1
    local lines = {}
    local nlines = 0
    -- Write headers first
    for _, h in ipairs(m.headers) do
        nlines = nlines + 1
        lines[nlines] = h
    end
    -- Write source lines in order
    for lineno = 1, m.max_lineno do
        nlines = nlines + 1
        if m.source_lines[lineno] then
            lines[nlines] = m.source_lines[lineno].text
        else
            -- Line not seen in any .gcov — mark as non-executable
            lines[nlines] = string.format("        -:%5d:", lineno)
        end
    end
    write_lines(src_dir .. "/" .. gcov_name, lines)
end

io.stderr:write(string.format("run-gcov: processed %d .gcda files, produced %d .gcov files\n", n, file_count))
