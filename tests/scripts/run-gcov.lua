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
Runs gcov on each .gcda file and merges the results into one .gcov per source.

The original motivation for this script is that llvm-cov gcov overwrites .gcov
files when processing multiple .gcda that share headers, losing coverage data
from earlier runs. Both gcov commands (GNU "gcov" and "llvm-cov gcov") support
-t, which prints the report to stdout and writes nothing to disk, so the
overwrite cannot happen for either tool. We parse that stream instead of reading
files back. The merge sums execution counts per line, so it is associative and
commutative: the result does not depend on the order or grouping of the .gcda.

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

local function basename(path)
    return (path:match("([^/]+)$"))
end

local function write_lines(path, lines)
    local f <close> = assert(io.open(path, "w"))
    f:write(table.concat(lines, "\n"), "\n")
end

-- Feed a sequence of gcov text lines into the `merged` accumulator. A line of
-- the form "-:0:Source:<path>" starts a new source file's section; subsequent
-- lines accumulate into it until the next Source line. This handles both the
-- multi-file gcov -t stream and a single partial .gcov file the same way.
local function merge_stream(lines, merged)
    local m -- current source file's merge table
    for line in lines do
        -- Parse the line number from the gcov format: "count:lineno:text"
        local lineno_str = line:match("^[^:]*:%s*(%d+):")
        local lineno = lineno_str and tonumber(lineno_str)

        if not lineno or lineno == 0 then
            -- Header line (Source:, Graph:, Data:, Runs:) or function record.
            local src = line:match("^%s*%-:%s*0:Source:(.*)$")
            if src then
                -- Start of a new source file. gcov names output by basename, so
                -- key by it to match the .gcov filenames produced on disk.
                local key = basename(src) .. ".gcov"
                m = merged[key]
                if not m then
                    m = { headers = {}, source_lines = {}, max_lineno = 0 }
                    merged[key] = m
                end
                -- Keep the Source: header from the first version seen.
                if #m.headers == 0 then
                    m.headers[1] = line
                end
            elseif m and line:match("^function ") then
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
            -- Skip Graph:, Data:, Runs:, branch lines, and anything before the
            -- first Source line.
        elseif m then
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
end

-- Run gcov on each .gcda (a basename in src_dir, or an absolute path)
-- and merge the streamed output into one table. gcov runs from src_dir so
-- Source: paths, filenames, and source text are consistent.
local function process_files(gcda_files)
    local merged = {}
    for _, gcda in ipairs(gcda_files) do
        merge_stream(popen(
            "cd %s && %s -t --demangled-names --relative-only --branch-probabilities %s 2>/dev/null",
            src_dir, gcov_cmd, gcda
        ), merged)
    end
    return merged
end

-- Write the merged .gcov files into out_dir, returning how many were produced.
local function write_merged(merged, out_dir)
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
                -- Line not seen in any .gcov: mark as non-executable
                lines[nlines] = string.format("        -:%5d:", lineno)
            end
        end
        write_lines(out_dir .. "/" .. gcov_name, lines)
    end
    return file_count
end

-- Collect the .gcda basenames found in src_dir.
local gcda_files = {}
local n = 0
for f in popen("ls %s/*.gcda 2>/dev/null", src_dir) do
    n = n + 1
    gcda_files[n] = basename(f)
end

if n == 0 then
    io.stderr:write("run-gcov: no .gcda files found, skipping C/C++ coverage merge\n")
    os.exit(0)
end

local file_count = write_merged(process_files(gcda_files), src_dir)

io.stderr:write(string.format("run-gcov: processed %d .gcda files, produced %d .gcov files\n", n, file_count))
