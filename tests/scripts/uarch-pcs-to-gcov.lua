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
Merges uarch PC coverage data into the gcov coverage report.

BACKGROUND

The coverage pipeline works as follows:

  1. The emulator is compiled with --coverage (gcc or clang), which
     instruments the host binary. Running the test suite produces .gcda files
     with execution counts.

  2. gcov (or llvm-cov gcov) reads the .gcda files and produces .gcov text
     files -- one per source file. Each .gcov file has header lines, function
     records, and one line per source line:

       "        -:    0:Source:interpret.cpp"                 (source filename)
       "function foo called 3 returned 100% ..."             (function record)
       "      123:   42:    x = y + z;"          (line 42 executed 123 times)
       "    #####:   43:    rare_path();"         (line 43 never executed)
       "        -:   44:    // comment"           (line 44 is not executable)

     The .gcov files are placed in the gcov-dir. Filenames use # in place of
     / for paths (e.g. ..#uarch#machine-uarch-bridge-state-access.h.gcov).
     gcovr requires function records to recognize lines as executable.

  3. gcovr reads the .gcov files (with --use-gcov-files) and produces the
     final HTML report and text summary.

THE PROBLEM

The emulator's interpret() function is compiled twice: once for the host (with
gcov instrumentation), and once for the uarch RISC-V binary (without
instrumentation). The host gcov report therefore misses code paths that are
only exercised inside the uarch -- most notably the bridge state access
(machine-uarch-bridge-state-access.h) and the failure branch of
verify_cold_tlb_slot().

THE SOLUTION

During test runs, we record the PC of every uarch instruction executed (one
hex address per line in .pcs files). This script resolves those PCs to
function/source/line triples via addr2line -f against the debug uarch-ram.elf,
then merges the results into the .gcov files before gcovr reads them:

  1. For source files that already have a .gcov file (e.g. interpret.cpp),
     lines marked as uncovered (#####) that were hit by the uarch are
     upgraded to show the uarch hit count. Lines already marked as executed
     by the host have the uarch count added to the existing count.

  2. For source files with no existing .gcov (e.g. the bridge header, which
     is only compiled into the uarch binary), a new .gcov file is created
     from scratch with function records and line hit counts. Non-hit lines
     are marked as non-executable (-) since we have no way to know which
     lines the compiler would consider executable.

Path resolution handles two cases: when the DWARF paths in the uarch ELF
match the local tree (direct prefix stripping), and when they differ (e.g.
the ELF was built inside Docker). In the latter case, paths are normalized
to resolve . and .. components, then matched by their tail after the last
/src/ or /uarch/ directory component. Files outside the project (e.g. C++
stdlib headers) are filtered out.

If addr2line is not available (e.g. no RISC-V toolchain installed), the
script exits gracefully and the coverage report is generated without the
uarch data.

Usage:
  lua5.4 uarch-pcs-to-gcov.lua <uarch-ram.elf> <pcs-dir> <gcov-dir>

  <uarch-ram.elf>  ELF with debug info (built with -g)
  <pcs-dir>        directory containing *.pcs files
  <gcov-dir>       directory containing .gcov files (also the gcovr --root)

Environment:
  ADDR2LINE    path to addr2line (default: riscv64-unknown-elf-addr2line)
]]

local elf = arg[1]
local pcs_dir = arg[2]
local gcov_dir = arg[3]

if not elf or not pcs_dir or not gcov_dir then
    io.stderr:write("Usage: lua5.4 uarch-pcs-to-gcov.lua <uarch-ram.elf> <pcs-dir> <gcov-dir>\n")
    os.exit(1)
end

local addr2line = os.getenv("ADDR2LINE") or "riscv64-unknown-elf-addr2line"

-- Check if addr2line is available; exit gracefully if not
if os.execute("command -v " .. addr2line .. " >/dev/null 2>&1") ~= true then
    io.stderr:write(string.format("uarch-pcs-to-gcov: %s not found, skipping uarch coverage merge\n", addr2line))
    os.exit(0)
end

-- Run a command via popen and return an iterator over its output lines
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

-- Given an iterator, return a new iterator that calls it twice per
-- iteration and returns both values as a pair
local function pairs_of(iter)
    return function()
        local a = iter()
        if not a then return nil end
        local b = iter()
        return a, b
    end
end

-- Normalize a path by resolving /. and /.. components (without touching the filesystem)
local function normalize_path(path)
    local absolute = path:sub(1, 1) == "/"
    local parts = {}
    local n = 0
    for part in path:gmatch("[^/]+") do
        if part == ".." and n > 0 and parts[n] ~= ".." then
            parts[n] = nil
            n = n - 1
        elseif part ~= "." then
            n = n + 1
            parts[n] = part
        end
    end
    local result = table.concat(parts, "/")
    return absolute and ("/" .. result) or result
end

-- Write a file from a table of lines (joined with newlines)
local function write_lines(path, lines)
    local f <close> = assert(io.open(path, "w"))
    f:write(table.concat(lines, "\n"), "\n")
end

io.stderr:write(string.format("uarch-pcs-to-gcov: elf=%s pcs_dir=%s gcov_dir=%s\n", elf, pcs_dir, gcov_dir))

-- Resolve gcov_dir to an absolute path so we can strip it from addr2line output
for line in popen("cd %s && pwd", gcov_dir) do
    gcov_dir = line
end
io.stderr:write(string.format("uarch-pcs-to-gcov: resolved gcov_dir=%s\n", gcov_dir))

-- Step 1: collect all unique PCs from all .pcs files
local pcs = {}
local pcs_files_count = 0
for pcs_file in popen("ls %s/*.pcs 2>/dev/null", pcs_dir) do
    pcs_files_count = pcs_files_count + 1
    for line in io.lines(pcs_file) do
        pcs[line] = true
    end
end

-- Write PCs to a temp file to avoid command-line length limits
local tmp = os.tmpname()
local pc_lines = {}
local n = 0
for pc in pairs(pcs) do
    n = n + 1
    pc_lines[n] = pc
end
write_lines(tmp, pc_lines)
pc_lines = nil
io.stderr:write(string.format("uarch-pcs-to-gcov: found %d .pcs files, %d unique PCs\n", pcs_files_count, n))

-- Step 2: resolve PCs to function:source:line via addr2line -f, accumulate hit counts
-- hits_by_file[relpath][lineno] = count
-- funcs_by_file[relpath][func_name] = { first_line, count }
local hits_by_file = {}
local funcs_by_file = {}
local prefix = gcov_dir .. "/"
local relpath_cache = {} -- cache absolute-path -> relative-path lookups

-- The project root is one level above gcov_dir (which is src/)
local project_root = normalize_path(gcov_dir .. "/..") .. "/"

-- With -f, addr2line outputs two lines per address: function name, then source:line
local function resolve_relpath(raw_source)
    local source = normalize_path(raw_source)
    local relpath = relpath_cache[source]
    if relpath == nil then
        if source:sub(1, #prefix) == prefix then
            -- Source is inside gcov_dir (src/): strip to bare filename
            relpath = source:sub(#prefix + 1)
        elseif source:sub(1, #project_root) == project_root then
            -- Source is inside the project but outside src/ (e.g. uarch/)
            local project_relpath = source:sub(#project_root + 1)
            if project_relpath:match("^uarch/") then
                relpath = "../" .. project_relpath
            end
        else
            -- DWARF path doesn't match local tree (e.g. built inside Docker).
            -- Extract the basename and check if it exists under src/ or uarch/.
            local basename = source:match("([^/]+)$")
            if basename then
                -- Try uarch/ first (more specific), then src/
                local f = io.open(gcov_dir .. "/../uarch/" .. basename, "r")
                if f then
                    f:close()
                    relpath = "../uarch/" .. basename
                else
                    f = io.open(gcov_dir .. "/" .. basename, "r")
                    if f then
                        f:close()
                        relpath = basename
                    end
                end
            end
        end
        -- Verify the file actually exists locally
        if relpath then
            local f = io.open(gcov_dir .. "/" .. relpath, "r")
            if f then
                f:close()
            else
                relpath = nil
            end
        end
        relpath_cache[source] = relpath or false
    end
    return relpath
end

for func_name, resolved in pairs_of(popen("%s -f -e %s < %s", addr2line, elf, tmp)) do
    -- Skip unresolved addresses
    if not func_name:match("^%?") and not resolved:match("^%?") then
        local raw_source, lineno = resolved:match("^(.+):(%d+)")
        if raw_source and lineno then
            lineno = tonumber(lineno)
            if lineno > 0 then
                local relpath = resolve_relpath(raw_source)
                if relpath then
                    if not hits_by_file[relpath] then
                        hits_by_file[relpath] = {}
                        funcs_by_file[relpath] = {}
                    end
                    hits_by_file[relpath][lineno] = (hits_by_file[relpath][lineno] or 0) + 1
                    -- Track function: remember first line and accumulate call count
                    local fi = funcs_by_file[relpath][func_name]
                    if fi then
                        fi.count = fi.count + 1
                        if lineno < fi.line then
                            fi.line = lineno
                        end
                    else
                        funcs_by_file[relpath][func_name] = { line = lineno, count = 1 }
                    end
                end
            end
        end
    end
end
os.remove(tmp)

-- Count resolved hits
local resolved_files = 0
local resolved_lines = 0
for relpath, line_hits in pairs(hits_by_file) do
    resolved_files = resolved_files + 1
    for _ in pairs(line_hits) do
        resolved_lines = resolved_lines + 1
    end
end
io.stderr:write(string.format("uarch-pcs-to-gcov: resolved to %d source files, %d unique source lines\n",
    resolved_files, resolved_lines))

-- Step 3: for each source file with hits, either patch the existing .gcov
-- file or create a new one

-- Convert a relative source path to the gcov filename convention:
-- gcov replaces / with # in the source path
local function gcov_path_for(relpath)
    return gcov_dir .. "/" .. relpath:gsub("/", "#") .. ".gcov"
end

for relpath, line_hits in pairs(hits_by_file) do
    local gcov_path = gcov_path_for(relpath)
    local gcov_file = io.open(gcov_path, "r")

    if gcov_file then
        -- Patch existing .gcov: add uarch hit counts.
        -- Each line in a .gcov file looks like:
        --   "    count:  lineno:source_text"   (executed line)
        --   "    #####:  lineno:source_text"   (unexecuted line)
        --   "        -:  lineno:source_text"   (non-executable line)
        -- For ##### lines, we replace with the uarch count.
        -- For already-executed lines, we add the uarch count to the existing count.
        local lines = {}
        local nlines = 0
        for line in gcov_file:lines() do
            nlines = nlines + 1
            -- Try matching an uncovered line
            local lno, rest = line:match("^%s*#####:%s*(%d+)(:.*)")
            if lno and line_hits[tonumber(lno)] then
                lines[nlines] = string.format("%9d:%5d%s", line_hits[tonumber(lno)], tonumber(lno), rest)
            else
                -- Try matching an already-executed line
                local host_count, lno2, rest2 = line:match("^%s*(%d+):%s*(%d+)(:.*)")
                if host_count and lno2 and line_hits[tonumber(lno2)] then
                    local total = tonumber(host_count) + line_hits[tonumber(lno2)]
                    lines[nlines] = string.format("%9d:%5d%s", total, tonumber(lno2), rest2)
                else
                    lines[nlines] = line
                end
            end
        end
        gcov_file:close()
        write_lines(gcov_path, lines)
        io.stderr:write(string.format("uarch-pcs-to-gcov: patched %s\n", gcov_path))
    else
        -- Create a new .gcov file for this source (uarch-only file).
        -- Read the source file and mark hit lines with their count.
        local src_path = gcov_dir .. "/" .. relpath
        local src_file <close> = io.open(src_path, "r")
        if src_file then
            local lines = { string.format("        -:    0:Source:%s", relpath) }
            local nlines = 1
            -- Add function records so gcovr recognizes executable lines
            local file_funcs = funcs_by_file[relpath] or {}
            for func_name, fi in pairs(file_funcs) do
                nlines = nlines + 1
                lines[nlines] = string.format("function %s called %d returned 100%% blocks executed 100%%", func_name, fi.count)
            end
            local lineno = 0
            for src_line in src_file:lines() do
                nlines = nlines + 1
                lineno = lineno + 1
                if line_hits[lineno] then
                    lines[nlines] = string.format("%9d:%5d:%s", line_hits[lineno], lineno, src_line)
                else
                    lines[nlines] = string.format("        -:%5d:%s", lineno, src_line)
                end
            end
            write_lines(gcov_path, lines)
            io.stderr:write(string.format("uarch-pcs-to-gcov: created %s\n", gcov_path))
        else
            io.stderr:write(string.format("uarch-pcs-to-gcov: source not found: %s\n", src_path))
        end
    end
end
