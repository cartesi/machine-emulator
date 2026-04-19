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
Converts a LuaCov stats file into a gcov-format .gcov file so that gcovr
--use-gcov-files can include Lua coverage alongside C/C++ coverage.

Follows the same conventions as uarch-pcs-to-gcov.lua: writes a .gcov file
per Lua source into gcov_dir so gcovr picks it up automatically via
--filter '$(abspath ../src)'.

Usage:
  lua5.4 luacov-to-gcov.lua <luacov.stats.out> <lua_source_path> <gcov_dir>

  luacov.stats.out  path to the stats file written by LuaCov
  lua_source_path   path to cartesi-machine.lua (used to read source text)
  gcov_dir          directory where .gcov files land (same as for C++ gcov)

If luacov.stats.out does not exist the script exits 0 with a warning,
leaving the rest of the coverage report unaffected.
--]]

local stats_path = arg[1]
local lua_source_path = arg[2]
local gcov_dir = arg[3]

if not lua_source_path or not gcov_dir then
	io.stderr:write("Usage: lua5.4 luacov-to-gcov.lua <luacov.stats.out> <lua_source_path> <gcov_dir>\n")
	os.exit(1)
end

-- Graceful exit when stats file is missing or unset (e.g. coverage not run yet)
local function file_exists(path)
	local f = io.open(path, "r")
	if f then
		f:close()
		return true
	end
	return false
end

if not stats_path or stats_path == "" or not file_exists(stats_path) then
	if stats_path and stats_path ~= "" then
		io.stderr:write(string.format("luacov-to-gcov: %s not found, skipping Lua coverage merge\n", stats_path))
	end
	os.exit(0)
end

-- Load LuaCov stats. Returns a table keyed by source path; each value is
-- a table mapping line_number (integer) -> hit_count (integer).
local stats = require("luacov.stats").load(stats_path)
if not stats then
	io.stderr:write(string.format("luacov-to-gcov: failed to load stats from %s\n", stats_path))
	os.exit(0)
end

-- Find the stats entry whose basename matches cartesi-machine.lua.
-- LuaCov may record an absolute or a relative path depending on how the
-- script was invoked; we match on basename to be robust.
local target_basename = lua_source_path:match("[^/]+$")
local line_hits
for path, hits in pairs(stats) do
	if path:match("[^/]+$") == target_basename then
		line_hits = hits
		break
	end
end

if not line_hits then
	io.stderr:write(string.format("luacov-to-gcov: no stats entry matching '%s', skipping\n", target_basename))
	os.exit(0)
end

-- Read source lines from the Lua file
local src_file = io.open(lua_source_path, "r")
if not src_file then
	io.stderr:write(string.format("luacov-to-gcov: cannot open source %s\n", lua_source_path))
	os.exit(0)
end
local source_lines = {}
for line in src_file:lines() do
	source_lines[#source_lines + 1] = line
end
src_file:close()

-- Find all executable lines using luac5.4 -l.
-- luac does not execute the file so no runtime dependencies are needed.
-- Lines that appear in the bytecode listing are executable; those not in
-- line_hits and not executable get '-', those executable but not hit get '#####'.
local executable_lines = {}
do
	local cmd = string.format("luac5.4 -l -l %q 2>/dev/null", lua_source_path)
	local f = io.popen(cmd)
	if f then
		for luac_line in f:lines() do
			local n = luac_line:match("%[(%d+)%]")
			if n then executable_lines[tonumber(n)] = true end
		end
		f:close()
	end
end

-- Convert a relative source path to the gcov filename convention:
-- gcov replaces / with # in the source path.  We use the basename only
-- since gcov_dir already contains the source tree root.
local function gcov_path_for(relpath)
	return gcov_dir .. "/" .. relpath:gsub("/", "#") .. ".gcov"
end

-- Compute the relative path of the Lua source under gcov_dir.
-- If the source path begins with gcov_dir, strip that prefix.
-- Otherwise use just the basename.
local rel_source
do
	local abs_gcov = gcov_dir:gsub("([%.%+%-%*%?%[%]%^%$%(%)%%])", "%%%1")
	rel_source = lua_source_path:match("^" .. abs_gcov .. "/(.+)$") or target_basename
end

local gcov_path = gcov_path_for(rel_source)

-- Count total hits for the function record header
local total_hits = 0
for _, count in pairs(line_hits) do
	total_hits = total_hits + count
end

-- Write the .gcov file
local out_lines = {}

-- Header line: gcov convention for source identification
out_lines[#out_lines + 1] = string.format("        -:    0:Source:%s", rel_source)

-- Function record: required so gcovr counts executable lines correctly.
-- Use the basename (without extension) as the synthetic function name.
local func_name = target_basename:gsub("%.lua$", "")
out_lines[#out_lines + 1] =
	string.format("function %s called %d returned 100%% blocks executed 100%%", func_name, total_hits > 0 and 1 or 0)

-- Per-line records
for lineno, src_line in ipairs(source_lines) do
	local count = line_hits[lineno]
	if count and count > 0 then
		out_lines[#out_lines + 1] = string.format("%9d:%5d:%s", count, lineno, src_line)
	elseif executable_lines[lineno] then
		out_lines[#out_lines + 1] = string.format("    #####:%5d:%s", lineno, src_line)
	else
		out_lines[#out_lines + 1] = string.format("        -:%5d:%s", lineno, src_line)
	end
end

-- Write the output file
local out_file = assert(io.open(gcov_path, "w"))
out_file:write(table.concat(out_lines, "\n"))
out_file:write("\n")
out_file:close()

io.stderr:write(
	string.format(
		"luacov-to-gcov: wrote %s (%d source lines, %d tracked)\n",
		gcov_path,
		#source_lines,
		(function()
			local n = 0
			for _ in pairs(line_hits) do
				n = n + 1
			end
			return n
		end)()
	)
)
