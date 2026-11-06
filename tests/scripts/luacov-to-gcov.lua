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
Merges LuaCov stats files into a gcov-format .gcov file so that gcovr
--use-gcov-files can include Lua coverage alongside C/C++ coverage.

Follows the same conventions as uarch-pcs-to-gcov.lua: writes a .gcov file
per Lua source into gcov_dir so gcovr picks it up automatically via
--filter '$(abspath ../src)'.

Usage:
  lua5.4 luacov-to-gcov.lua <lua_source_path> <gcov_dir> [luacov.stats.out ...]

  lua_source_path   path to cartesi-machine.lua (used to read source text)
  gcov_dir          directory where .gcov files land (same as for C++ gcov)
  luacov.stats.out  paths to the stats files written by LuaCov

If no stats files are supplied the script exits 0 with a warning,
leaving the rest of the coverage report unaffected.
--]]

local lua_source_path = arg[1]
local gcov_dir = arg[2]

if not lua_source_path or not gcov_dir then
	io.stderr:write("Usage: lua5.4 luacov-to-gcov.lua <lua_source_path> <gcov_dir> [luacov.stats.out ...]\n")
	os.exit(1)
end

if not arg[3] then
	io.stderr:write("luacov-to-gcov: no stats files, skipping Lua coverage merge\n")
	os.exit(0)
end

-- Sum line counts across all shards, excluding LuaCov's max/max_hits metadata.
-- LuaCov may record an absolute or a relative path depending on how the
-- script was invoked; we match on basename to be robust.
local stats = require("luacov.stats")
local target_basename = lua_source_path:match("[^/]+$")
local line_hits = {}
for i = 3, #arg do
	local data = assert(stats.load(arg[i]), "failed to load LuaCov stats from " .. arg[i])
	for path, hits in pairs(data) do
		if path:match("[^/]+$") == target_basename then
			for line, count in pairs(hits) do
				if type(line) == "number" then
					line_hits[line] = (line_hits[line] or 0) + count
				end
			end
		end
	end
end

if not next(line_hits) then
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
