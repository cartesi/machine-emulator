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

local utils = require("cartesi.utils")

-- Module providing helpers for filesystem operations.
local filesystem = {}

-- Creates a temporary filename (an empty file is also created).
function filesystem.temp_filename()
    return (assert(os.tmpname()))
end

-- Returns a temporary path name (without creating a file or directory).
function filesystem.temp_pathname()
    local pathname = assert(os.tmpname())
    assert(os.remove(pathname))
    return pathname
end

-- Reads binary data from a file.
function filesystem.read_file(filename)
    local f <close> = assert(io.open(filename, "rb"))
    return (assert(f:read("a")))
end

-- Writes a binary data to a new file (the file is overwritten if it exists).
function filesystem.write_file(filename, data)
    local f <close> = assert(io.open(filename, "wb"))
    assert(f:write(data))
end

-- Returns the size of a file in bytes.
function filesystem.get_file_size(filename)
    local f <close> = assert(io.open(filename, "rb"))
    return (assert(f:seek("end")))
end

-- Writes a binary data to a temporary file.
function filesystem.write_temp_file(data)
    local filename = filesystem.temp_filename()
    local ok, err = pcall(function()
        filesystem.write_file(filename, data)
    end)
    if not ok then
        os.remove(filename)
    end
    assert(ok, err)
    return filename
end

-- Writes a binary data to a temporary file that is auto removed when scoped ends.
function filesystem.write_scope_temp_file(data)
    local filename = filesystem.write_temp_file(data)
    return utils.scope_exit(function()
        filesystem.remove_file(filename)
    end), filename
end

-- Removes a file.
function filesystem.remove_file(filename)
    assert(os.remove(filename))
end

return filesystem
