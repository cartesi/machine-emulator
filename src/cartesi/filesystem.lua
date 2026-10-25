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

local core = require("cartesi.filesystem.core")

-- Module providing helpers for filesystem operations. Nothing here syncs implicitly. To make a
-- file durable, write it under a temporary name, sync it, rename it into place, and sync its
-- directory, which can be done once for a batch of files.
local filesystem = {}

-- Returns true when a file or directory exists.
filesystem.exists = core.exists

-- Creates a directory, whose parent must exist.
filesystem.create_directory = core.create_directory

-- Returns the names of a directory's entries in lexicographic order.
filesystem.list_directory = core.list_directory

-- Clones a file into a new path, which must not exist. A read-only file is hard linked, a writable
-- file is reflinked, and a copy is made when the filesystem supports neither.
filesystem.clone_file = core.clone_file

-- Truncates or extends an existing file to a size, filling an extension with zeros.
filesystem.truncate_file = core.truncate_file

-- Flushes the contents of an open file, after its buffer, or of the file at a path to permanent
-- storage.
filesystem.sync_file = core.sync_file

local temporary_file_meta = { __index = {} }

-- Moves the file to its final path, after closing it. Closing the object then leaves it in place.
function temporary_file_meta.__index:rename(to)
    self.file:close()
    filesystem.rename_file(self.path, to)
    self.path = nil
end

function temporary_file_meta.__index:close()
    if io.type(self.file) == "file" then self.file:close() end
    if self.path then
        filesystem.remove_file(self.path)
        self.path = nil
    end
end
temporary_file_meta.__close = temporary_file_meta.__index.close
temporary_file_meta.__gc = temporary_file_meta.__index.close

-- Creates a file with a unique name starting with prefix, in a directory, usually the one it will
-- be renamed into. The returned object holds the open file in file and its name in path. Closing
-- the object removes the file unless rename moved it.
function filesystem.new_temporary_file(dirname, prefix)
    local file, path = core.create_temporary_file(dirname, prefix)
    return setmetatable({ file = file, path = path }, temporary_file_meta)
end

-- Flushes a directory's entries, such as created, renamed, and removed names, to permanent storage.
filesystem.sync_directory = core.sync_directory

-- Creates a temporary filename (an empty file is also created).
function filesystem.temp_filename() return (assert(os.tmpname())) end

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
function filesystem.write_file(data, filename)
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
    local ok, err = pcall(function() filesystem.write_file(data, filename) end)
    if not ok then os.remove(filename) end
    assert(ok, err)
    return filename
end

-- Writes a binary data to a temporary file that is auto removed when scoped ends.
function filesystem.write_scope_temp_file(data)
    local filename = filesystem.write_temp_file(data)
    local function remove()
        if filename then
            filesystem.remove_file(filename)
            filename = nil
        end
    end
    return setmetatable({}, { __gc = remove, __close = remove }), filename
end

-- Removes a file.
function filesystem.remove_file(filename) assert(os.remove(filename)) end

-- Renames a file, atomically replacing the destination if it exists.
function filesystem.rename_file(from, to) assert(os.rename(from, to)) end

-- Removes an empty directory.
function filesystem.remove_directory(dirname) assert(os.remove(dirname)) end

return filesystem
