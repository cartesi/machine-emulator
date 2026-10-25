--[[
Test suite for the Lua filesystem module.
Specifically, it provides test coverage for:
    src/cartesi/filesystem.lua
    src/clua-cartesi-filesystem.cpp
Can be run independently during development of the mentioned files.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local filesystem = require("cartesi.filesystem")

-- A new empty directory, removed with its files when the scope ends.
local function new_scope_directory()
    local dirname = filesystem.temp_pathname()
    filesystem.create_directory(dirname)
    local function remove()
        if dirname then
            for _, name in ipairs(filesystem.list_directory(dirname)) do
                filesystem.remove_file(dirname .. "/" .. name)
            end
            filesystem.remove_directory(dirname)
            dirname = nil
        end
    end
    return setmetatable({}, { __gc = remove, __close = remove }), dirname
end

describe("filesystem", function()
    it("creates, lists, and removes directories", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        expect.truthy(filesystem.exists(dirname))
        expect.equal(#filesystem.list_directory(dirname), 0)
        filesystem.create_directory(dirname .. "/b")
        filesystem.write_file("a", dirname .. "/c")
        filesystem.write_file("a", dirname .. "/a")
        local names = filesystem.list_directory(dirname)
        expect.equal(table.concat(names, ","), "a,b,c")
        expect.fail(function()
            filesystem.create_directory(dirname .. "/b")
        end, "unable to create directory")
        expect.fail(function()
            filesystem.remove_directory(dirname)
        end)
        filesystem.remove_directory(dirname .. "/b")
        expect.falsy(filesystem.exists(dirname .. "/b"))
    end)

    it("writes, renames, and syncs files", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local filename = dirname .. "/state.json"
        local temporary = filename .. ".tmp"
        filesystem.write_file("old", filename)
        filesystem.write_file("new", temporary)
        filesystem.sync_file(temporary)
        filesystem.rename_file(temporary, filename)
        filesystem.sync_directory(dirname)
        expect.equal(filesystem.read_file(filename), "new")
        expect.falsy(filesystem.exists(temporary))
        expect.equal(filesystem.get_file_size(filename), 3)
    end)

    it("clones files", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local original, clone = dirname .. "/original", dirname .. "/clone"
        filesystem.write_file("contents", original)
        filesystem.clone_file(original, clone)
        expect.equal(filesystem.read_file(clone), "contents")
        filesystem.write_file("changed", clone)
        expect.equal(filesystem.read_file(original), "contents")
        expect.fail(function()
            filesystem.clone_file(original, clone)
        end, "File exists")
        expect.fail(function()
            filesystem.clone_file(dirname .. "/missing", dirname .. "/other")
        end, "unable to clone file")
    end)

    it("truncates and extends files", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local filename = dirname .. "/log"
        filesystem.write_file("0123456789", filename)
        filesystem.truncate_file(filename, 4)
        expect.equal(filesystem.read_file(filename), "0123")
        filesystem.truncate_file(filename, 6)
        expect.equal(filesystem.read_file(filename), "0123\0\0")
        filesystem.truncate_file(filename, 0)
        expect.equal(filesystem.get_file_size(filename), 0)
        expect.fail(function()
            filesystem.truncate_file(dirname .. "/missing", 0)
        end, "unable to truncate file")
        expect.fail(function()
            filesystem.truncate_file(filename, -1)
        end, "size must not be negative")
    end)

    it("creates temporary files that are removed unless renamed", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local first <close> = filesystem.new_temporary_file(dirname, "state.json.tmp.")
        local second <close> = filesystem.new_temporary_file(dirname, "state.json.tmp.")
        expect.equal(io.type(first.file), "file")
        expect.truthy(first.path:find(dirname .. "/state.json.tmp.", 1, true) == 1)
        expect.truthy(first.path ~= second.path)
        first.file:write("contents")
        filesystem.sync_file(first.file)
        first:rename(dirname .. "/state.json")
        expect.equal(filesystem.read_file(dirname .. "/state.json"), "contents")
        local second_path = second.path
        second:close()
        expect.falsy(filesystem.exists(second_path))
        expect.equal(table.concat(filesystem.list_directory(dirname), ","), "state.json")
        expect.fail(function()
            filesystem.sync_file(first.file)
        end, "attempt to sync a closed file")
        expect.fail(function()
            filesystem.new_temporary_file(dirname .. "/missing", "state.json.tmp.")
        end, "unable to create temporary file")
    end)

    it("reports missing paths", function()
        local missing = filesystem.temp_pathname()
        expect.falsy(filesystem.exists(missing))
        expect.fail(function()
            filesystem.sync_file(missing)
        end, "unable to sync file")
        expect.fail(function()
            filesystem.sync_directory(missing)
        end, "unable to sync directory")
        expect.fail(function()
            filesystem.list_directory(missing)
        end, "unable to list directory")
        expect.fail(function()
            filesystem.create_directory(missing .. "/child")
        end, "unable to create directory")
    end)
end)
