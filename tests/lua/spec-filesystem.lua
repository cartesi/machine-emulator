--[[
Test suite for the Lua filesystem module.
Specifically, it provides test coverage for:
    src/os-filesystem.cpp
    src/cm-filesystem.cpp
    src/clua-cartesi-filesystem.cpp
Can be run independently during development of the mentioned files.
]]

local lester = require("cartesi.third-party.lester")
lester.parse_args()
local describe, it, expect = lester.describe, lester.it, lester.expect
local filesystem = require("cartesi.filesystem")
local has_posix, unistd = pcall(require, "posix.unistd")
local _, stat = pcall(require, "posix.sys.stat")

-- A new empty directory, removed with its files when the scope ends.
local function new_scope_directory()
    local dirname = filesystem.create_temporary_directory(os.getenv("TMPDIR") or "/tmp", "cartesi-test-")
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

    it("preserves filename bytes when listing directories", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local names = { "a", 'quote"newline\n', "z", "\231\140\171" }
        for _, name in ipairs(names) do
            filesystem.write_file("contents", dirname .. "/" .. name)
        end
        -- Some host filesystems reject filenames that are not valid UTF-8.
        local file = io.open(dirname .. "/\255", "wb")
        if file then
            assert(file:close())
            names[#names + 1] = "\255"
        end
        expect.equal(filesystem.list_directory(dirname), names)
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

    it("reports write errors that only show when the file is closed", function()
        -- /dev/full accepts buffered writes and fails every flush with ENOSPC, but only Linux has it
        if not filesystem.exists("/dev/full") then
            return
        end
        expect.fail(function()
            filesystem.write_file("contents", "/dev/full")
        end, "No space left on device")
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

    if has_posix then
        it("clones the read-only file a symbolic link refers to", function()
            local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
            local clones_scope <close>, clones_dirname = new_scope_directory() -- luacheck: ignore 211
            local original = dirname .. "/original"
            filesystem.write_file("contents", original)
            assert(stat.chmod(original, tonumber("444", 8)))
            assert(unistd.link("original", dirname .. "/relative", true))
            assert(unistd.link(original, dirname .. "/absolute", true))
            for _, name in ipairs({ "relative", "absolute" }) do
                local clone = clones_dirname .. "/" .. name
                filesystem.clone_file(dirname .. "/" .. name, clone)
                expect.truthy(stat.S_ISREG(assert(stat.lstat(clone)).st_mode) ~= 0)
                expect.equal(filesystem.read_file(clone), "contents")
            end
            -- The clones must not depend on the original
            filesystem.remove_file(original)
            filesystem.write_file("replaced", original)
            expect.equal(filesystem.read_file(clones_dirname .. "/relative"), "contents")
            expect.equal(filesystem.read_file(clones_dirname .. "/absolute"), "contents")
        end)
    end

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

    it("creates unique temporary directories owned by the caller", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local first = filesystem.create_temporary_directory(dirname, "state-")
        local second = filesystem.create_temporary_directory(dirname, "state-")
        expect.truthy(first:find(dirname .. "/state-", 1, true) == 1)
        expect.truthy(first ~= second)
        expect.equal(filesystem.list_directory(first), {})
        expect.equal(filesystem.list_directory(second), {})
        filesystem.write_file("contents", first .. "/file")
        expect.equal(filesystem.read_file(first .. "/file"), "contents")
        expect.fail(function()
            filesystem.create_directory(first)
        end, "unable to create directory")
        expect.fail(function()
            filesystem.create_temporary_directory(dirname .. "/missing", "state-")
        end, "unable to create temporary directory")
        filesystem.remove_file(first .. "/file")
        filesystem.remove_directory(first)
        filesystem.remove_directory(second)
        expect.equal(filesystem.list_directory(dirname), {})
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

    it("reads binary contents and overwrites existing files", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local path = dirname .. "/binary"
        local data = ("a\0\255"):rep(5000)
        filesystem.write_file(data, path)
        expect.equal(filesystem.read_file(path), data)
        filesystem.write_file("", path)
        expect.equal(filesystem.read_file(path), "")
        expect.equal(filesystem.get_file_size(path), 0)
    end)

    it("creates temporary names and written files", function()
        local path = filesystem.temp_filename()
        expect.truthy(filesystem.exists(path))
        expect.equal(filesystem.read_file(path), "")
        filesystem.remove_file(path)
        path = filesystem.write_temp_file("a\0b")
        expect.equal(filesystem.read_file(path), "a\0b")
        filesystem.remove_file(path)
    end)

    it("removes scoped temporary files on return and error", function()
        local path
        do
            local scope <close>, name = filesystem.write_scope_temp_file("a\0b") -- luacheck: ignore 211
            path = name
            expect.equal(filesystem.read_file(path), "a\0b")
        end
        expect.falsy(filesystem.exists(path))
        expect.fail(function()
            local scope <close>, name = filesystem.write_scope_temp_file("contents") -- luacheck: ignore 211
            path = name
            error("scope failure")
        end, "scope failure")
        expect.falsy(filesystem.exists(path))
    end)

    it("allows the stream to close before its temporary owner", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local file <close> = filesystem.new_temporary_file(dirname, "temp.")
        local path = file.path
        assert(file.file:write("contents"))
        assert(file.file:close())
        expect.equal(io.type(file.file), "closed file")
        expect.equal(filesystem.read_file(path), "contents")
        file:close()
        file:close()
        expect.falsy(filesystem.exists(path))
    end)

    it("collects temporary owners and their streams without double closing", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local path
        do
            local file = filesystem.new_temporary_file(dirname, "temp.")
            path = file.path
            assert(file.file:write("contents"))
        end
        collectgarbage("collect")
        expect.falsy(filesystem.exists(path))
        collectgarbage("collect")
        do
            local file = filesystem.new_temporary_file(dirname, "temp.")
            path = file.path
            assert(file.file:close())
        end
        collectgarbage("collect")
        expect.falsy(filesystem.exists(path))
    end)

    it("returns the parent directory of a path", function()
        expect.equal(filesystem.get_parent_directory("/name"), "/")
        expect.equal(filesystem.get_parent_directory("//name"), "/")
        expect.equal(filesystem.get_parent_directory("/a/name"), "/a")
        expect.equal(filesystem.get_parent_directory("a/name"), "a")
        expect.equal(filesystem.get_parent_directory("name"), ".")
    end)

    it("writes durable files through a temporary file", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local filename = dirname .. "/state.json"
        filesystem.write_file("old", filename)
        filesystem.write_durable_file("new", filename)
        expect.equal(filesystem.read_file(filename), "new")
        -- A rename onto a non-empty directory fails after the temporary file is written
        filesystem.create_directory(dirname .. "/busy")
        filesystem.write_file("a", dirname .. "/busy/a")
        expect.fail(function()
            filesystem.write_durable_file("contents", dirname .. "/busy")
        end)
        expect.equal(table.concat(filesystem.list_directory(dirname), ","), "busy,state.json")
        filesystem.remove_file(dirname .. "/busy/a")
        filesystem.remove_directory(dirname .. "/busy")
    end)

    it("refuses to sync a file after a failed write", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local filename = dirname .. "/state.json"
        filesystem.write_file("contents", filename)
        -- Writing to a read-only stream fails and leaves nothing to flush
        local file <close> = assert(io.open(filename, "rb"))
        expect.falsy(file:write("more"))
        expect.fail(function()
            filesystem.sync_file(file)
        end, "unable to sync file: a previous write failed")
    end)

    it("reports missing paths", function()
        local scope <close>, dirname = new_scope_directory() -- luacheck: ignore 211
        local missing = dirname .. "/missing"
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

    it("removes private temporary test paths on return and error", function()
        local tests_util = require("cartesi.tests.util")
        for _, fail in ipairs({ false, true }) do
            local directory
            local ok = pcall(function()
                local _ <close>, path = tests_util.scope_temp_pathname(".json")
                directory = filesystem.get_parent_directory(path)
                expect.truthy(filesystem.exists(directory))
                expect.falsy(filesystem.exists(path))
                filesystem.write_file("contents", path)
                if fail then
                    error("injected failure")
                end
            end)
            expect.equal(ok, not fail)
            expect.falsy(filesystem.exists(directory))
        end
    end)
end)
