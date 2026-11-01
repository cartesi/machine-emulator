#!/usr/bin/env lua5.4
-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

local dirent = require("posix.dirent")
local stat = require("posix.sys.stat")
local output = assert(arg[1], "usage: gen-step-log-seed-corpus.lua <output> <fixture-dir>...")
local total = 0
for root_index = 2, #arg do
    local count = 0
    local function visit(path)
        local info = stat.stat(path)
        if not info or count >= 40 then
            return
        end
        if stat.S_ISDIR(info.st_mode) ~= 0 then
            local names = assert(dirent.dir(path))
            table.sort(names)
            for _, name in ipairs(names) do
                if name ~= "." and name ~= ".." then
                    visit(path .. "/" .. name)
                end
            end
        elseif path:match("%.log$") and info.st_size >= 16 and info.st_size < 65536 then
            local src <close> = assert(io.open(path, "rb"))
            local data = assert(src:read("a"))
            local hash = string.unpack("<I8", data, 9)
            local machine = path:find("reject-machine/", 1, true) or path:find("cartesi-machine-tests/", 1, true)
            local selector = (machine and 1 or 0) | (hash == 1 and 2 or 0)
            count = count + 1
            local dst <close> = assert(io.open(string.format("%s/%d-%02d", output, root_index - 1, count), "wb"))
            assert(dst:write(string.char(selector), data))
        end
    end
    visit(arg[root_index])
    total = total + count
end
io.stderr:write(string.format("seeded %d step logs (shape/hash selector byte plus wire image)\n", total))
if total == 0 then
    io.stderr:write("warning: record fixtures with make create-reject-test-fixtures first\n")
end
