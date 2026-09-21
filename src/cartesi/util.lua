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

local _M = {}

local function indentout(f, indent, fmt, ...) f:write(string.rep("  ", indent), string.format(fmt, ...)) end

_M.indentout = indentout

local function dump_table(what, out, whatdef, indent)
    whatdef = whatdef or {}
    indent = indent or ""
    if type(what) == "table" then
        local next_indent = indent .. "  "
        local keys = {}
        for k in pairs(what) do
            table.insert(keys, k)
        end
        table.sort(keys)
        if #keys > 0 then
            out:write("{\n")
            for _, k in ipairs(keys) do
                local v, vdef = what[k], whatdef and whatdef[k]
                out:write(next_indent)
                if type(k) == "string" then out:write(k, " = ") end
                dump_table(v, out, vdef, next_indent)
                out:write(",")
                if v == vdef then out:write(" -- default") end
                out:write("\n")
            end
            out:write(indent, "}")
        else
            out:write("{}")
        end
    elseif math.type(what) == "integer" then
        out:write(string.format("0x%x", what))
    else
        out:write(string.format("%q", what))
    end
end

_M.dump_table = dump_table

function _M.parse_number(n)
    if not n then return nil, "number is missing" end
    local base, rest = string.match(n, "^%s*(0[xX]%x+)%s*(.-)%s*$")
    local format
    if base then
        base = base:lower():gsub("^0x0*", "0x")
        if base == "0x" then base = "0x0" end
        format = "0x%x"
    else
        base, rest = string.match(n, "^%s*(%d+)%s*(.-)%s*$")
        if not base then return nil, "invalid number syntax" end
        base = base:gsub("^0+", "")
        if base == "" then base = "0" end
        format = "%d"
    end
    local value = tonumber(base)
    if math.type(value) ~= "integer" or string.format(format, value) ~= base then
        return nil,
            format == "%d" and "decimal literal exceeds maximum signed integer" or "hexadecimal literal exceeds 64 bits"
    end
    local shift
    if rest == "Ki" then
        shift = 10
    elseif rest == "Mi" then
        shift = 20
    elseif rest == "Gi" then
        shift = 30
    elseif rest == "Ti" then
        shift = 40
    elseif rest == "" then
        return value
    else
        shift = tonumber(string.match(rest, "^%s*%<%<%s*(%d+)$"))
        if not shift then return nil, "invalid number suffix" end
    end
    if value == 0 then return 0 end
    if shift >= 64 or value >> (64 - shift) ~= 0 then return nil, "shifted number exceeds 64 bits" end
    return value << shift
end

function _M.parse_boolean(b)
    if b == "true" or b == true then
        return true
    elseif b == "false" or b == false then
        return false
    end
    return nil
end

-- String-shaped kinds: all parsed identically as strings, but the subtype
-- carries a hint used by bash completion to pick the right candidates.
local string_kinds = {
    string = true,
    file = true,
    dir = true,
    hostport = true,
    netif = true,
}
_M.string_kinds = string_kinds

-- The array part of "keys" (keys[1], optional) names the key that receives a
-- bare value: a comma item with no colon that is not itself a declared key. At
-- most one such positional is allowed. A colon inside a positional value must be
-- escaped, since an unescaped colon always means key:value (so typos still error).
function _M.parse_options(keys, all, opts)
    local positional_key = keys[1]
    local function escape(v)
        -- replace escaped \, :, and , with something "safe"
        v = string.gsub(v, "%\\%\\", "\0")
        v = string.gsub(v, "%\\%:", "\1")
        return string.gsub(v, "%\\%,", "\2")
    end
    local function unescape(v)
        v = string.gsub(v, "\0", "\\")
        v = string.gsub(v, "\1", ":")
        return string.gsub(v, "\2", ",")
    end
    -- split at commas and validate key
    local options = {}
    local positional_seen = false
    string.gsub(escape(opts) .. ",", "(.-)%,", function(o)
        local k, v = string.match(o, "(.-):(.*)")
        if k and v then
            k = unescape(k)
            v = unescape(v)
            assert(keys[k], string.format("unknown option %q in '%s'", k, all))
        elseif keys[unescape(o)] ~= nil then
            k = unescape(o)
            v = nil
        else
            -- not a declared key: treat as the positional value
            k = unescape(o)
            assert(positional_key, string.format("unknown option %q in '%s'", k, all))
            assert(not positional_seen, string.format("only one positional value allowed in '%s'", all))
            positional_seen = true
            v, k = k, positional_key
        end
        if keys[k] == "array" then
            options[k] = options[k] or {}
            table.insert(options[k], v)
        elseif keys[k] == "boolean" then
            if v == nil then
                v = true
            else
                v = _M.parse_boolean(v)
                if v == nil then error(string.format("invalid boolean for option %q in '%s'", k, all)) end
            end
            options[k] = v
        elseif keys[k] == "number" then
            local parse_error
            v, parse_error = _M.parse_number(v)
            if v == nil then error(string.format("invalid number for option %q in '%s': %s", k, all, parse_error)) end
            options[k] = v
        elseif string_kinds[keys[k]] then
            if v == nil then error(string.format("missing string for option %q in '%s'", k, all)) end
            options[k] = v
        elseif type(keys[k]) == "table" then
            if not keys[k][v] then error(string.format("invalid value for option %q in '%s'", k, all)) end
            options[k] = keys[k][v]
        end
    end)
    return options
end

function _M.ilog2(n)
    n = assert(math.tointeger(n), "expected integer")
    assert(n ~= 0, "expected non-zero integer")
    local v = n - 1
    local r = 0
    if v & 0xFFFFFFFF00000000 ~= 0 then
        v = v >> 32
        r = r + 32
    end
    if v & 0x00000000FFFF0000 ~= 0 then
        v = v >> 16
        r = r + 16
    end
    if v & 0x000000000000FF00 ~= 0 then
        v = v >> 8
        r = r + 8
    end
    if v & 0x00000000000000F0 ~= 0 then
        v = v >> 4
        r = r + 4
    end
    if v & 0x000000000000000C ~= 0 then
        v = v >> 2
        r = r + 2
    end
    if v & 0x0000000000000002 ~= 0 then
        v = v >> 1
        r = r + 1
    end
    if v ~= 0 then r = r + 1 end
    return r
end

-- Returns the drive in config[what] (e.g. "nvram" or "flash_drive") whose label matches, after
-- filling in its log2_size from its length. Returns nil and an error message when there is no such
-- drive, so a caller can simply wrap the call in assert().
function _M.find_drive(config, what, label)
    for _, drive in ipairs(config[what]) do
        if drive.label == label then
            drive.log2_size = _M.ilog2(drive.length)
            return drive
        end
    end
    return nil, string.format("missing %s %s", label, what)
end

-- Reads the entire contents of a file as a binary string.
function _M.read_file(filename)
    local f <close> = assert(io.open(filename, "rb"))
    return assert(f:read("a"))
end

-- Writes a binary string as the entire contents of a file.
function _M.write_file(contents, filename)
    local f <close> = assert(io.open(filename, "wb"))
    assert(f:write(contents))
end

return _M
