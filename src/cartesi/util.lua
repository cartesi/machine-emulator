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

local cartesi = require("cartesi")

local _M = {}

local function indentout(f, indent, fmt, ...) f:write(string.rep("  ", indent), string.format(fmt, ...)) end

_M.indentout = indentout

local function hexstring(hash)
    return (string.gsub(hash, ".", function(c) return string.format("%02x", string.byte(c)) end))
end

local hexhash = hexstring
_M.hexstring = hexstring
_M.hexhash = hexstring

local function dump_json_sibling_hashes(sibling_hashes, out, indent)
    for i, h in ipairs(sibling_hashes) do
        indentout(out, indent, '"%s"', hexhash(h))
        if sibling_hashes[i + 1] then
            out:write(",\n")
        else
            out:write("\n")
        end
    end
end

local function dump_json_proof(proof, out, indent)
    indentout(out, indent, '"target_address": %u,\n', proof.target_address)
    indentout(out, indent, '"log2_target_size": %u,\n', proof.log2_target_size)
    indentout(out, indent, '"log2_root_size": %u,\n', proof.log2_root_size)
    indentout(out, indent, '"target_hash": "%s",\n', hexhash(proof.target_hash))
    indentout(out, indent, '"sibling_hashes": [\n')
    dump_json_sibling_hashes(proof.sibling_hashes, out, indent + 1)
    indentout(out, indent, "],\n")
    indentout(out, indent, '"root_hash": "%s"\n', hexhash(proof.root_hash))
end

_M.dump_json_proof = dump_json_proof

local function dump_json_log_notes(notes, out, indent)
    local n = #notes
    for i, note in ipairs(notes) do
        indentout(out, indent, '"%s"', note)
        if i < n then
            out:write(",\n")
        else
            out:write("\n")
        end
    end
end

local function dump_json_log_brackets(brackets, out, indent)
    local n = #brackets
    for i, bracket in ipairs(brackets) do
        indentout(out, indent, "{\n")
        indentout(out, indent + 1, '"type": "%s",\n', bracket.type)
        indentout(out, indent + 1, '"where": %u,\n', bracket.where)
        indentout(out, indent + 1, '"text": "%s"\n', bracket.text)
        indentout(out, indent, "}")
        if i < n then
            out:write(",\n")
        else
            out:write("\n")
        end
    end
end

local function dump_json_log_access(access, out, indent)
    indentout(out, indent, "{\n")
    indentout(out, indent + 1, '"type": "%s",\n', access.type)
    indentout(out, indent + 1, '"address": %u,\n', access.address)
    indentout(out, indent + 1, '"read": "%s"', hexstring(access.read))
    if access.type == "write" then
        out:write(",\n")
        indentout(out, indent + 1, '"written": "%s"', hexstring(access.written))
    end
    if access.proof then
        out:write(",\n")
        indentout(out, indent + 1, '"proof": {\n')
        dump_json_proof(access.proof, out, indent + 2)
        indentout(out, indent + 1, "}\n")
    else
        out:write("\n")
    end
    indentout(out, indent, "}")
end

local function dump_json_log_accesses(accesses, out, indent)
    local n = #accesses
    for i, access in ipairs(accesses) do
        dump_json_log_access(access, out, indent)
        if i < n then
            out:write(",\n")
        else
            out:write("\n")
        end
    end
end

function _M.dump_json_log(log, init_mcycle, init_uarch_cycle, final_mcycle, final_uarch_cycle, out, indent)
    indent = indent or 0
    indentout(out, indent, "{\n")
    indentout(out, indent + 1, '"init_mcycle": %u,\n', init_mcycle)
    indentout(out, indent + 1, '"init_uarch_cycle": %u,\n', init_uarch_cycle)
    indentout(out, indent + 1, '"final_mcycle": %u,\n', final_mcycle)
    indentout(out, indent + 1, '"final_uarch_cycle": %u,\n', final_uarch_cycle)
    indentout(out, indent + 1, '"accesses": [\n')
    dump_json_log_accesses(log.accesses, out, indent + 2)
    indentout(out, indent + 1, "]")
    if log.log_type.annotations then
        out:write(",\n")
        indentout(out, indent + 1, '"notes": [\n')
        dump_json_log_notes(log.notes, out, indent + 2)
        indentout(out, indent + 1, "],\n")
        indentout(out, indent + 1, '"brackets": [\n')
        dump_json_log_brackets(log.brackets, out, indent + 2)
        indentout(out, indent + 1, "]\n")
    else
        out:write("\n")
    end
    indentout(out, indent, "}")
end

function _M.parse_number(n)
    if not n then return nil end
    local base, rest = string.match(n, "^%s*(0x%x+)%s*(.-)%s*$")
    if not base then
        base, rest = string.match(n, "^%s*(%d+)%s*(.-)%s*$")
    end
    base = tonumber(base)
    if not base then return nil end
    if rest == "Ki" then
        return base << 10
    elseif rest == "Mi" then
        return base << 20
    elseif rest == "Gi" then
        return base << 30
    elseif rest == "" then
        return base
    end
    local shift = string.match(rest, "^%s*%<%<%s*(%d+)$")
    if shift then
        shift = tonumber(shift)
        if shift then return base << shift end
    end
    return nil
end

function _M.parse_boolean(b)
    if b == "true" or b == true then
        return true
    elseif b == "false" or b == false then
        return false
    end
    return nil
end

function _M.parse_options(s, all, keys)
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
    string.gsub(escape(s) .. ",", "(.-)%,", function(o)
        local k, v = string.match(o, "(.-):(.*)")
        if k and v then
            k = unescape(k)
            v = unescape(v)
        else
            k = unescape(o)
            v = nil
        end
        assert(keys[k], string.format("unknown option %q in '%s'", k, all))
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
            v = _M.parse_number(v)
            if v == nil then error(string.format("invalid number for option %q in '%s'", k, all)) end
            options[k] = v
        elseif keys[k] == "string" then
            if v == nil then error(string.format("missing string for option %q in '%s'", k, all)) end
            options[k] = v
        elseif type(keys[k]) == "table" then
            if not keys[k][v] then error(string.format("invalid value for option %q in '%s'", k, all)) end
            options[k] = keys[k][v]
        end
    end)
    return options
end

local function hexhash8(hash) return string.sub(hexhash(hash), 1, 8) end

local function accessdatastring(data, data_hash, data_log2_size, address)
    local data_size = 1 << data_log2_size
    if data_log2_size == 3 then
        if not data then return "???(no written data)" end
        if data_size < #data then
            -- access data is  smaller than the tree leaf size
            -- the logged data is the entire tree leaf, but we only need the data that was accessed
            local leaf_aligned_address = (address >> cartesi.TREE_LOG2_WORD_SIZE) << cartesi.TREE_LOG2_WORD_SIZE
            local word_offset = address - leaf_aligned_address
            data = data:sub(word_offset + 1, word_offset + data_size)
        end
        data = string.unpack("<I8", data)
        return string.format("0x%x(%u)", data, data)
    else
        local data_snippet = ""
        if data_hash ~= nil then data_snippet = string.format('hash:"%s"', hexhash8(data_hash)) end
        if data ~= nil then
            if data_snippet ~= "" then data_snippet = data_snippet .. " " end
            data_snippet = data_snippet
                .. string.format("%s...%s", hexstring(data:sub(1, 3)), hexstring(data:sub(-3, -1)))
        end
        return string.format("%s(2^%d bytes)", data_snippet, data_log2_size)
    end
end

function _M.dump_log(log, out)
    local indent = 0
    local j = 1 -- Bracket index
    local i = 1 -- Access index
    local brackets = log.brackets or {}
    local notes = log.notes or {}
    local accesses = log.accesses
    -- Loop until accesses and brackets are exhausted
    while true do
        local bj = brackets[j]
        local ai = accesses[i]
        if not bj and not ai then break end
        -- If bracket points before current access, output bracket
        if bj and bj.where <= i then
            if bj.type == "begin" then
                indentout(out, indent, "begin %s\n", bj.text)
                indent = indent + 1 -- Increase indentation before bracket
            elseif bj.type == "end" then
                indent = indent - 1 -- Decrease indentation after bracket
                indentout(out, indent, "end %s\n", bj.text)
            end
            j = j + 1
        -- Otherwise, output access
        elseif ai then
            local read = accessdatastring(ai.read, ai.read_hash, ai.log2_size, ai.address)
            if ai.type == "read" then
                indentout(out, indent, "%d: read %s@0x%x(%u): %s\n", i, notes[i] or "", ai.address, ai.address, read)
            else
                assert(ai.type == "write", "unknown access type")
                local written = accessdatastring(ai.written, ai.written_hash, ai.log2_size, ai.address)
                indentout(
                    out,
                    indent,
                    "%d: write %s@0x%x(%u): %s -> %s\n",
                    i,
                    notes[i] or "",
                    ai.address,
                    ai.address,
                    read,
                    written
                )
            end
            i = i + 1
        end
    end
end

return _M
