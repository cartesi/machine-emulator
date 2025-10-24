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

-- Module with helpers for table manipulations.
local tabular = {}

-- Convert a table with indexed rows into a table with named rows. e.g.
-- {"foo", 999} -> {name = "foo", cycles = 999} with keys described by md
function tabular.expand_row(metadata, row)
    local expanded_row = {}
    for key, val in ipairs(metadata) do
        expanded_row[val] = row[key]
    end
    return expanded_row
end

-- Apply `expand_row` for each row of `t`. e.g.
-- {{ "foo", 999 }} -> {{name = "foo", cycles = 999}} with keys described by md
function tabular.expand(metadata, t)
    local expanded_t = {}
    for _, row in ipairs(t) do
        expanded_t[#expanded_t + 1] = tabular.expand_row(metadata, row)
    end
    return expanded_t
end

-- Clear all key-value pairs from table `t`.
function tabular.clear(t)
    for k in pairs(t) do
        t[k] = nil
    end
    return t
end

-- Append all elements from `elems` to the end of table `t`.
function tabular.append(t, elems)
    local n = #t
    for i = 1, #elems do
        t[n + i] = elems[i]
    end
    return t
end

local function deep_traverse_iter(t, path)
    path = path or {}
    for k, v in pairs(t) do
        local current_path = {}
        for i = 1, #path do
            current_path[i] = path[i]
        end
        current_path[#current_path + 1] = k
        if type(v) == "table" then
            deep_traverse_iter(v, current_path)
        else
            coroutine.yield(current_path, k, v)
        end
    end
end

-- Iterator that recursively traverses all key-value pairs in table `t`,
-- yielding the path to each value, its key, and the value itself.
function tabular.deep_traverse(t)
    return coroutine.wrap(function()
        deep_traverse_iter(t)
    end)
end

-- Recursively copy a table `t` and all its subtables.
function tabular.deep_copy(t)
    local copy = {}
    for k, v in pairs(t) do
        if type(v) == "table" then
            copy[k] = tabular.deep_copy(v)
        else
            copy[k] = v
        end
    end
    return copy
end

-- Recursively merge all key-value pairs from table `src_t` into table `t`.
function tabular.deep_merge(t, src_t)
    for k, v in pairs(src_t) do
        if type(v) == "table" then
            if type(t[k]) == "table" then
                tabular.deep_merge(t[k], v)
            else
                t[k] = tabular.deep_copy(v)
            end
        else
            t[k] = v
        end
    end
    return t
end

-- Recursively copy all key-value pairs from table `src_t` into a deep copy of
-- table `t`, returning the new table.
function tabular.deep_copy_and_merge(t, src_t)
    return tabular.deep_merge(tabular.deep_copy(t), src_t)
end

return tabular
