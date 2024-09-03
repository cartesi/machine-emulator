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

-- module to convert array tables into key-value tables
local M = {}

-- convert a table with indexed rows into a table with named rows. e.g.
-- {"foo", 999} -> {name = "foo", cycles = 999} with keys described by md
local function expand_row(metadata, row)
    local expanded_row = {}
    for key, val in ipairs(metadata) do
        expanded_row[val] = row[key]
    end
    return expanded_row
end

-- apply `expand_row` for each row of `t`. e.g.
-- {{ "foo", 999 }} -> {{name = "foo", cycles = 999}} with keys described by md
M.expand = function(metadata, t)
    local expanded_t = {}
    for _, row in ipairs(t) do
        expanded_t[#expanded_t + 1] = expand_row(metadata, row)
    end
    return expanded_t
end

return M
