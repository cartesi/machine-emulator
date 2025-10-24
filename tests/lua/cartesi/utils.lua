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

-- Module providing utilities.
local utils = {}

-- Executes a callback when the scope exits.
-- REMARKS: Use <close> on its returned value to make it behave deterministically.
function utils.scope_exit(callback)
    local function do_callback()
        if callback then
            callback()
            callback = nil
        end
    end
    return setmetatable({}, { __gc = do_callback, __close = do_callback })
end

return utils
