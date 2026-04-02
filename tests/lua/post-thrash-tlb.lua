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

--[[
Post-run script for the thrash-tlb test.

Verifies that the shadow TLB was fully restored after the second run
by comparing it against the valid TLB string returned by the pre script.
]]

local cartesi = require("cartesi")

return function(machine, valid_tlb)
    local current_tlb = machine:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH)
    assert(current_tlb == valid_tlb, "shadow TLB was not restored to its valid state after re-run")
end
