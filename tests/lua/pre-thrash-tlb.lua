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
Pre-run script for the thrash-tlb test.

Runs thrash-tlb.bin once to fill all TLB entries, then corrupts every shadow
TLB slot with six different corruption types (one per slot % 6) that cover
all rejection paths in shadow_tlb_verify_slot().  Resets PC and mcycle so
the test infrastructure can run the binary again from scratch.

Returns the raw TLB string captured before corruption, so the post script
can verify the TLB was restored to the same state.
]]

local cartesi = require("cartesi")

local TLB_CODE = 0
local TLB_READ = 1
local TLB_WRITE = 2
local TLB_SETS = { TLB_CODE, TLB_READ, TLB_WRITE }

local TLB_SET_SIZE = 256
local TLB_SLOT_BYTES = 32

local PMA_ENTRY_BYTES = 16

local RAM_START = cartesi.AR_RAM_START

local function count_pmas(machine)
    local pmas_data = machine:read_memory(cartesi.AR_PMAS_START, cartesi.AR_PMAS_LENGTH)
    local sentinel = string.rep("\0", PMA_ENTRY_BYTES)
    for i = 0, #pmas_data // PMA_ENTRY_BYTES - 1 do
        local offset = 1 + i * PMA_ENTRY_BYTES
        if pmas_data:sub(offset, offset + PMA_ENTRY_BYTES - 1) == sentinel then
            return i
        end
    end
    error("PMA sentinel not found")
end

local function build_corrupted_tlb(tlb_data, num_pmas)
    local parts = {}
    for _, _ in ipairs(TLB_SETS) do
        for slot = 0, TLB_SET_SIZE - 1 do
            local offset = 1 + #parts * TLB_SLOT_BYTES
            local vaddr_page, vp_offset, pma_index = string.unpack("<I8I8I8", tlb_data, offset)
            local new_data
            local ct = slot % 6
            if ct == 0 then
                -- zero_padding != 0
                new_data = string.pack("<I8I8I8I8", vaddr_page, vp_offset, pma_index, 1)
            elseif ct == 1 then
                -- vaddr_page not page-aligned
                new_data = string.pack("<I8I8I8I8", vaddr_page | 1, vp_offset, pma_index, 0)
            elseif ct == 2 then
                -- paddr_page not page-aligned
                new_data = string.pack("<I8I8I8I8", vaddr_page, vp_offset | 1, pma_index, 0)
            elseif ct == 3 then
                -- pma_index one past valid range (sentinel, not memory)
                new_data = string.pack("<I8I8I8I8", vaddr_page, vp_offset, num_pmas, 0)
            elseif ct == 4 then
                -- paddr_page above PMA end
                new_data = string.pack("<I8I8I8I8", 0x90000000, 0, pma_index, 0)
            else
                -- paddr_page below PMA start
                new_data = string.pack("<I8I8I8I8", 0x70000000, 0, pma_index, 0)
            end
            parts[#parts + 1] = new_data
        end
    end
    return table.concat(parts)
end

return function(machine)
    -- Run once to fill all TLB entries
    machine:run()
    assert(machine:read_reg("htif_tohost_data") >> 1 == 0, "thrash-tlb.bin failed on initial run")

    local num_pmas = count_pmas(machine)

    -- Capture the valid TLB as a single string
    local valid_tlb = machine:read_memory(cartesi.AR_SHADOW_TLB_START, cartesi.AR_SHADOW_TLB_LENGTH)

    -- Build corrupted TLB and splice it into the full shadow state
    local shadow = machine:read_memory(cartesi.AR_SHADOW_STATE_START, cartesi.AR_SHADOW_STATE_LENGTH)
    local tlb_offset = cartesi.AR_SHADOW_TLB_START - cartesi.AR_SHADOW_STATE_START
    local tlb_end_offset = tlb_offset + cartesi.AR_SHADOW_TLB_LENGTH
    local corrupted_shadow = shadow:sub(1, tlb_offset)
        .. build_corrupted_tlb(valid_tlb, num_pmas)
        .. shadow:sub(tlb_end_offset + 1)
    machine:write_memory(cartesi.AR_SHADOW_STATE_START, corrupted_shadow)

    -- Reset so the binary runs again from scratch
    machine:write_reg("pc", RAM_START)
    machine:write_reg("mcycle", 0)
    machine:write_reg("iflags_H", 0)
    machine:write_reg("htif_tohost", 0)

    return valid_tlb
end
