-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Shared rejection recipes for the C++/Lua specs and cross-verifier fixtures.
-- Mutations deliberately serialize invalid geometry; do not use the verifier's
-- parser to construct these inputs.
local function resize(slice, size, offset)
    slice.page_offset, slice.log2_size = offset or 0, size
    slice.data = string.rep("\0", 1 << size)
end

return {
    {
        tag = "old_signature",
        error = "invalid step log signature",
        mutate = function(log)
            log.signature = "CTSI\4\0\0\0"
        end,
    },
    {
        tag = "slice_size_low",
        error = "slice log2 size out of range",
        mutate = function(log)
            log.slices[1].log2_size = 4
        end,
    },
    {
        tag = "slice_size_high",
        error = "slice log2 size out of range",
        mutate = function(log)
            log.slices[1].log2_size = 13
        end,
    },
    {
        tag = "slice_unaligned",
        error = "slice address not aligned to its size",
        mutate = function(log)
            log.slices[1].page_offset = log.slices[1].page_offset | 8
        end,
    },
    {
        tag = "slice_data_offset",
        error = "slice data offset mismatch",
        mutate = function(log)
            log.slices[2].override_data_offset = log.slices[2].data_offset + 8
        end,
    },
    {
        tag = "slice_unsorted",
        error = "slice addresses not in increasing order",
        mutate = function(log)
            log.slices[1], log.slices[2] = log.slices[2], log.slices[1]
        end,
    },
    {
        tag = "slice_overlap",
        error = "slice overlaps previous slice",
        mutate = function(log)
            resize(log.slices[1], 12)
            resize(log.slices[2], 9, 512)
            log.slices[2].page_index = log.slices[1].page_index
        end,
    },
    {
        tag = "slice_same_page",
        error = "multiple slices in the same page",
        mutate = function(log)
            resize(log.slices[1], 5)
            resize(log.slices[2], 5, 32)
            log.slices[2].page_index = log.slices[1].page_index
        end,
    },
    {
        tag = "slice_node_overlap",
        error = "slice or node overlaps a previous entry",
        mutate = function(log)
            log.nodes =
                { { address = (log.slices[1].page_index & ~1) << 12, log2_size = 13, hash = string.rep("\0", 32) } }
        end,
    },
    {
        tag = "slice_truncated",
        error = "truncated slice data",
        mutate = function(log)
            log.slices = { log.slices[1] }
            log.nodes, log.siblings = {}, {}
        end,
        wire = function(bytes)
            return bytes:sub(1, -2)
        end,
    },
    {
        tag = "slice_trailing_bytes",
        error = "step log byte length does not match counts",
        wire = function(bytes)
            return bytes .. "\0"
        end,
    },
    {
        tag = "slice_count_mismatch",
        error = "step log byte length does not match counts",
        mutate = function(log)
            log.override_sibling_count = #log.siblings + 1
        end,
    },
}
