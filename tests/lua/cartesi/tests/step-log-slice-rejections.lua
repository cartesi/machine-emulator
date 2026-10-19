-- Copyright Cartesi and individual authors (see AUTHORS)
-- SPDX-License-Identifier: LGPL-3.0-or-later

-- Shared rejection recipes for the C++/Lua specs and cross-verifier fixtures.
-- Mutations deliberately serialize invalid geometry; do not use the verifier's
-- parser to construct these inputs.
local function resize(page, size, offset)
    page.offset, page.log2_size = offset or 0, size
    page.data = string.rep("\0", 1 << size)
end

return {
    {
        tag = "old_signature",
        error = "invalid step log signature",
        mutate = function(log)
            log.signature = "CTSI\3\0\0\0"
        end,
    },
    {
        tag = "slice_size_low",
        error = "slice log2 size out of range",
        mutate = function(log)
            log.pages[1].log2_size = 4
        end,
    },
    {
        tag = "slice_size_high",
        error = "slice log2 size out of range",
        mutate = function(log)
            log.pages[1].log2_size = 13
        end,
    },
    {
        tag = "slice_unaligned",
        error = "slice address not aligned to its size",
        mutate = function(log)
            log.pages[1].offset = log.pages[1].offset | 8
        end,
    },
    {
        tag = "slice_unsorted",
        error = "slice addresses not in increasing order",
        mutate = function(log)
            log.pages[1], log.pages[2] = log.pages[2], log.pages[1]
        end,
    },
    {
        tag = "slice_overlap",
        error = "slice overlaps previous slice",
        mutate = function(log)
            resize(log.pages[1], 12)
            resize(log.pages[2], 9, 512)
            log.pages[2].index = log.pages[1].index
        end,
    },
    {
        tag = "slice_same_page",
        error = "multiple slices in the same page",
        mutate = function(log)
            resize(log.pages[1], 5)
            resize(log.pages[2], 5, 32)
            log.pages[2].index = log.pages[1].index
        end,
    },
    {
        tag = "slice_node_overlap",
        error = "slice or node overlaps a previous entry",
        mutate = function(log)
            log.nodes = { { address = (log.pages[1].index & ~1) << 12, log2_size = 13, hash = string.rep("\0", 32) } }
        end,
    },
    {
        tag = "slice_truncated",
        error = "truncated slice data or hash",
        mutate = function(log)
            log.pages = { log.pages[1] }
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
