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

-- One rejection vocabulary for the C++ and Solidity fixture replayers. Each tag
-- specifies both implementations' observable failure; recorders export this table
-- beside their manifests so Foundry consumes the same definitions as Lester.
local cartesi = require("cartesi")
local M = {}

M.errors = {
    bad_signature = {
        cpp_pattern = "invalid step log signature",
        solidity_signature = "InvalidSignature()",
        solidity_message = "",
    },
    unsupported_hash_function = {
        cpp_pattern = "unsupported hash function type",
        solidity_signature = "UnsupportedHashFunction(uint64)",
        solidity_message = "",
    },
    page_count_zero = {
        cpp_pattern = "page count is zero",
        solidity_signature = "PageCountZero()",
        solidity_message = "",
    },
    page_index_not_increasing = {
        cpp_pattern = "page index is not in increasing order",
        solidity_signature = "PagesNotInOrder()",
        solidity_message = "",
    },
    entries_overlap = {
        cpp_pattern = "page or node overlaps a previous entry",
        solidity_signature = "OverlappingEntries()",
        solidity_message = "",
    },
    node_misaligned = {
        cpp_pattern = "node address not aligned to its size",
        solidity_signature = "NodeNotAligned(uint64,uint64)",
        solidity_message = "",
    },
    node_log2_out_of_range = {
        cpp_pattern = "node log2 size out of range",
        solidity_signature = "NodeLog2SizeOutOfRange(uint64)",
        solidity_message = "",
    },
    nonzero_scratch_hash = {
        cpp_pattern = "page scratch hash area is not zero",
        solidity_signature = "NonZeroScratchHash()",
        solidity_message = "",
    },
    too_few_siblings = {
        cpp_pattern = "too few sibling hashes in log",
        solidity_signature = "TooFewSiblings()",
        solidity_message = "",
    },
    required_page_not_found = {
        cpp_pattern = "required page not found",
        solidity_signature = "RequiredPageNotFound(uint64)",
        solidity_message = "",
    },
    required_node_not_found = {
        cpp_pattern = "required node not found",
        solidity_signature = "RequiredNodeNotFound(uint64)",
        solidity_message = "",
    },
    too_many_pages = {
        cpp_pattern = "too many pages in log",
        solidity_signature = "TooManyPages()",
        solidity_message = "",
    },
    too_many_siblings = {
        cpp_pattern = "too many sibling hashes in log",
        solidity_signature = "TooManySiblings()",
        solidity_message = "",
    },
    reset_uarch_wrong_size = {
        cpp_pattern = "required node not found",
        solidity_signature = "ResetUarchWrongSize(uint64)",
        solidity_message = "",
    },
    root_before_mismatch = {
        cpp_pattern = "root hash before does not match step log",
        solidity_signature = "RootHashBeforeMismatch(bytes32,bytes32)",
        solidity_message = "",
    },
    root_after_mismatch = {
        cpp_pattern = "root hash after does not match claimed hash",
        solidity_signature = "",
        solidity_message = "",
    },
    illegal_instruction = {
        cpp_pattern = "illegal instruction",
        solidity_signature = "RuntimeError(string)",
        solidity_message = "illegal instruction",
    },
    uarch_aborted = {
        cpp_pattern = "uarch aborted",
        solidity_signature = "RuntimeError(string)",
        solidity_message = "uarch aborted",
    },
    unsupported_ecall = {
        cpp_pattern = "unsupported ecall function",
        solidity_signature = "RuntimeError(string)",
        solidity_message = "unsupported ecall function",
    },
    tlb_index_out_of_range = {
        cpp_pattern = "TLB index out of range",
        solidity_signature = "RuntimeError(string)",
        solidity_message = "TLB index out of range",
    },
}

function M.write(dir)
    local out <close> = assert(io.open(dir .. "/_errors.json", "w"))
    assert(out:write(cartesi.tojson(M.errors)))
end

return M
