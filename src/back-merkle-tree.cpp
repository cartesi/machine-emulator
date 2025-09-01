// Copyright Cartesi and individual authors (see AUTHORS)
// SPDX-License-Identifier: LGPL-3.0-or-later
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License along
// with this program (see COPYING). If not, see <https://www.gnu.org/licenses/>.
//

/// \file
/// \brief Back merkle tree implementation.

#include "back-merkle-tree.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

#include "machine-hash.h"
#include "variant-hasher.h"

namespace cartesi {

int back_merkle_tree::validate_log2_max_leaves_size(int log2_root_size, int log2_leaf_size, int log2_word_size) {
    if (log2_root_size < 0) {
        throw std::out_of_range{"log2_root_size is negative"};
    }
    if (log2_leaf_size < 0) {
        throw std::out_of_range{"log2_leaf_size is negative"};
    }
    if (log2_word_size < 0) {
        throw std::out_of_range{"log2_word_size is negative"};
    }
    if (log2_leaf_size > log2_root_size) {
        throw std::out_of_range{"log2_leaf_size is greater than log2_root_size"};
    }
    if (log2_word_size > log2_leaf_size) {
        throw std::out_of_range{"log2_word_size is greater than log2_leaf_size"};
    }
    if (log2_root_size - log2_leaf_size >= std::numeric_limits<uint64_t>::digits) {
        throw std::out_of_range{"log2_root_size is too large"};
    }
    return log2_root_size - log2_leaf_size;
}

void back_merkle_tree::push_back(const machine_hash &new_leaf_hash) {
    variant_hasher h{m_hash_function};
    machine_hash right = new_leaf_hash;
    if (m_leaf_count >= get_max_leaves()) {
        throw std::out_of_range{"too many leaves"};
    }
    const size_t log2_max_leaves = get_log2_max_leaves();
    for (size_t i = 0; i <= log2_max_leaves; ++i) {
        const auto i_span = UINT64_C(1) << i;
        if ((m_leaf_count & i_span) != 0) {
            const auto &left = m_context[i];
            h.concat_hash(left, right, right);
        } else {
            m_context[i] = right;
            break;
        }
    }
    ++m_leaf_count;
}

void back_merkle_tree::pad_back(uint64_t new_leaf_count, const machine_hashes &pad_hashes) {
    if (new_leaf_count == 0) {
        return;
    }
    const size_t max_leaves = get_max_leaves();
    const size_t log2_max_leaves = get_log2_max_leaves();

    // Validate inputs
    if (new_leaf_count > max_leaves || m_leaf_count + new_leaf_count > max_leaves) {
        throw std::invalid_argument{"too many leaves"};
    }
    if (pad_hashes.size() != log2_max_leaves + 1) {
        throw std::invalid_argument{"pad hashes does not have expected size"};
    }

    variant_hasher h{m_hash_function};

    // Process each bit position from LSB to MSB
    for (size_t j = 0; j <= log2_max_leaves;) {
        const uint64_t j_span = UINT64_C(1) << j;

        // Skip if this bit isn't set in new_leaf_count
        if (j_span > new_leaf_count) {
            break;
        }

        // Check if we have an existing subtree at this position
        if ((m_leaf_count & j_span) != 0) { // Is our smallest tree at depth j?
            // Combine existing subtree with padding and propagate upward
            auto right = pad_hashes[j];
            for (size_t i = j; i <= log2_max_leaves; ++i) {
                const uint64_t i_span = UINT64_C(1) << i;
                if ((m_leaf_count & i_span) != 0) {
                    const auto &left = m_context[i];
                    h.concat_hash(left, right, right);
                } else {
                    m_context[i] = right;
                    // Outer loop continues where we left off
                    j = i;
                    break;
                }
            }
            m_leaf_count += j_span;
            new_leaf_count -= j_span;
        } else {
            ++j;
        }
    }

    // Add the rest of the padding directly to the context
    for (size_t i = 0; i <= log2_max_leaves && new_leaf_count > 0; ++i) {
        const uint64_t i_span = UINT64_C(1) << i;
        // Check if we have to set the subtree at this position
        if ((new_leaf_count & i_span) != 0) {
            m_context[i] = pad_hashes[i];
            m_leaf_count += i_span;
            new_leaf_count -= i_span;
        }
    }

    assert(new_leaf_count == 0);
    assert(m_leaf_count <= get_max_leaves());
}

machine_hashes back_merkle_tree::make_pad_hashes(const machine_hash &leaf_hash, int log2_max_leaves,
    hash_function_type hash_function) {
    assert(log2_max_leaves >= 0);
    machine_hashes hashes;
    hashes.resize(log2_max_leaves + 1);
    hashes[0] = leaf_hash;
    variant_hasher h{hash_function};
    for (size_t i = 1; i < hashes.size(); ++i) {
        h.concat_hash(hashes[i - 1], hashes[i - 1], hashes[i]);
    }
    return hashes;
}

static machine_hash get_pristine_word_hash(int log2_word_size, hash_function_type hash_function) {
    std::vector<uint8_t> word(UINT64_C(1) << log2_word_size, 0);
    machine_hash hash{};
    variant_hasher h{hash_function};
    h.hash(word, hash);
    return hash;
}

machine_hashes back_merkle_tree::make_pristine_pad_hashes(int log2_root_size, int log2_leaf_size, int log2_word_size,
    hash_function_type hash_function) {
    validate_log2_max_leaves_size(log2_root_size, log2_leaf_size, log2_word_size);
    auto pristine_pad_hashes = make_pad_hashes(get_pristine_word_hash(log2_word_size, hash_function),
        log2_root_size - log2_word_size, hash_function);
    if (log2_leaf_size > log2_word_size) {
        pristine_pad_hashes.erase(pristine_pad_hashes.begin(),
            pristine_pad_hashes.begin() + (log2_leaf_size - log2_word_size));
    }
    return pristine_pad_hashes;
}

} // namespace cartesi
