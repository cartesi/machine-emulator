// Copyright 2021 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//

#ifndef PRISTINE_MERKLE_TREE_H
#define PRISTINE_MERKLE_TREE_H

#include <cstdint>
#include <vector>

#include "meta.h"
#include "keccak-256-hasher.h"

namespace cartesi {

/// \brief Hashes of pristine subtrees for a range of sizes
class pristine_merkle_tree {
public:

    /// \brief Hasher class.
    using hasher_type = keccak_256_hasher;

    /// \brief Storage for a hash.
    using hash_type = hasher_type::hash_type;

    using address_type = uint64_t;

    pristine_merkle_tree(int log2_root_size, int log2_word_size):
        m_log2_root_size{log2_root_size},
        m_log2_word_size{log2_word_size},
        m_hashes(std::max(0, log2_root_size-log2_word_size+1)) {
        if (log2_root_size < 0) {
            throw std::out_of_range{
                "log2_root_size is negative"};
        }
        if (log2_word_size < 0) {
            throw std::out_of_range{
                "log2_word_size is negative"};
        }
        if (log2_word_size > log2_root_size) {
            throw std::out_of_range{
                "log2_word_size is greater than log2_root_size"};
        }
        std::vector<uint8_t> word(1 << log2_word_size, 0);
        assert(word.size() == (1 << log2_word_size));
        hasher_type h;
        h.begin();
        h.add_data(word.data(), word.size());
        h.end(m_hashes[0]);
        for (unsigned i = 1; i < m_hashes.size(); ++i) {
            get_concat_hash(h, m_hashes[i-1], m_hashes[i-1], m_hashes[i]);
        }
    }

    /// \brief Returns hash of pristine subtree
    /// \param log2_size Log<sub>2</sub> of subtree size. Must be between
    /// log2_word_size (inclusive) and log2_root_size (inclusive) passed
    /// to constructor.
    const hash_type &get_hash(int log2_size) const {
        if (log2_size < m_log2_word_size || log2_size > m_log2_root_size) {
            throw std::out_of_range{"log2_size is out of range"};
        }
        return m_hashes[log2_size-m_log2_word_size];
    }

private:

    int m_log2_root_size;            ///< Log<sub>2</sub> of tree size
    int m_log2_word_size;            ///< Log<sub>2</sub> of word size
    std::vector<hash_type> m_hashes; ///< Vector with hashes

};

} // namespace cartesi

#endif
