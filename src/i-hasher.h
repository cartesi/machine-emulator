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

#ifndef I_HASHER_H
#define I_HASHER_H

/// \file
/// \brief Hasher class

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <type_traits>
#include <variant>

#include "hash-tree-target.h"
#include "keccak-256-hasher.h"
#include "machine-config.h"
#include "machine-hash.h"
#include "meta.h"
#include "sha-256-hasher.h"

namespace cartesi {

/// \brief Hasher interface
class i_hasher {
    hash_tree_target m_hash_tree_target;
    std::variant<keccak_256_hasher, sha_256_hasher> m_hasher;

    /// \brief Constructor
    /// \param hash_tree_target Hash tree target.
    /// \details The actual hashing algorithm is selected based on the hash tree target.
    explicit i_hasher(hash_tree_target hash_tree_target) : m_hash_tree_target(hash_tree_target) {
        switch (hash_tree_target) {
            case hash_tree_target::uarch:
                m_hasher = keccak_256_hasher();
                break;
            case hash_tree_target::risc0:
                m_hasher = sha_256_hasher();
                break;
        }
    }

public:
    /// \brief Returns the hash tree target
    hash_tree_target get_hash_tree_target() const {
        return m_hash_tree_target;
    }

    /// \brief Begins the hashing process
    void begin() {
        std::visit([](auto &h) { h.begin(); }, m_hasher);
    }

    /// \brief Adds data to the hash
    /// \param data Pointer to the data to be added
    /// \param length Length of the data to be added
    void add_data(const unsigned char *data, size_t length) {
        std::visit([data, length](auto &h) { h.add_data(data, length); }, m_hasher);
    }

    /// \brief Finalizes the hash
    /// \param hash Receives the resulting hash
    void end(machine_hash &hash) {
        std::visit([&hash](auto &h) { h.end(hash); }, m_hasher);
    }

    /// \brief Creates a hasher object
    static i_hasher make_uarch() {
        return make(hash_tree_target::uarch);
    }

    /// \brief Creates a hasher object
    static i_hasher make_risc0() {
        return make(hash_tree_target::risc0);
    }

    /// \brief Creates a hasher object
    static i_hasher make(hash_tree_target hash_tree_target) {
        switch (hash_tree_target) {
            case hash_tree_target::uarch:
                return i_hasher(hash_tree_target::uarch);
            case hash_tree_target::risc0:
                return i_hasher(hash_tree_target::risc0);
        }
    }

    /// \brief Computes the hash of concatenated hashes
    /// \param h Hasher object
    /// \param left Left hash to concatenate
    /// \param right Right hash to concatenate
    /// \param result Receives the hash of the concatenation
    void get_concat_hash(const machine_hash &left, const machine_hash &right, machine_hash &result) {
        begin();
        add_data(left.data(), static_cast<int>(left.size()));
        add_data(right.data(), static_cast<int>(right.size()));
        end(result);
    }

    /// \brief  Computes a merkle tree hash of a data buffer
    /// \param h Hasher object
    /// \param data Data to be hashed
    /// \param data_length Length of data
    /// \param word_length  Length of each word
    /// \param result Receives the resulting merkle tree hash
    void get_merkle_tree_hash(const unsigned char *data, uint64_t data_length, uint64_t word_length,
        machine_hash &result) {
        if (data_length > word_length) {
            if ((data_length & 1) != 0) {
                throw std::invalid_argument("data_length must be a power of 2 multiple of word_length");
            }
            data_length = data_length / 2;
            machine_hash left;
            get_merkle_tree_hash(data, data_length, word_length, left);
            get_merkle_tree_hash(data + data_length, data_length, word_length, result);
            begin();
            add_data(left.data(), left.size());
            add_data(result.data(), result.size());
            end(result);
        } else {
            if (data_length != word_length) {
                throw std::invalid_argument("data_length must be a power of 2 multiple of word_length");
            }
            begin();
            add_data(data, data_length);
            end(result);
        }
    }
};

} // namespace cartesi

#endif
