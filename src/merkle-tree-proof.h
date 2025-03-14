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

#ifndef MERKLE_TREE_PROOF_H
#define MERKLE_TREE_PROOF_H

/// \file
/// \brief Merkle tree proof structure

#include <algorithm>
#include <cstdint>
#include <ranges>
#include <stdexcept>
#include <type_traits>
#include <vector>

#include "i-hasher.h"
#include "meta.h"

namespace cartesi {

/// \brief Merkle tree proof structure
/// \details \{
/// This structure holds a proof that the node spanning a log2_target_size
/// at a given address in the tree has a certain hash.
/// \}
class merkle_tree_proof final {
public:
    /// \brief Constructs a merkle_tree_proof object and allocates
    /// room for the sibling hashes
    merkle_tree_proof(int log2_root_size, int log2_target_size) :
        m_log2_target_size{log2_target_size},
        m_log2_root_size{log2_root_size},
        m_sibling_hashes(std::max(0, log2_root_size - log2_target_size)) {
        if (log2_root_size <= 0) {
            throw std::out_of_range{"log2_root_size is not positive"};
        }
        if (log2_target_size < 0) {
            throw std::out_of_range{"log2_target_size is negative"};
        }
        if (log2_target_size > log2_root_size) {
            throw std::out_of_range{"log2_target_size is greater than log2_root_size"};
        }
    }

    merkle_tree_proof(const merkle_tree_proof &other) = default;
    merkle_tree_proof(merkle_tree_proof &&other) noexcept = default;
    merkle_tree_proof &operator=(const merkle_tree_proof &other) = default;
    merkle_tree_proof &operator=(merkle_tree_proof &&other) noexcept = default;
    ~merkle_tree_proof() = default;

    /// \brief Storage for the hashes of the siblings of all nodes along
    /// the path from the root node to the target node.
    using sibling_hashes_type = std::vector<machine_hash>;

    /// \brief Gets log<sub>2</sub> of size subintended by entire tree.
    /// \returns log<sub>2</sub> of size subintended by entire tree.
    int get_log2_root_size() const {
        return m_log2_root_size;
    }

    /// \brief Gets log<sub>2</sub> of size subintended by target node.
    /// \returns log<sub>2</sub> of size subintended by target node.
    int get_log2_target_size() const {
        return m_log2_target_size;
    }

    /// \brief Set target node address
    /// \param target_address New address.
    void set_target_address(uint64_t target_address) {
        m_target_address = target_address;
    }

    /// \brief Gets address of target node
    /// \return Reference to hash.
    const uint64_t &get_target_address() const {
        return m_target_address;
    }
    uint64_t &get_target_address() {
        return m_target_address;
    }

    /// \brief Set hash of target node
    /// \param hash New hash.
    void set_target_hash(const_machine_hash_view hash) {
        std::ranges::copy(hash, m_target_hash.begin());
    }

    /// \brief Gets hash of target node
    /// \return Reference to hash.
    const machine_hash &get_target_hash() const {
        return m_target_hash;
    }
    machine_hash &get_target_hash() {
        return m_target_hash;
    }

    /// \brief Set hash of root node
    /// \param hash New hash.
    void set_root_hash(const_machine_hash_view hash) {
        std::ranges::copy(hash, m_root_hash.begin());
    }

    /// \brief Gets hash of root node
    /// \return Reference to hash.
    const machine_hash &get_root_hash() const {
        return m_root_hash;
    }
    machine_hash &get_root_hash() {
        return m_root_hash;
    }

    /// \brief Get hash corresponding to log2_size from the list of siblings.
    /// \param log2_size log<sub>2</sub> of size subintended by hash.
    /// \return Reference to hash inside list of siblings.
    const machine_hash &get_sibling_hash(int log2_size) const {
        return m_sibling_hashes[log2_size_to_index(log2_size)];
    }

    /// \brief Modify hash corresponding to log2_size in the list of siblings.
    /// \param hash New hash.
    /// \param log2_size log<sub>2</sub> of size subintended by hash.
    void set_sibling_hash(const_machine_hash_view hash, int log2_size) {
        std::ranges::copy(hash, m_sibling_hashes[log2_size_to_index(log2_size)].begin());
    }

    const sibling_hashes_type &get_sibling_hashes() const {
        return m_sibling_hashes;
    }

    /// \brief Checks if two Merkle proofs are equal
    bool operator==(const merkle_tree_proof &other) const {
        if (get_log2_target_size() != other.get_log2_target_size()) {
            return false;
        }
        if (get_log2_root_size() != other.get_log2_root_size()) {
            return false;
        }
        if (get_target_address() != other.get_target_address()) {
            return false;
        }
        if (get_root_hash() != other.get_root_hash()) {
            return false;
        }
        if (get_target_hash() != other.get_target_hash()) {
            return false;
        }
        if (m_sibling_hashes != other.m_sibling_hashes) {
            return false;
        }
        return true;
    }

    /// \brief Checks if two Merkle proofs are different
    bool operator!=(const merkle_tree_proof &other) const {
        return !(operator==(other));
    }

    ///< \brief Verify if proof is valid
    ///< \tparam H Hasher class to use
    ///< \param h Hasher object to use
    ///< \return True if proof is valid, false otherwise
    template <IHasher H>
    bool verify(H &&h) const {
        return bubble_up(std::forward<H>(h), get_target_hash()) == get_root_hash();
    }

    ///< \brief Verify if proof is valid
    ///< \tparam H Hasher class to use
    ///< \param h Hasher object to use
    ///< \param new_target_hash New target hash to replace
    ///< \return New root hash
    template <IHasher H>
    // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
    machine_hash bubble_up(H &&h, const machine_hash &new_target_hash) const {
        machine_hash hash = new_target_hash;
        for (int log2_size = get_log2_target_size(); log2_size < get_log2_root_size(); ++log2_size) {
            const int bit = (get_target_address() & (static_cast<uint64_t>(1) << log2_size)) != 0;
            if (bit) {
                get_concat_hash(h, get_sibling_hash(log2_size), hash, hash);
            } else {
                get_concat_hash(h, hash, get_sibling_hash(log2_size), hash);
            }
        }
        return hash;
    }

    template <IHasher H>
    // NOLINTNEXTLINE(cppcoreguidelines-missing-std-forward)
    merkle_tree_proof slice(H &&h, int new_log2_root_size, int new_log2_target_size) const {
        if (new_log2_root_size <= 0) {
            throw std::out_of_range{"log2_root_size is not positive"};
        }
        if (new_log2_target_size < 0) {
            throw std::out_of_range{"log2_target_size is negative"};
        }
        if (new_log2_target_size > new_log2_root_size) {
            throw std::out_of_range{"log2_target_size is greater than log2_root_size"};
        }
        if (new_log2_root_size > get_log2_root_size()) {
            throw std::out_of_range{"log2_root_size is too large"};
        }
        if (new_log2_target_size < get_log2_target_size()) {
            throw std::out_of_range{"log2_target_size is too small"};
        }
        merkle_tree_proof sliced(new_log2_root_size, new_log2_target_size);
        machine_hash hash = get_target_hash();
        for (int log2_size = get_log2_target_size(); log2_size < new_log2_target_size; ++log2_size) {
            const auto bit = (get_target_address() & (static_cast<uint64_t>(1) << log2_size)) != 0;
            if (bit) {
                get_concat_hash(h, get_sibling_hash(log2_size), hash, hash);
            } else {
                get_concat_hash(h, hash, get_sibling_hash(log2_size), hash);
            }
        }
        sliced.set_target_hash(hash);
        for (int log2_size = new_log2_target_size; log2_size < new_log2_root_size; ++log2_size) {
            const auto bit = (get_target_address() & (static_cast<uint64_t>(1) << log2_size)) != 0;
            const machine_hash &sibling_hash = get_sibling_hash(log2_size);
            if (bit) {
                get_concat_hash(h, sibling_hash, hash, hash);
            } else {
                get_concat_hash(h, hash, sibling_hash, hash);
            }
            sliced.set_sibling_hash(sibling_hash, log2_size);
        }
        sliced.set_root_hash(hash);
        sliced.set_target_address((get_target_address() >> new_log2_target_size) << new_log2_target_size);
        if (!sliced.verify(h)) {
            throw std::logic_error{"produced invalid sliced proof"};
        }
        return sliced;
    }

private:
    /// \brief Converts log2_size to index into siblings array
    /// \return Index into siblings array, or throws exception if out of bounds
    int log2_size_to_index(int log2_size) const {
        const int index = log2_size - m_log2_target_size;
        if (index < 0 || index >= static_cast<int>(m_sibling_hashes.size())) {
            throw std::out_of_range{"log2_size is out of range"};
        }
        return index;
    }

    uint64_t m_target_address{0};         ///< Address of target node
    int m_log2_target_size{0};            ///< log<sub>2</sub> of size subintended by target node
    machine_hash m_target_hash{};         ///< Hash of target node
    int m_log2_root_size{0};              ///< log<sub>2</sub> of size subintended by tree
    machine_hash m_root_hash{};           ///< Hash of root node
    sibling_hashes_type m_sibling_hashes; ///< Hashes of siblings in path from target to root
};

} // namespace cartesi

#endif
