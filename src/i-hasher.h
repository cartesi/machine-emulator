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
/// \brief Hasher interface

#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <stdexcept>
#include <type_traits>

#include "machine-hash.h"
#include "meta.h"

namespace cartesi {

/// \brief Hasher interface.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_hasher { // CRTP
    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    void begin() {
        return derived().do_begin();
    }

    template <std::ranges::contiguous_range R>
    void add_data(const R &r)
        requires ByteLike<std::ranges::range_value_t<R>>
    {
        return derived().do_add_data(r);
    }

    void end(machine_hash_view hash) {
        return derived().do_end(hash);
    }
};

template <typename DERIVED>
using is_an_i_hasher = std::integral_constant<bool, is_template_base_of_v<i_hasher, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_hasher_v = is_an_i_hasher<DERIVED>::value;

// C++20 concept for is_an_i_hasher_v
template <typename T>
concept IHasher = is_an_i_hasher_v<T>;

/// \brief Computes the hash of data
/// \tparam H Hasher class
/// \param h Hasher object
/// \param data Data to hash
/// \param result Receives the hash of data
template <IHasher H, std::ranges::contiguous_range R>
inline static void get_hash(H &h, R data, machine_hash_view result)
        requires ByteLike<std::ranges::range_value_t<R>>
{
    h.begin();
    h.add_data(data);
    h.end(result);
}

/// \brief Computes the hash of concatenated hashes
/// \tparam H Hasher class
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \param result Receives the hash of the concatenation
template <IHasher H>
inline static void get_concat_hash(H &h, const_machine_hash_view left, const_machine_hash_view right,
    machine_hash_view result) {
    h.begin();
    h.add_data(left);
    h.add_data(right);
    h.end(result);
}

/// \brief Computes the hash of concatenated hashes
/// \tparam H Hasher class
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \return The hash of the concatenation
template <IHasher H>
inline static machine_hash get_concat_hash(H &h, const_machine_hash_view left, const_machine_hash_view right) {
    machine_hash result;
    get_concat_hash(h, left, right, result);
    return result;
}

/// \brief  Computes a merkle tree hash of a data buffer
/// \tparam H Hasher class
/// \tparam D Contiguous range class
/// \param h Hasher object
/// \param data Data to be hashed
/// \param word_length  Length of each word
/// \param result Receives the resulting merkle tree hash
template <IHasher H, std::ranges::contiguous_range D>
inline static void get_merkle_tree_hash(H &h, const D &data, uint64_t word_length, machine_hash_view result)
    requires ByteLike<std::ranges::range_value_t<D>>
{
    const auto size = std::ranges::size(data);
    if (size > word_length) {
        if (size & 1) {
            throw std::invalid_argument("data size must be a power of 2 multiple of word_length");
        }
        machine_hash left;
        const auto half_size = size >> 1;
        auto start = std::ranges::begin(data);
        get_merkle_tree_hash(h, std::ranges::subrange(start, start + half_size), word_length, left);
        get_merkle_tree_hash(h, std::ranges::subrange(start + half_size, start + size), word_length, result);
        get_concat_hash(h, left, result, result);
    } else {
        if (size != word_length) {
            throw std::invalid_argument("data size must be a power of 2 multiple of word_length");
        }
        get_hash(h, data, result);
    }
}

} // namespace cartesi

#endif
