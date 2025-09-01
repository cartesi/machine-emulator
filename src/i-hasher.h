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

#include <array>
#include <cstddef>
#include <cstdint>
#include <ranges>
#include <span>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include "array2d.h"
#include "concepts.h"
#include "hash-tree-constants.h"
#include "machine-hash.h"
#include "meta.h"

namespace cartesi {

using hash_tree_word_view = std::span<unsigned char, HASH_TREE_WORD_SIZE>;
using const_hash_tree_word_view = std::span<const unsigned char, HASH_TREE_WORD_SIZE>;

/// \brief Hasher interface.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_hasher { // CRTP
    i_hasher() = default;
    friend DERIVED;

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    static constexpr int MAX_LANE_COUNT = DERIVED::MAX_LANE_COUNT; ///< Number of maximum supported SIMD lanes

    template <ContiguousRangeOfByteLike D>
    void hash(D &&data, machine_hash_view hash) noexcept { // NOLINT(cppcoreguidelines-missing-std-forward)
        const auto data_span =
            std::span<const unsigned char>{// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
                reinterpret_cast<const uint8_t *>(std::ranges::data(data)), std::ranges::size(data)};
        if (data_span.size() == HASH_TREE_WORD_SIZE) { // Special case for hash tree word hashing
            return derived().do_simd_concat_hash(
                array2d<std::span<const unsigned char>, 1, 1>{{{const_hash_tree_word_view{data_span}}}},
                std::array<machine_hash_view, 1>{hash});
        }
        return derived().do_simd_concat_hash(array2d<std::span<const unsigned char>, 1, 1>{{{data_span}}},
            std::array<machine_hash_view, 1>{hash});
    }

    void hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept {
        return derived().do_simd_concat_hash(array2d<const_hash_tree_word_view, 1, 1>{{{data}}},
            std::array<machine_hash_view, 1>{hash});
    }

    template <ContiguousRangeOfByteLike D>
    void concat_hash(D &&data1, D &&data2, // NOLINT(cppcoreguidelines-missing-std-forward)
        machine_hash_view hash) noexcept {
        auto data1_span = std::span<const unsigned char>{// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const uint8_t *>(std::ranges::data(data1)), std::ranges::size(data1)};
        auto data2_span = std::span<const unsigned char>{// NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const uint8_t *>(std::ranges::data(data2)), std::ranges::size(data2)};
        if (data1_span.size() == MACHINE_HASH_SIZE &&
            data2_span.size() == MACHINE_HASH_SIZE) { // Special case for hash tree hash concatenation
            return derived().do_simd_concat_hash(
                array2d<const_machine_hash_view, 2, 1>{
                    {{const_machine_hash_view{data1_span}}, {const_machine_hash_view{data2_span}}}},
                std::array<machine_hash_view, 1>{hash});
        }
        return derived().do_simd_concat_hash(
            array2d<std::span<const unsigned char>, 2, 1>{{{data1_span}, {data2_span}}},
            std::array<machine_hash_view, 1>{hash});
    }

    void concat_hash(const_machine_hash_view data1, const_machine_hash_view data2, machine_hash_view hash) noexcept {
        return derived().do_simd_concat_hash(array2d<const_machine_hash_view, 2, 1>{{{data1}, {data2}}},
            std::array<machine_hash_view, 1>{hash});
    }

    // \brief Hashes the concatenation of data using multiple SIMD lanes.
    // \tparam LaneCount Number of SIMD lanes
    // \tparam ConcatCount Number of concatenated data items
    // \tparam Extent Extent of the data span
    // \param data Data to hash, as a multi-dimensional array of spans
    // \param hash Array of machine hashes to store the results
    // \warning When LaneCount is greater than 1, it is assumed data spans have same size, there is no check for that.
    template <size_t ConcatCount, size_t ParallelCount>
    void simd_concat_hash(const array2d<const_hash_tree_word_view, ConcatCount, ParallelCount> &data,
        const std::array<machine_hash_view, ParallelCount> &hash) noexcept {
        return derived().do_simd_concat_hash(data, hash);
    }

    // \brief Gets the optimal number of SIMD lanes for hashing.
    // \returns The optimal number of SIMD lanes for hashing.
    // \details This value is architecture-dependent and may vary based on the available instruction sets.
    size_t get_optimal_lane_count() const noexcept {
        return derived().do_get_optimal_lane_count();
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
template <IHasher H, ContiguousRangeOfByteLike D>
inline static void get_hash(H &h, D &&data, machine_hash_view result) noexcept {
    h.hash(std::forward<D>(data), result);
}

/// \brief Computes the hash of data
/// \tparam H Hasher class
/// \param h Hasher object
/// \param data Data to hash
/// \returns The hash of data
template <IHasher H, ContiguousRangeOfByteLike D>
inline static machine_hash get_hash(H &&h, D &&data) noexcept {
    machine_hash result;
    get_hash(std::forward<H>(h), std::forward<D>(data), result);
    return result;
}

/// \brief Computes the hash of concatenated hashes
/// \tparam H Hasher class
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \param result Receives the hash of the concatenation
template <IHasher H>
inline static void get_concat_hash(H &h, const_machine_hash_view left, const_machine_hash_view right,
    machine_hash_view result) noexcept {
    h.concat_hash(left, right, result);
}

/// \brief Computes the hash of concatenated hashes
/// \tparam H Hasher class
/// \param h Hasher object
/// \param left Left hash to concatenate
/// \param right Right hash to concatenate
/// \return The hash of the concatenation
template <IHasher H>
inline static machine_hash get_concat_hash(H &&h, const_machine_hash_view left,
    const_machine_hash_view right) noexcept {
    machine_hash result;
    get_concat_hash(std::forward<H>(h), left, right, result);
    return result;
}

/// \brief  Computes a merkle tree hash of a data buffer
/// \tparam H Hasher class
/// \tparam D Contiguous range class
/// \param h Hasher object
/// \param data Data to be hashed
/// \param leaf_length  Length of each leaf
/// \param result Receives the resulting merkle tree hash
template <IHasher H, ContiguousRangeOfByteLike D>
inline static void get_merkle_tree_hash(H &&h, D &&data, uint64_t leaf_length, machine_hash_view result) {
    const auto size = std::ranges::size(data);
    if (size > leaf_length) {
        if (size & 1) {
            throw std::invalid_argument("data size must be a power of 2 multiple of leaf_length");
        }
        machine_hash left;
        const auto half_size = size >> 1;
        auto start = std::ranges::begin(data);
        get_merkle_tree_hash(h, std::ranges::subrange(start, start + half_size), leaf_length, left);
        get_merkle_tree_hash(h, std::ranges::subrange(start + half_size, start + size), leaf_length, result);
        get_concat_hash(h, left, result, result);
    } else {
        if (size != leaf_length) {
            throw std::invalid_argument("data size must be a power of 2 multiple of leaf length");
        }
        //??D we use universal references so the function works with non-const l- and r-value references
        //??D forwarding just to silence linter.
        get_hash(std::forward<H>(h), std::forward<D>(data), result);
    }
}

/// \brief  Computes a merkle tree hash of a data buffer
/// \tparam H Hasher class
/// \tparam D Contiguous range class
/// \param h Hasher object
/// \param data Data to be hashed
/// \param leaf_length  Length of each leaf
/// \returns The resulting merkle tree hash
template <IHasher H, ContiguousRangeOfByteLike D>
inline static machine_hash get_merkle_tree_hash(H &&h, D &&data, uint64_t leaf_length) {
    machine_hash hash;
    get_merkle_tree_hash(std::forward<H>(h), std::forward<D>(data), leaf_length, hash);
    return hash;
}

} // namespace cartesi

#endif
