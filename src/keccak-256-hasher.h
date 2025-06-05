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

#ifndef KECCAK_256_HASHER_H
#define KECCAK_256_HASHER_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "array2d.h"
#include "compiler-defines.h"
#include "i-hasher.h"
#include "machine-hash.h"

namespace cartesi {

// Generic implementations
MULTIVERSION_GENERIC void keccak_data_1x1(const array2d<std::span<const uint8_t>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_data_2x1(const array2d<std::span<const uint8_t>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;

// Optimized implementation for x86_64 architecture leveraging modern CPU instruction sets:
// - BMI1/BMI2 (Bit Manipulation Instructions) provide specialized bit operations:
//   * RORX performs optimized bitwise rotation without requiring separate shift operations
//   * ANDN efficiently computes (~x & y) in a single instruction
// - AVX2 for parallel hashing
// - AVX-512 for x8 parallel hashing
#ifdef USE_MULTIVERSINING_AMD64
// AVX2 implementation for x1, x2, x4, x8 parallel hashing
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_data_1x1(const array2d<std::span<const uint8_t>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_data_2x1(const array2d<std::span<const uint8_t>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
// AVX-512 implementation for x8 parallel hashing
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
#endif

class keccak_256_hasher final : public i_hasher<keccak_256_hasher> {
public:
    /// \brief Default constructor
    keccak_256_hasher() = default;

    /// \brief Default destructor
    ~keccak_256_hasher() = default;

    /// \brief No copy constructor
    keccak_256_hasher(const keccak_256_hasher &) = delete;
    /// \brief No move constructor
    keccak_256_hasher(keccak_256_hasher &&) = delete;
    /// \brief No copy assignment
    keccak_256_hasher &operator=(const keccak_256_hasher &) = delete;
    /// \brief No move assignment
    keccak_256_hasher &operator=(keccak_256_hasher &&) = delete;

    // \brief Hashes the concatenation of data in parallel using keccak
    // \tparam ParallelCount Number of parallel hashes
    // \tparam ConcatCount Number of concatenated data items
    // \tparam Extent Extent of the data span
    // \param data Data to hash, as a multi-dimensional array of spans
    // \param hash Array of machine hashes to store the results
    // \warning When parallel hashing is used, it is assumed data spans have same size, there is no check for that.
    template <size_t ConcatCount, size_t ParallelCount, size_t Extent>
    static void do_parallel_concat_hash(
        const array2d<std::span<const uint8_t, Extent>, ConcatCount, ParallelCount> &data,
        const std::array<machine_hash_view, ParallelCount> &hash) noexcept;
};

template <>
inline void keccak_256_hasher::do_parallel_concat_hash<1, 1, std::dynamic_extent>(
    const array2d<std::span<const uint8_t>, 1, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_data_1x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<1, 1, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_word_1x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<1, 2, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 2> &data, const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_word_1x2(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<1, 4, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 4> &data, const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_word_1x4(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<1, 8, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 8> &data, const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_word_1x8(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<2, 1, std::dynamic_extent>(
    const array2d<std::span<const uint8_t>, 2, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_data_2x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<2, 1, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_hash_2x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<2, 2, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 2> &data, const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_hash_2x2(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<2, 4, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 4> &data, const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_hash_2x4(data, hash);
}
template <>
inline void keccak_256_hasher::do_parallel_concat_hash<2, 8, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 8> &data, const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_hash_2x8(data, hash);
}

} // namespace cartesi

#endif
