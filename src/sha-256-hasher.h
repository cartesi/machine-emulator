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

#ifndef SHA_256_HASHER_H
#define SHA_256_HASHER_H

#include <array>
#include <cstddef>
#include <span>

#include "array2d.h"
#include "compiler-defines.h"
#include "hash-tree-constants.h"
#include "i-hasher.h"
#include "machine-hash.h"

namespace cartesi {

// Generic implementations
MULTIVERSION_GENERIC size_t sha_256_get_optimal_lane_count() noexcept;
MULTIVERSION_GENERIC void sha_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_word_1x16(const array2d<const_hash_tree_word_view, 1, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_GENERIC void sha_256_hash_2x16(const array2d<const_machine_hash_view, 2, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept;

// Optimized implementation for x86_64 architecture leveraging modern CPU instruction sets:
// - BMI1/BMI2 (Bit Manipulation Instructions) provide specialized bit operations:
//   * RORX performs optimized bitwise rotation without requiring separate shift operations
//   * ANDN efficiently computes (~x & y) in a single instruction
// - AVX2 for x8 SIMD hashing
// - AVX-512 for x16 SIMD hashing
#ifdef USE_MULTIVERSINING_AMD64
// AVX2 implementation for x1, x2, x4, x8, x16 SIMD hashing
MULTIVERSION_AMD64_AVX2_BMI_BMI2 size_t sha_256_get_optimal_lane_count() noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x16(const array2d<const_hash_tree_word_view, 1, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x16(const array2d<const_machine_hash_view, 2, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept;
// AVX-512 implementation for x16 SIMD hashing
MULTIVERSION_AMD64_AVX512_BMI_BMI2 size_t sha_256_get_optimal_lane_count() noexcept;
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void sha_256_word_1x16(const array2d<const_hash_tree_word_view, 1, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept;
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void sha_256_hash_2x16(const array2d<const_machine_hash_view, 2, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept;
#endif

class sha_256_hasher final : public i_hasher<sha_256_hasher> {
public:
    sha_256_hasher() = default;

    static constexpr int MAX_LANE_COUNT = 16; ///< Number of maximum supported SIMD lanes

    template <size_t ConcatCount, size_t LaneCount, size_t Extent>
    static void do_simd_concat_hash(const array2d<std::span<const unsigned char, Extent>, ConcatCount, LaneCount> &data,
        const std::array<machine_hash_view, LaneCount> &hash) noexcept;

    static size_t do_get_optimal_lane_count() noexcept {
        return sha_256_get_optimal_lane_count();
    }
};

template <>
inline void sha_256_hasher::do_simd_concat_hash<1, 1, std::dynamic_extent>(
    const array2d<std::span<const unsigned char>, 1, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_data_1x1(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<1, 1, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_word_1x1(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<1, 2, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 2> &data, const std::array<machine_hash_view, 2> &hash) noexcept {
    sha_256_word_1x2(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<1, 4, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 4> &data, const std::array<machine_hash_view, 4> &hash) noexcept {
    sha_256_word_1x4(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<1, 8, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 8> &data, const std::array<machine_hash_view, 8> &hash) noexcept {
    sha_256_word_1x8(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<1, 16, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 16> &data, const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_word_1x16(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<2, 1, std::dynamic_extent>(
    const array2d<std::span<const unsigned char>, 2, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_data_2x1(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<2, 1, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_hash_2x1(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<2, 2, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 2> &data, const std::array<machine_hash_view, 2> &hash) noexcept {
    sha_256_hash_2x2(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<2, 4, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 4> &data, const std::array<machine_hash_view, 4> &hash) noexcept {
    sha_256_hash_2x4(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<2, 8, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 8> &data, const std::array<machine_hash_view, 8> &hash) noexcept {
    sha_256_hash_2x8(data, hash);
}
template <>
inline void sha_256_hasher::do_simd_concat_hash<2, 16, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 16> &data, const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_hash_2x16(data, hash);
}

} // namespace cartesi

#endif
