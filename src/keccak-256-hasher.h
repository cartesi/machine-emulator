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
MULTIVERSION_GENERIC size_t keccak_256_get_optimal_lane_count() noexcept;
MULTIVERSION_GENERIC void keccak_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_GENERIC void keccak_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;

// Optimized implementation for x86_64 architecture leveraging modern CPU instruction sets:
// - BMI1/BMI2 (Bit Manipulation Instructions) provide specialized bit operations:
//   * RORX performs optimized bitwise rotation without requiring separate shift operations
//   * ANDN efficiently computes (~x & y) in a single instruction
// - AVX2 for x4 SIMD hashing
// - AVX-512 for x8 SIMD hashing
#ifdef USE_MULTIVERSINING_AMD64
// AVX2 implementation for x1, x2, x4, x8 SIMD hashing
MULTIVERSION_AMD64_AVX2_BMI_BMI2 size_t keccak_256_get_optimal_lane_count() noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
// AVX-512 implementation for x8 SIMD hashing
MULTIVERSION_AMD64_AVX512_BMI_BMI2 size_t keccak_256_get_optimal_lane_count() noexcept;
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept;
#endif

class keccak_256_hasher final : public i_hasher<keccak_256_hasher> {
public:
    static constexpr int MAX_LANE_COUNT = 8;

    template <size_t ConcatCount, size_t LaneCount, size_t Extent>
    static void do_simd_concat_hash(const array2d<std::span<const unsigned char, Extent>, ConcatCount, LaneCount> &data,
        const std::array<machine_hash_view, LaneCount> &hash) noexcept;

    static size_t do_get_optimal_lane_count() noexcept {
        return keccak_256_get_optimal_lane_count();
    }
};

template <>
inline void keccak_256_hasher::do_simd_concat_hash<1, 1, std::dynamic_extent>(
    const array2d<std::span<const unsigned char>, 1, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_data_1x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<1, 1, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_word_1x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<1, 2, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 2> &data, const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_256_word_1x2(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<1, 4, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 4> &data, const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_256_word_1x4(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<1, 8, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 8> &data, const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_word_1x8(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<1, 16, HASH_TREE_WORD_SIZE>(
    const array2d<const_hash_tree_word_view, 1, 16> &data, const std::array<machine_hash_view, 16> &hash) noexcept {
    // Keccak-256 does not support 16-way parallelism, we simulate it by splitting it into two 8-way hashes
    keccak_256_word_1x8(array2d<const_hash_tree_word_view, 1, 8>{{{
                            data[0][0],
                            data[0][1],
                            data[0][2],
                            data[0][3],
                            data[0][4],
                            data[0][5],
                            data[0][6],
                            data[0][7],
                        }}},
        std::array<machine_hash_view, 8>{
            hash[0],
            hash[1],
            hash[2],
            hash[3],
            hash[4],
            hash[5],
            hash[6],
            hash[7],
        });
    keccak_256_word_1x8(array2d<const_hash_tree_word_view, 1, 8>{{{
                            data[0][8],
                            data[0][9],
                            data[0][10],
                            data[0][11],
                            data[0][12],
                            data[0][13],
                            data[0][14],
                            data[0][15],
                        }}},
        std::array<machine_hash_view, 8>{
            hash[8],
            hash[9],
            hash[10],
            hash[11],
            hash[12],
            hash[13],
            hash[14],
            hash[15],
        });
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<2, 1, std::dynamic_extent>(
    const array2d<std::span<const unsigned char>, 2, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_data_2x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<2, 1, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 1> &data, const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_hash_2x1(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<2, 2, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 2> &data, const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_256_hash_2x2(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<2, 4, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 4> &data, const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_256_hash_2x4(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<2, 8, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 8> &data, const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_hash_2x8(data, hash);
}
template <>
inline void keccak_256_hasher::do_simd_concat_hash<2, 16, MACHINE_HASH_SIZE>(
    const array2d<const_machine_hash_view, 2, 16> &data, const std::array<machine_hash_view, 16> &hash) noexcept {
    // Keccak-256 does not support 16-way parallelism, we simulate it by splitting it into two 8-way hashes
    keccak_256_hash_2x8(array2d<const_machine_hash_view, 2, 8>{{
                            {
                                data[0][0],
                                data[0][1],
                                data[0][2],
                                data[0][3],
                                data[0][4],
                                data[0][5],
                                data[0][6],
                                data[0][7],
                            },
                            {
                                data[1][0],
                                data[1][1],
                                data[1][2],
                                data[1][3],
                                data[1][4],
                                data[1][5],
                                data[1][6],
                                data[1][7],
                            },
                        }},
        std::array<machine_hash_view, 8>{
            hash[0],
            hash[1],
            hash[2],
            hash[3],
            hash[4],
            hash[5],
            hash[6],
            hash[7],
        });
    keccak_256_hash_2x8(array2d<const_machine_hash_view, 2, 8>{{
                            {
                                data[0][8],
                                data[0][9],
                                data[0][10],
                                data[0][11],
                                data[0][12],
                                data[0][13],
                                data[0][14],
                                data[0][15],
                            },
                            {
                                data[1][8],
                                data[1][9],
                                data[1][10],
                                data[1][11],
                                data[1][12],
                                data[1][13],
                                data[1][14],
                                data[1][15],
                            },
                        }},
        std::array<machine_hash_view, 8>{
            hash[8],
            hash[9],
            hash[10],
            hash[11],
            hash[12],
            hash[13],
            hash[14],
            hash[15],
        });
}

} // namespace cartesi

#endif
