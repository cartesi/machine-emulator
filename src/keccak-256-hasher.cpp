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

#include "keccak-256-hasher.h"
#include "compiler-defines.h"
#include "keccakf.h"
#include "machine-hash.h"

#include <cstddef>
#include <cstdint>
#include <span>

namespace cartesi {

// NOLINTNEXTLINE(misc-redundant-expression)
static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");

// ??(edubart): These constants are defined as macros instead of constexpr because GCC 12 (uarch toolchain GCC)
// is crashing when using the constants with UNROLL_LOOP.
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#define KECCAK_HASH_SIZE 32
#define MAX_LANE_COUNT 8
#define MAX_CONCAT_COUNT 8
#define TUNED_DATA_SIZE 32
#define CACHE_LINE_SIZE 64
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

constexpr size_t KECCAK_WORD_COUNT = 25;
constexpr size_t KECCAK_RSIZE = (KECCAK_WORD_COUNT * sizeof(uint64_t)) - (static_cast<size_t>(2) * KECCAK_HASH_SIZE);

template <size_t LaneCount>
struct uint64_vector_type;

template <>
struct uint64_vector_type<1> {
    using type = uint64_t;
};

template <>
struct uint64_vector_type<2> {
    using type = uint64_t __attribute__((vector_size(16)));
};

template <>
struct uint64_vector_type<4> {
    using type = uint64_t __attribute__((vector_size(32)));
};

template <>
struct uint64_vector_type<8> {
    using type = uint64_t __attribute__((vector_size(64)));
};

// NOLINTBEGIN(cppcoreguidelines-pro-type-union-access)

template <size_t LaneCount>
struct alignas(CACHE_LINE_SIZE) keccak_ctx final {
    using vector_type = uint64_vector_type<LaneCount>::type;
    union {
        vector_type words[5][5];                                       // 64-bit words
        uint8_t bytes[KECCAK_WORD_COUNT][LaneCount][sizeof(uint64_t)]; // 8-bit bytes
    } state{};
    size_t pos{};

    template <size_t SpanExtent>
    FORCE_INLINE void update(const std::array<std::span<const unsigned char, SpanExtent>, LaneCount> &data) noexcept {
        const size_t len = data[0].size();
        for (size_t i = 0; i < len;) {
            // Interleave data while XORing
            const size_t step = std::min(KECCAK_RSIZE - pos, len - i);
            UNROLL_LOOP(TUNED_DATA_SIZE)
            for (size_t j = 0; j < step; j++) {
                const size_t x = (pos + j) / sizeof(uint64_t);
                const size_t z = (pos + j) % sizeof(uint64_t);
                UNROLL_LOOP(MAX_LANE_COUNT)
                for (size_t y = 0; y < LaneCount; ++y) {
                    state.bytes[x][y][z] ^= data[y][i + j];
                }
            }
            i += step;
            pos += step;
            // Perform keccak permutation
            if (unlikely(pos >= KECCAK_RSIZE)) {
                keccakf(state.words);
                pos = 0;
            }
        }
    }

    FORCE_INLINE void final(const std::array<machine_hash_view, LaneCount> &hashes) noexcept {
        // Perform last keccak permutation
        const size_t x = pos / sizeof(uint64_t);
        const size_t z = pos % sizeof(uint64_t);
        UNROLL_LOOP(MAX_LANE_COUNT)
        for (size_t y = 0; y < LaneCount; ++y) {
            constexpr uint8_t KECCAK_DSUFFIX = 0x01;
            state.bytes[x][y][z] ^= KECCAK_DSUFFIX;
            constexpr size_t lx = (KECCAK_RSIZE - 1) / sizeof(uint64_t);
            constexpr size_t lz = (KECCAK_RSIZE - 1) % sizeof(uint64_t);
            state.bytes[lx][y][lz] ^= 0x80;
        }
        keccakf(state.words);
        // Deinterleave hash
        UNROLL_LOOP(KECCAK_HASH_SIZE)
        for (size_t i = 0; i < KECCAK_HASH_SIZE; i++) {
            const size_t x = i / sizeof(uint64_t);
            const size_t z = i % sizeof(uint64_t);
            UNROLL_LOOP(MAX_LANE_COUNT)
            for (size_t y = 0; y < LaneCount; ++y) {
                hashes[y][i] = state.bytes[x][y][z];
            }
        }
    }
    template <size_t ConcatCount, size_t SpanExtent>
    static FORCE_INLINE void simd_concat_hash(
        array2d<std::span<const unsigned char, SpanExtent>, ConcatCount, LaneCount> data,
        std::array<machine_hash_view, LaneCount> hashes) noexcept {
        keccak_ctx ctx;
        UNROLL_LOOP(MAX_CONCAT_COUNT)
        for (size_t i = 0; i < ConcatCount; ++i) {
            ctx.update(data[i]);
        }
        ctx.final(hashes);
    }
};

// NOLINTEND(cppcoreguidelines-pro-type-union-access)

// Generic implementations

MULTIVERSION_GENERIC void keccak_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash<1>(data, hash);
}
MULTIVERSION_GENERIC void keccak_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_ctx<2>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_ctx<4>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_ctx<8>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_ctx<2>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_ctx<4>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_ctx<8>::simd_concat_hash(data, hash);
}

// x86_64 implementations

#ifdef USE_MULTIVERSINING_AMD64

MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash<1>(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_ctx<2>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_ctx<4>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_ctx<4>::simd_concat_hash(array2d<const_hash_tree_word_view, 1, 4>{{{
                                        data[0][0],
                                        data[0][1],
                                        data[0][2],
                                        data[0][3],
                                    }}},
        std::array<machine_hash_view, 4>{
            hash[0],
            hash[1],
            hash[2],
            hash[3],
        });
    keccak_ctx<4>::simd_concat_hash(array2d<const_hash_tree_word_view, 1, 4>{{{
                                        data[0][4],
                                        data[0][5],
                                        data[0][6],
                                        data[0][7],
                                    }}},
        std::array<machine_hash_view, 4>{
            hash[4],
            hash[5],
            hash[6],
            hash[7],
        });
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_ctx<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_ctx<2>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_ctx<4>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_ctx<4>::simd_concat_hash(array2d<const_machine_hash_view, 2, 4>{{
                                        {
                                            data[0][0],
                                            data[0][1],
                                            data[0][2],
                                            data[0][3],
                                        },
                                        {
                                            data[1][0],
                                            data[1][1],
                                            data[1][2],
                                            data[1][3],
                                        },
                                    }},
        std::array<machine_hash_view, 4>{
            hash[0],
            hash[1],
            hash[2],
            hash[3],
        });
    keccak_ctx<4>::simd_concat_hash(array2d<const_machine_hash_view, 2, 4>{{
                                        {
                                            data[0][4],
                                            data[0][5],
                                            data[0][6],
                                            data[0][7],
                                        },
                                        {
                                            data[1][4],
                                            data[1][5],
                                            data[1][6],
                                            data[1][7],
                                        },
                                    }},
        std::array<machine_hash_view, 4>{
            hash[4],
            hash[5],
            hash[6],
            hash[7],
        });
}
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_ctx<8>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_ctx<8>::simd_concat_hash(data, hash);
}
#endif

} // namespace cartesi
