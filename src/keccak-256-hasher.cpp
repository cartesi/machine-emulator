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

namespace cartesi {

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");

// ??(edubart): These constants are defined as macros instead of constexpr because GCC 12 (uarch toolchain GCC)
// is crashing when using the constants with UNROLL_LOOP.
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#define KECCAK_HASH_SIZE 32
#define MAX_PARALLEL_COUNT 8
#define MAX_CONCAT_COUNT 8
#define TUNED_DATA_SIZE 32
#define CACHE_LINE_SIZE 64
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)

constexpr size_t KECCAK_WORD_COUNT = 25;
constexpr size_t KECCAK_RSIZE = (KECCAK_WORD_COUNT * sizeof(uint64_t)) - (static_cast<size_t>(2) * KECCAK_HASH_SIZE);

template <size_t ParallelCount>
struct uint64_vector_type {
    using type = uint64_t __attribute__((vector_size(64)));
};

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

template <size_t ParallelCount>
struct alignas(CACHE_LINE_SIZE) keccak_ctx final {
    using vector_type = uint64_vector_type<ParallelCount>::type;
    union {
        vector_type words[5][5];                                           // 64-bit words
        uint8_t bytes[KECCAK_WORD_COUNT][ParallelCount][sizeof(uint64_t)]; // 8-bit bytes
    } state{};
    size_t pos{};

    template <size_t SpanExtent>
    FORCE_INLINE void update(const std::array<std::span<const uint8_t, SpanExtent>, ParallelCount> &data) noexcept {
        const size_t len = data[0].size();
        for (size_t i = 0; i < len;) {
            // Interleave data while XORing
            const size_t step = std::min(KECCAK_RSIZE - pos, len - i);
            UNROLL_LOOP(TUNED_DATA_SIZE)
            for (size_t j = 0; j < step; j++) {
                const size_t x = (pos + j) / sizeof(uint64_t);
                const size_t z = (pos + j) % sizeof(uint64_t);
                UNROLL_LOOP(MAX_PARALLEL_COUNT)
                for (size_t y = 0; y < ParallelCount; ++y) {
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

    FORCE_INLINE void final(const std::array<machine_hash_view, ParallelCount> &hashes) noexcept {
        // Perform last keccak permutation
        const size_t x = pos / sizeof(uint64_t);
        const size_t z = pos % sizeof(uint64_t);
        UNROLL_LOOP(MAX_PARALLEL_COUNT)
        for (size_t y = 0; y < ParallelCount; ++y) {
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
            UNROLL_LOOP(MAX_PARALLEL_COUNT)
            for (size_t y = 0; y < ParallelCount; ++y) {
                hashes[y][i] = state.bytes[x][y][z];
            }
        }
    }

    template <size_t SpanExtent>
    static FORCE_INLINE void hash(const std::array<std::span<const uint8_t, SpanExtent>, ParallelCount> &data,
        const std::array<machine_hash_view, ParallelCount> &hashes) noexcept {
        keccak_ctx ctx;
        ctx.update(data);
        ctx.final(hashes);
    }

    template <size_t ConcatCount, size_t SpanExtent>
    static FORCE_INLINE void concat_hash(
        const std::array<std::array<std::span<const uint8_t, SpanExtent>, ParallelCount>, ConcatCount> &data,
        const std::array<machine_hash_view, ParallelCount> &hashes) noexcept {
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

MULTIVERSION_GENERIC void keccak_hash(std::span<const uint8_t> data, machine_hash_view hash) noexcept {
    keccak_ctx<1>::hash(std::array<std::span<const uint8_t>, 1>{data}, std::array<machine_hash_view, 1>{hash});
}
MULTIVERSION_GENERIC void keccak_hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept {
    keccak_ctx<1>::hash(std::array<std::span<const uint8_t>, 1>{data}, std::array<machine_hash_view, 1>{hash});
}
MULTIVERSION_GENERIC void keccak_concat_hash(std::span<const uint8_t> data1, std::span<const uint8_t> data2,
    machine_hash_view hash) noexcept {
    keccak_ctx<1>::concat_hash<2>(
        std::array<std::array<std::span<const uint8_t>, 1>, 2>{std::array<std::span<const uint8_t>, 1>{data1}, {data2}},
        std::array<machine_hash_view, 1>{hash});
}
MULTIVERSION_GENERIC void keccak_concat_hash(const_machine_hash_view data1, const_machine_hash_view data2,
    machine_hash_view hash) noexcept {
    keccak_ctx<1>::concat_hash<2>(
        std::array<std::array<std::span<const uint8_t>, 1>, 2>{std::array<std::span<const uint8_t>, 1>{data1}, {data2}},
        std::array<machine_hash_view, 1>{hash});
}

// x86_64 implementations

#ifdef USE_MULTIVERSINING_AMD64
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash(std::span<const uint8_t> data, machine_hash_view hash) noexcept {
    keccak_ctx<1>::hash(std::array<std::span<const uint8_t>, 1>{data}, std::array<machine_hash_view, 1>{hash});
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept {
    keccak_ctx<1>::hash(std::array<std::span<const uint8_t>, 1>{data}, std::array<machine_hash_view, 1>{hash});
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_concat_hash(std::span<const uint8_t> data1, std::span<const uint8_t> data2,
    machine_hash_view hash) noexcept {
    keccak_ctx<1>::concat_hash<2>(
        std::array<std::array<std::span<const uint8_t>, 1>, 2>{std::array<std::span<const uint8_t>, 1>{data1}, {data2}},
        std::array<machine_hash_view, 1>{hash});
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_concat_hash(const_machine_hash_view data1, const_machine_hash_view data2,
    machine_hash_view hash) noexcept {
    keccak_ctx<1>::concat_hash<2>(
        std::array<std::array<std::span<const uint8_t>, 1>, 2>{std::array<std::span<const uint8_t>, 1>{data1}, {data2}},
        std::array<machine_hash_view, 1>{hash});
}
#endif

} // namespace cartesi
