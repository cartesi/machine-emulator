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
#include "i-hasher.h"
#include "keccakf.h"
#include "machine-hash.h"
#include "simd-vector-type.h"

#include <bit>
#include <cstddef>
#include <cstdint>
#include <span>

namespace cartesi {

// This code is not portable to big-endian architectures.
// NOLINTNEXTLINE(misc-redundant-expression)
static_assert(std::endian::native == std::endian::little, "code assumes little-endian byte ordering");

constexpr size_t KECCAK_WORD_COUNT = 25;
constexpr size_t KECCAK_RSIZE = (KECCAK_WORD_COUNT * sizeof(uint64_t)) - (static_cast<size_t>(2) * MACHINE_HASH_SIZE);

template <size_t LaneCount, size_t DataExtent = std::dynamic_extent>
struct alignas(uint64_vector_type<LaneCount>::align) keccak_256_context final {
    using word_vector_type = uint64_vector_type<LaneCount>::type;
    using word_bytes_array = uint8_t[KECCAK_WORD_COUNT][LaneCount][sizeof(uint64_t)];
    using data_span = std::span<const unsigned char, DataExtent>;

    static constexpr size_t word_vector_align = uint64_vector_type<LaneCount>::align; // 64-bit m_words

    word_vector_type m_words[5][5]{}; ///< Buffer for Keccak-256 words, interleaved by lanes

    FORCE_INLINE void update(const std::array<data_span, LaneCount> &data, size_t &pos) noexcept {
        [[maybe_unused]] auto words_bytes = // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<word_bytes_array &>(m_words);
        // Assume all data spans have the same length
        const size_t data_len = data[0].size();
        for (size_t i = 0; i < data_len;) {
            // Interleave data while XORing
            const size_t step = std::min(KECCAK_RSIZE - pos, data_len - i);
            if constexpr (DataExtent != std::dynamic_extent && DataExtent % sizeof(uint64_t) == 0) {
                // If data length is a multiple of word size, process a word at time
                UNROLL_LOOP(128)
                for (size_t j = 0; j < step; j += sizeof(uint64_t)) {
                    word_vector_type data_word;
                    UNROLL_LOOP_FULL()
                    for (size_t l = 0; l < LaneCount; ++l) {
                        uint64_t lane_word{};
                        __builtin_memcpy(&lane_word, &data[l][i + j], sizeof(lane_word));
                        data_word[l] = lane_word;
                    }
                    m_words[((pos + j) / sizeof(uint64_t)) / 5][((pos + j) / sizeof(uint64_t)) % 5] ^= data_word;
                }
            } else { // Otherwise, process a byte at time
                UNROLL_LOOP(128)
                for (size_t j = 0; j < step; j++) {
                    const size_t bi = (pos + j) / sizeof(uint64_t);
                    const size_t bj = (pos + j) % sizeof(uint64_t);
                    UNROLL_LOOP_FULL()
                    for (size_t l = 0; l < LaneCount; ++l) {
                        words_bytes[bi][l][bj] ^= data[l][i + j];
                    }
                }
            }
            i += step;
            pos += step;
            // Perform Keccak-256 permutation
            if (pos >= KECCAK_RSIZE) [[unlikely]] {
                keccakf_1600<word_vector_type, word_vector_align>(m_words);
                pos = 0;
            }
        }
    }

    FORCE_INLINE void finish(const std::array<machine_hash_view, LaneCount> &hashes, size_t pos) noexcept {
        // Append delimiter suffix
        constexpr uint64_t KECCAK_DSUFFIX = 0x01;
        const size_t dsuffix_word_pos = pos / sizeof(uint64_t);
        const size_t dsuffix_byte_pos = pos % sizeof(uint64_t);
        m_words[dsuffix_word_pos / 5][dsuffix_word_pos % 5] ^= KECCAK_DSUFFIX << (dsuffix_byte_pos * 8);
        // Append last bit
        constexpr uint64_t KECCAK_LASTBIT = 0x80;
        constexpr size_t lastbit_word_pos = (KECCAK_RSIZE - 1) / sizeof(uint64_t);
        constexpr size_t lastbit_byte_pos = (KECCAK_RSIZE - 1) % sizeof(uint64_t);
        m_words[lastbit_word_pos / 5][lastbit_word_pos % 5] ^= KECCAK_LASTBIT << (lastbit_byte_pos * 8);
        // Perform last permutation
        keccakf_1600<word_vector_type, word_vector_align>(m_words);
        // Deinterleave hash
        UNROLL_LOOP_FULL()
        for (size_t l = 0; l < LaneCount; ++l) {
            UNROLL_LOOP_FULL()
            for (size_t i = 0; i < MACHINE_HASH_SIZE; i += sizeof(uint64_t)) {
                const uint64_t word = m_words[0][i / sizeof(uint64_t)][l];
                __builtin_memcpy(&hashes[l][i], &word, sizeof(uint64_t));
            }
        }
    }
    template <size_t ConcatCount>
    FORCE_INLINE static void simd_concat_hash(array2d<data_span, ConcatCount, LaneCount> data,
        std::array<machine_hash_view, LaneCount> hashes) noexcept {
        keccak_256_context ctx;
        // Position is kept local to allow the compiler optimize it out when DataExtent is a compile time constant.
        size_t pos = 0;
        UNROLL_LOOP(4)
        for (size_t i = 0; i < ConcatCount; ++i) {
            ctx.update(data[i], pos);
        }
        ctx.finish(hashes, pos);
    }
};

// Generic implementations

MULTIVERSION_GENERIC size_t keccak_256_get_optimal_lane_count() noexcept {
#if defined(__x86_64__)
    // On AMD64, SSE2 has 128-bit registers, supporting up to 2 lanes.
    return 2;
#elif defined(__aarch64__)
    // On ARM64, NEON has 128-bit registers, supporting up to 2 lanes.
    return 2;
#elif defined(__riscv) && defined(__riscv_v)
    // RISC-V with Vector extension, we assume 128-bit registers are available, supporting up to 2 lanes.
    return 2;
#elif defined(__wasm_simd128__)
    // WebAssembly with SIMD extension has 128-bit registers, supporting up to 2 lanes.
    return 2;
#else
    // For other architectures, we assume vector instructions are not available and use scalar implementation.
    return 1;
#endif
}

MULTIVERSION_GENERIC void keccak_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1>::simd_concat_hash<1>(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_256_context<2, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_256_context<4, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_context<8, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_256_context<2, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_256_context<4, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void keccak_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_context<8, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}

// x86_64 implementations

#ifdef USE_MULTIVERSINING_AMD64

// AVX2
MULTIVERSION_AMD64_AVX2_BMI_BMI2 size_t keccak_256_get_optimal_lane_count() noexcept {
    // AVX2 has 256-bit registers, supporting up to 4 lanes.
    return 4;
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1>::simd_concat_hash<1>(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_256_context<2, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_256_context<4, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_context<8, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    keccak_256_context<1, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    keccak_256_context<2, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    keccak_256_context<4, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_context<8, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}

// AVX-512

MULTIVERSION_AMD64_AVX512_BMI_BMI2 size_t keccak_256_get_optimal_lane_count() noexcept {
    // AVX-512 has 512-bit registers, supporting up to 8 lanes.
    return 8;
}
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_context<8, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void keccak_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    keccak_256_context<8, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}

#endif // USE_MULTIVERSINING_AMD64

} // namespace cartesi
