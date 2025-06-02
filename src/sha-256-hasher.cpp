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

#include "sha-256-hasher.h"
#include "compiler-defines.h"
#include "i-hasher.h"
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

static constexpr size_t SHA256_ROUND_COUNT = 64;
static constexpr size_t SHA256_STATE_WORD_COUNT = 8;
static constexpr size_t SHA256_BUF_WORD_COUNT = 16;
static constexpr size_t SHA256_BUF_SIZE = 64;
static constexpr size_t SHA256_LENGTH_WORD_INDEX = 14;

template <size_t LaneCount, size_t DataExtent = std::dynamic_extent>
struct alignas(uint32_vector_type<LaneCount>::align) sha_256_context final {
    using word_vector_type = uint32_vector_type<LaneCount>::type;
    using word_bytes_array = uint8_t[SHA256_BUF_WORD_COUNT][LaneCount][sizeof(uint32_t)];
    using data_span = std::span<const unsigned char, DataExtent>;

    static constexpr size_t word_vector_align = uint32_vector_type<LaneCount>::align;

    word_vector_type m_words[SHA256_BUF_WORD_COUNT]{}; ///< Buffer for SHA-256 words, interleaved by lanes
    word_vector_type m_state[SHA256_STATE_WORD_COUNT] = {
        ///< SHA-256 state, interleaved by lanes
        word_vector_type{} | 0x6a09e667,
        word_vector_type{} | 0xbb67ae85,
        word_vector_type{} | 0x3c6ef372,
        word_vector_type{} | 0xa54ff53a,
        word_vector_type{} | 0x510e527f,
        word_vector_type{} | 0x9b05688c,
        word_vector_type{} | 0x1f83d9ab,
        word_vector_type{} | 0x5be0cd19,
    };

    FORCE_INLINE void update(const std::array<data_span, LaneCount> &data, size_t &pos, size_t &len) noexcept {
        [[maybe_unused]] auto words_bytes = // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<word_bytes_array &>(m_words);
        // Assume all data spans have the same length
        const size_t data_len = data[0].size();
        for (size_t i = 0; i < data_len;) {
            // Interleave data
            const size_t step = std::min(SHA256_BUF_SIZE - pos, data_len - i);
            if constexpr (DataExtent != std::dynamic_extent && DataExtent % sizeof(uint32_t) == 0) {
                // If data length is a multiple of word size, process a word at time
                UNROLL_LOOP(64)
                for (size_t j = 0; j < step; j += sizeof(uint32_t)) {
                    word_vector_type data_word;
                    UNROLL_LOOP_FULL()
                    for (size_t l = 0; l < LaneCount; ++l) {
                        uint32_t lane_word{};
                        __builtin_memcpy(&lane_word, &data[l][i + j], sizeof(lane_word));
                        data_word[l] = __builtin_bswap32(lane_word);
                    }
                    m_words[(pos + j) / sizeof(uint32_t)] = word_vector_type{} | data_word;
                }
            } else { // Otherwise, process a byte at time
                UNROLL_LOOP(64)
                for (size_t j = 0; j < step; j++) {
                    const size_t bi = (pos + j) / sizeof(uint32_t);
                    const size_t bj = sizeof(uint32_t) - 1 - ((pos + j) % sizeof(uint32_t));
                    UNROLL_LOOP_FULL()
                    for (size_t l = 0; l < LaneCount; ++l) {
                        words_bytes[bi][l][bj] = data[l][i + j];
                    }
                }
            }
            i += step;
            pos += step;
            // Perform SHA-256 compression
            if (pos >= SHA256_BUF_SIZE) [[unlikely]] {
                compress();
                len++;
                pos = 0;
            }
        }
    }

    FORCE_INLINE void finish(const std::array<machine_hash_view, LaneCount> &hashes, size_t pos, size_t len) noexcept {
        // Pad and append the 1 bit in the last word
        const size_t bi = pos / sizeof(uint32_t);
        const size_t bj = sizeof(uint32_t) - 1 - (pos % sizeof(uint32_t));
        m_words[bi] &= static_cast<uint32_t>(0xffffff00) << (bj * 8);
        m_words[bi] |= static_cast<uint32_t>(0x00000080) << (bj * 8);
        // Pad remaining words with zeros
        UNROLL_LOOP(64)
        for (size_t x = (pos / sizeof(uint32_t)) + 1; x < SHA256_BUF_WORD_COUNT; ++x) {
            m_words[x] = word_vector_type{};
        }
        // Compress if there is no space left to store the length
        if (pos >= SHA256_LENGTH_WORD_INDEX * sizeof(uint32_t)) [[unlikely]] {
            compress();
            // Clear all words
            UNROLL_LOOP_FULL()
            for (size_t x = 0; x < SHA256_BUF_WORD_COUNT; ++x) { // NOLINT(modernize-loop-convert)
                m_words[x] = word_vector_type{};
            }
        }
        // Store length in the last two words
        const uint64_t bit_len = ((static_cast<uint64_t>(len) * SHA256_BUF_SIZE) + static_cast<uint64_t>(pos)) * 8;
        m_words[SHA256_LENGTH_WORD_INDEX + 0] |= static_cast<uint32_t>(bit_len >> 32);
        m_words[SHA256_LENGTH_WORD_INDEX + 1] |= static_cast<uint32_t>(bit_len);
        // Perform final compression
        compress();
        // Deinterleave hash
        UNROLL_LOOP_FULL()
        for (size_t l = 0; l < LaneCount; ++l) {
            UNROLL_LOOP_FULL()
            for (size_t i = 0; i < MACHINE_HASH_SIZE; i += sizeof(uint32_t)) {
                const uint32_t word = __builtin_bswap32(m_state[i / sizeof(uint32_t)][l]);
                __builtin_memcpy(&hashes[l][i], &word, sizeof(uint32_t));
            }
        }
    }

    template <size_t ConcatCount>
    FORCE_INLINE static void simd_concat_hash(array2d<data_span, ConcatCount, LaneCount> data,
        std::array<machine_hash_view, LaneCount> hashes) noexcept {
        sha_256_context ctx;
        // Position and length are kept local to allow the compiler optimize them out
        // when DataExtent is a compile time constant.
        size_t pos = 0; // Current position in the buffer in bytes
        size_t len = 0; // Current position in the buffer in 64-byte blocks
        UNROLL_LOOP(4)
        for (size_t i = 0; i < ConcatCount; ++i) {
            ctx.update(data[i], pos, len);
        }
        ctx.finish(hashes, pos, len);
    }

private:
    FORCE_INLINE void compress() noexcept {
        // This code is inspired by SHA-256 pseudo-code from Wikipedia:
        // https://en.wikipedia.org/wiki/SHA-2#Pseudocode
        // Selected for its simplicity and vectorization-friendly structure.
        // However it was optimized to use circular buffers in words array to minimize memory bandwidth,
        // similar how is done in the generic SHA-256 implementation of OpenSSL.
        alignas(word_vector_align) static constexpr uint32_t SHA256_K[SHA256_ROUND_COUNT] = {0x428a2f98, 0x71374491,
            0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
            0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
            0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb,
            0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
            0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        // Unfortunately we can't use C++ functions that take vectors as arguments
        // because according to GCC it would violate ABI rules, so we have to use macros instead.
        // NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
#define SHA256_CH(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SHA256_S0(x) (SHA256_ROR(x, 2) ^ SHA256_ROR(x, 13) ^ SHA256_ROR(x, 22))
#define SHA256_S1(x) (SHA256_ROR(x, 6) ^ SHA256_ROR(x, 11) ^ SHA256_ROR(x, 25))
#define SHA256_G0(x) (SHA256_ROR(x, 7) ^ SHA256_ROR(x, 18) ^ ((x) >> 3))
#define SHA256_G1(x) (SHA256_ROR(x, 17) ^ SHA256_ROR(x, 19) ^ ((x) >> 10))
#define SHA256_WI(i, k) (((i) - (k)) & 15) // Circular buffer index for words
#define SHA256_SI(i, k) (((k) - (i)) & 7)  // Circular buffer index for state
        // NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-macro-to-enum,modernize-macro-to-enum)
        // Load state
        word_vector_type s[8]{m_state[0], m_state[1], m_state[2], m_state[3], m_state[4], m_state[5], m_state[6],
            m_state[7]};
        word_vector_type w[16];
        // Perform SHA-256 rounds
        UNROLL_LOOP_FULL()
        for (size_t r = 0; r < SHA256_ROUND_COUNT; r++) {
            const size_t i = r % 16;
            const size_t j = r - i;
            if (j == 0) {
                w[i] = m_words[i];
            } else {
                w[i] += SHA256_G1(w[SHA256_WI(i, 2)]) + w[SHA256_WI(i, 7)] + SHA256_G0(w[SHA256_WI(i, 15)]);
            }
            s[SHA256_SI(i, 7)] += w[i] + SHA256_S1(s[SHA256_SI(i, 4)]) +
                SHA256_CH(s[SHA256_SI(i, 4)], s[SHA256_SI(i, 5)], s[SHA256_SI(i, 6)]) + SHA256_K[i + j];
            s[SHA256_SI(i, 3)] += s[SHA256_SI(i, 7)];
            s[SHA256_SI(i, 7)] +=
                SHA256_S0(s[SHA256_SI(i, 0)]) + SHA256_MAJ(s[SHA256_SI(i, 0)], s[SHA256_SI(i, 1)], s[SHA256_SI(i, 2)]);
        }
        // Store state
        UNROLL_LOOP_FULL()
        for (size_t i = 0; i < SHA256_STATE_WORD_COUNT; ++i) {
            m_state[i] += s[i];
        }
    }
};

// Generic implementations

MULTIVERSION_GENERIC size_t sha_256_get_optimal_lane_count() noexcept {
#if defined(__x86_64__)
    // On AMD64, SSE2 has 128-bit registers, supporting up to 4 lanes.
    return 4;
#elif defined(__aarch64__)
    // On ARM64, NEON has 128-bit registers, supporting up to 4 lanes.
    return 4;
#elif defined(__riscv) && defined(__riscv_v)
    // RISC-V with Vector extension, we assume 128-bit registers are available, supporting up to 4 lanes.
    return 4;
#elif defined(__wasm_simd128__)
    // WebAssembly with SIMD extension has 128-bit registers, supporting up to 4 lanes.
    return 4;
#else
    // For other architectures, we assume vector instructions are not available and use scalar implementation.
    return 1;
#endif
}
MULTIVERSION_GENERIC void sha_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1>::simd_concat_hash<1>(data, hash);
}
MULTIVERSION_GENERIC void sha_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    sha_256_context<2, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    sha_256_context<4, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    sha_256_context<8, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_word_1x16(const array2d<const_hash_tree_word_view, 1, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_context<16, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    sha_256_context<2, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    sha_256_context<4, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    sha_256_context<8, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_GENERIC void sha_256_hash_2x16(const array2d<const_machine_hash_view, 2, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_context<16, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}

// x86_64 implementations

#ifdef USE_MULTIVERSINING_AMD64

// AVX2
MULTIVERSION_AMD64_AVX2_BMI_BMI2 size_t sha_256_get_optimal_lane_count() noexcept {
    // AVX2 has 256-bit registers, supporting up to 8 lanes.
    return 8;
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_data_1x1(const array2d<std::span<const unsigned char>, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1>::simd_concat_hash<1>(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x1(const array2d<const_hash_tree_word_view, 1, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x2(const array2d<const_hash_tree_word_view, 1, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    sha_256_context<2, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x4(const array2d<const_hash_tree_word_view, 1, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    sha_256_context<4, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x8(const array2d<const_hash_tree_word_view, 1, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    sha_256_context<8, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_word_1x16(const array2d<const_hash_tree_word_view, 1, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_context<16, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_data_2x1(const array2d<std::span<const unsigned char>, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x1(const array2d<const_machine_hash_view, 2, 1> &data,
    const std::array<machine_hash_view, 1> &hash) noexcept {
    sha_256_context<1, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x2(const array2d<const_machine_hash_view, 2, 2> &data,
    const std::array<machine_hash_view, 2> &hash) noexcept {
    sha_256_context<2, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x4(const array2d<const_machine_hash_view, 2, 4> &data,
    const std::array<machine_hash_view, 4> &hash) noexcept {
    sha_256_context<4, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x8(const array2d<const_machine_hash_view, 2, 8> &data,
    const std::array<machine_hash_view, 8> &hash) noexcept {
    sha_256_context<8, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void sha_256_hash_2x16(const array2d<const_machine_hash_view, 2, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_context<16, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}

// AVX-512

MULTIVERSION_AMD64_AVX512_BMI_BMI2 size_t sha_256_get_optimal_lane_count() noexcept {
    // AVX-512 has 512-bit registers, supporting up to 16 lanes.
    return 16;
}
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void sha_256_word_1x16(const array2d<const_hash_tree_word_view, 1, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_context<16, const_hash_tree_word_view::extent>::simd_concat_hash(data, hash);
}
MULTIVERSION_AMD64_AVX512_BMI_BMI2 void sha_256_hash_2x16(const array2d<const_machine_hash_view, 2, 16> &data,
    const std::array<machine_hash_view, 16> &hash) noexcept {
    sha_256_context<16, const_machine_hash_view::extent>::simd_concat_hash(data, hash);
}

#endif // USE_MULTIVERSINING_AMD64

} // namespace cartesi
