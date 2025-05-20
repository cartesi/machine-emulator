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
#include "machine-hash.h"

#include <cstddef>
#include <cstdint>

namespace cartesi {

// NOLINTBEGIN(cppcoreguidelines-pro-type-union-access)

constexpr uint8_t KECCAK_DSUFFIX = 0x01;
constexpr size_t KECCAK_HASH_SIZE = 32;
constexpr size_t KECCAK_RSIZE = 200 - (2 * KECCAK_HASH_SIZE);

constexpr static uint64_t rotl64(uint64_t x, uint8_t y) {
    return (x << y) | ((x) >> (64 - y));
}

FORCE_INLINE static void keccakf_impl(uint64_t st[25]) noexcept {
    static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "code assumes little-endian byte ordering");
    // Constants
    constexpr uint64_t KECCAKF_RNDC[24] = {0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a, 0x000000008000808b,
        0x800000000000008b, 0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001,
        0x8000000080008008};
    constexpr uint64_t KECCAKF_ROTC[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18,
        39, 61, 20, 44};
    constexpr uint64_t KECCAKF_PILN[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22,
        9, 6, 1};
    // Variables
    uint64_t bc[5];
    // Round iteration
    for (const uint64_t r : KECCAKF_RNDC) {
        // Theta
        UNROLL_LOOP(5)
        for (size_t i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }
        UNROLL_LOOP(5)
        for (size_t i = 0; i < 5; i++) {
            const uint64_t t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            UNROLL_LOOP(25)
            for (size_t j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }
        // Rho Pi
        uint64_t t = st[1];
        UNROLL_LOOP(24)
        for (size_t i = 0; i < 24; i++) {
            const size_t j = KECCAKF_PILN[i];
            bc[0] = st[j];
            st[j] = rotl64(t, KECCAKF_ROTC[i]);
            t = bc[0];
        }
        //  Chi
        UNROLL_LOOP(25)
        for (size_t j = 0; j < 25; j += 5) {
            UNROLL_LOOP(5)
            for (size_t i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            UNROLL_LOOP(5)
            for (size_t i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }
        //  Iota
        st[0] ^= r;
    }
}

template <size_t Extent>
FORCE_INLINE static size_t keccak_update_impl(keccak_ctx &ctx, std::span<const uint8_t, Extent> data,
    size_t j) noexcept {
    for (size_t i = 0; i < data.size();) {
        const size_t step = std::min(KECCAK_RSIZE - j, data.size() - i);
        for (size_t k = 0; k < step; k++) {
            ctx.b[j + k] ^= data[i + k];
        }
        i += step;
        j += step;
        if (j >= KECCAK_RSIZE) {
            keccakf(ctx.q);
            j = 0;
        }
    }
    return j;
}

FORCE_INLINE static void keccak_final_impl(keccak_ctx &ctx, machine_hash_view hash, size_t j) noexcept {
    ctx.b[j] ^= KECCAK_DSUFFIX;
    ctx.b[KECCAK_RSIZE - 1] ^= 0x80;
    keccakf(ctx.q);
    for (size_t i = 0; i < KECCAK_HASH_SIZE; i++) {
        hash[i] = ctx.b[i];
    }
}

template <size_t Extent>
FORCE_INLINE static void keccak_hash_impl(std::span<const uint8_t, Extent> data, machine_hash_view hash) noexcept {
    keccak_ctx ctx{};
    size_t j = 0;
    j = keccak_update_impl(ctx, data, 0);
    keccak_final_impl(ctx, hash, j);
}

template <size_t Extent>
FORCE_INLINE static void keccak_concat_hash_impl(std::span<const uint8_t, Extent> data1,
    std::span<const uint8_t, Extent> data2, machine_hash_view hash) noexcept {
    keccak_ctx ctx{};
    size_t j = 0;
    j = keccak_update_impl(ctx, data1, j);
    j = keccak_update_impl(ctx, data2, j);
    keccak_final_impl(ctx, hash, j);
}

// NOLINTEND(cppcoreguidelines-pro-type-union-access)

// Generic implementations

MULTIVERSION_GENERIC void keccakf(uint64_t st[25]) noexcept {
    keccakf_impl(st);
}
MULTIVERSION_GENERIC size_t keccak_update(keccak_ctx &ctx, std::span<const uint8_t> data, size_t j) noexcept {
    return keccak_update_impl(ctx, data, j);
}
MULTIVERSION_GENERIC void keccak_final(keccak_ctx &ctx, machine_hash_view hash, size_t j) noexcept {
    keccak_final_impl(ctx, hash, j);
}
MULTIVERSION_GENERIC void keccak_hash(std::span<const uint8_t> data, machine_hash_view hash) noexcept {
    keccak_hash_impl(data, hash);
}
MULTIVERSION_GENERIC void keccak_hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept {
    keccak_hash_impl(data, hash);
}
MULTIVERSION_GENERIC void keccak_concat_hash(std::span<const uint8_t> data1, std::span<const uint8_t> data2,
    machine_hash_view hash) noexcept {
    keccak_concat_hash_impl(data1, data2, hash);
}
MULTIVERSION_GENERIC void keccak_concat_hash(const_machine_hash_view data1, const_machine_hash_view data2,
    machine_hash_view hash) noexcept {
    keccak_concat_hash_impl(data1, data2, hash);
}

// x86_64 implementations

#ifdef USE_MULTIVERSINING_AMD64
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccakf(uint64_t st[25]) noexcept {
    keccakf_impl(st);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 size_t keccak_update(keccak_ctx &ctx, std::span<const uint8_t> data,
    size_t j) noexcept {
    return keccak_update_impl(ctx, data, j);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_final(keccak_ctx &ctx, machine_hash_view hash, size_t j) noexcept {
    keccak_final_impl(ctx, hash, j);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash(std::span<const uint8_t> data, machine_hash_view hash) noexcept {
    keccak_hash_impl(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept {
    keccak_hash_impl(data, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_concat_hash(std::span<const uint8_t> data1, std::span<const uint8_t> data2,
    machine_hash_view hash) noexcept {
    keccak_concat_hash_impl(data1, data2, hash);
}
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_concat_hash(const_machine_hash_view data1, const_machine_hash_view data2,
    machine_hash_view hash) noexcept {
    keccak_concat_hash_impl(data1, data2, hash);
}
#endif

} // namespace cartesi
