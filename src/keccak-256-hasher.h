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

#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>

#include "compiler-defines.h"
#include "i-hasher.h"
#include "machine-hash.h"

namespace cartesi {

// \brief Hashes the data using keccak
MULTIVERSION_GENERIC void keccak_hash(std::span<const uint8_t> data, machine_hash_view hash) noexcept;

// \brief Hashes the hash tree word using keccak
MULTIVERSION_GENERIC void keccak_hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept;

// \brief Hashes the concatenation of two data buffers using keccak
MULTIVERSION_GENERIC void keccak_concat_hash(std::span<const uint8_t> data1, std::span<const uint8_t> data2,
    machine_hash_view hash) noexcept;

// \brief Hashes the concatenation of two hashes using keccak
MULTIVERSION_GENERIC void keccak_concat_hash(const_machine_hash_view data1, const_machine_hash_view data2,
    machine_hash_view hash) noexcept;

// Optimized implementation for x86_64 architecture leveraging modern CPU instruction sets:
// - BMI1/BMI2 (Bit Manipulation Instructions) provide specialized bit operations:
//   * RORX performs optimized bitwise rotation without requiring separate shift operations
//   * ANDN efficiently computes (~x & y) in a single instruction
// - AVX2 is utilized just for efficient loading of constants and initial data XOR operations,
// the algorithm's inherent data dependencies prevent a more effective vectorization
#ifdef USE_MULTIVERSINING_AMD64
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash(std::span<const uint8_t> data, machine_hash_view hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_hash(const_hash_tree_word_view data, machine_hash_view hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_concat_hash(std::span<const uint8_t> data1, std::span<const uint8_t> data2,
    machine_hash_view hash) noexcept;
MULTIVERSION_AMD64_AVX2_BMI_BMI2 void keccak_concat_hash(const_machine_hash_view data1, const_machine_hash_view data2,
    machine_hash_view hash) noexcept;
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

    template <size_t Extent>
    static void do_hash(std::span<const uint8_t, Extent> data, machine_hash_view hash) noexcept {
        keccak_hash(data, hash);
    }

    template <size_t Extent>
    static void do_concat_hash(std::span<const uint8_t, Extent> data1, std::span<const uint8_t, Extent> data2,
        machine_hash_view hash) noexcept {
        keccak_concat_hash(data1, data2, hash);
    }
};

} // namespace cartesi

#endif
