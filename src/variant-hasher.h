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

#ifndef VARIANT_HASHER_H
#define VARIANT_HASHER_H

#include <cstdint>
#include <variant>

#include "i-hasher.h"
#include "keccak-256-hasher.h"
#include "sha-256-hasher.h"

namespace cartesi {

/// \brief Hash function
enum class hash_function_type : uint64_t {
    keccak256, ///< Keccak-256 (recommended for fraud proofs based on Microarchitecture)
    sha256,    ///< SHA-256 (recommended for fraud proofs using zkVMs)
};

class variant_hasher final : public i_hasher<variant_hasher> {
    std::variant<keccak_256_hasher, sha_256_hasher> m_hasher_impl;

public:
    static constexpr int MAX_LANE_COUNT = std::max(keccak_256_hasher::MAX_LANE_COUNT, sha_256_hasher::MAX_LANE_COUNT);

    explicit variant_hasher(hash_function_type algo) {
        switch (algo) {
            case hash_function_type::keccak256:
                m_hasher_impl = keccak_256_hasher{};
                break;
            case hash_function_type::sha256:
                m_hasher_impl = sha_256_hasher{};
                break;
            default:
                throw std::invalid_argument("unsupported hash function type");
        }
    }

    variant_hasher() = delete; ///< Default constructor is not allowed

    template <size_t ConcatCount, size_t LaneCount, size_t Extent>
    // NOLINTNEXTLINE(bugprone-exception-escape)
    void do_simd_concat_hash(const array2d<std::span<const unsigned char, Extent>, ConcatCount, LaneCount> &data,
        const std::array<machine_hash_view, LaneCount> &hash) noexcept {
        std::visit([&](auto &h) noexcept { h.do_simd_concat_hash(data, hash); }, m_hasher_impl);
    }

    // NOLINTNEXTLINE(bugprone-exception-escape)
    size_t do_get_optimal_lane_count() const noexcept {
        return std::visit([](auto &h) noexcept { return h.do_get_optimal_lane_count(); }, m_hasher_impl);
    }
};

} // namespace cartesi

#endif
