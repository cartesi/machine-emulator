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
#include <type_traits>

#include "i-hasher.h"
#include "machine-hash.h"

extern "C" {
#include "sha3.h"
}

namespace cartesi {

struct keccak_instance final {
    union {
        uint8_t b[200];
        uint64_t q[25];
    } st;
    int pt;
};

class keccak_256_hasher final : public i_hasher<keccak_256_hasher> {
    sha3_ctx_t m_ctx{};

    friend i_hasher<keccak_256_hasher>;

    void do_begin() {
        sha3_init(&m_ctx, machine_hash_size, 0x01);
    }

    template <std::ranges::contiguous_range R>
    void do_add_data(const R &r) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        sha3_update(&m_ctx, reinterpret_cast<const unsigned char *>(std::ranges::data(r)), std::ranges::size(r));
    }

    void do_end(machine_hash_view hash) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        sha3_final(reinterpret_cast<unsigned char *>(hash.data()), &m_ctx);
    }

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
};

} // namespace cartesi

#endif
