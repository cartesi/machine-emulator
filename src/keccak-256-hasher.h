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

class keccak_256_hasher final {
    sha3_ctx_t m_ctx{};

public:
    void begin() {
        sha3_init(&m_ctx, 32, 0x01);
    }

    void add_data(const unsigned char *data, size_t length) {
        sha3_update(&m_ctx, data, length);
    }

    void end(machine_hash &hash) {
        sha3_final(hash.data(), &m_ctx);
    }

    /// \brief Default constructor
    keccak_256_hasher() = default;

    /// \brief Default destructor
    ~keccak_256_hasher() = default;

    /// \brief No copy constructor
    keccak_256_hasher(const keccak_256_hasher &) = default;
    /// \brief No move constructor
    keccak_256_hasher(keccak_256_hasher &&) = default;
    /// \brief No copy assignment
    keccak_256_hasher &operator=(const keccak_256_hasher &) = default;
    /// \brief No move assignment
    keccak_256_hasher &operator=(keccak_256_hasher &&) = default;
};

} // namespace cartesi

#endif
