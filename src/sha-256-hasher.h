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

#ifndef SHA256_HASHER_H
#define SHA256_HASHER_H

#include <type_traits>

#include "machine-hash.h"

extern "C" {
#include "sha256.h"
}

namespace cartesi {

class sha_256_hasher final {
    sha256_context m_ctx{};

public:
    void begin() {
        sha256_init(&m_ctx);
    }

    void add_data(const unsigned char *data, size_t length) {
        sha256_hash(&m_ctx, data, length);
    }

    void end(machine_hash &hash) {
        sha256_done(&m_ctx, hash.data());
    }

    /// \brief Default constructor
    sha_256_hasher() = default;

    /// \brief Default destructor
    ~sha_256_hasher() = default;

    /// \brief No copy constructor
    sha_256_hasher(const sha_256_hasher &) = default;
    /// \brief No move constructor
    sha_256_hasher(sha_256_hasher &&) = default;
    /// \brief No copy assignment
    sha_256_hasher &operator=(const sha_256_hasher &) = default;
    /// \brief No move assignment
    sha_256_hasher &operator=(sha_256_hasher &&) = default;
};

} // namespace cartesi

#endif
