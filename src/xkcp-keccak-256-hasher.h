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

#ifndef XKCP_KECCAK_256_HASHER_H
#define XKCP_KECCAK_256_HASHER_H

#include <type_traits>

extern "C" {
#include <KeccakSpongeWidth1600.h>
}

#include "i-hasher.h"

namespace cartesi {

class xkcp_keccak_256_hasher final : public i_hasher<xkcp_keccak_256_hasher, std::integral_constant<int, 32>> {

    KeccakWidth1600_SpongeInstance m_state;

    /// \brief No copy constructor
    xkcp_keccak_256_hasher(const xkcp_keccak_256_hasher &) = delete;
    /// \brief No move constructor
    xkcp_keccak_256_hasher(xkcp_keccak_256_hasher &&) = delete;
    /// \brief No copy assignment
    xkcp_keccak_256_hasher &operator=(const xkcp_keccak_256_hasher &) = delete;
    /// \brief No move assignment
    xkcp_keccak_256_hasher &operator=(xkcp_keccak_256_hasher &&) = delete;

    friend i_hasher<xkcp_keccak_256_hasher, std::integral_constant<int, 32>>;

    void do_begin(void) {
        KeccakWidth1600_SpongeInitialize(&m_state, 1088, 512);
    }

    void do_add_data(const unsigned char *data, size_t length) {
        KeccakWidth1600_SpongeAbsorb(&m_state, data, length);
    }

    void do_end(hash_type &hash) {
        KeccakWidth1600_SpongeAbsorbLastFewBits(&m_state, 1);
        KeccakWidth1600_SpongeSqueeze(&m_state, hash.data(), hash.size());
    }

public:
    /// \brief Default constructor
    xkcp_keccak_256_hasher(void) = default;
};

} // namespace cartesi

#endif
