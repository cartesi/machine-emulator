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

#ifndef XKCP_KANGAROOTWELVE_256_HASHER_H
#define XKCP_KANGAROOTWELVE_256_HASHER_H

#include <type_traits>

extern "C" {
#include <KangarooTwelve.h>
}

#include "i-hasher.h"

namespace cartesi {

class xkcp_kangarootwelve_hasher final : public i_hasher<xkcp_kangarootwelve_hasher, std::integral_constant<int, 32>> {
    bool m_started = false;
    KangarooTwelve_Instance m_instance{};

public:
    /// \brief No copy constructor
    xkcp_kangarootwelve_hasher(const xkcp_kangarootwelve_hasher &) = delete;
    /// \brief No move constructor
    xkcp_kangarootwelve_hasher(xkcp_kangarootwelve_hasher &&) = delete;
    /// \brief No copy assignment
    xkcp_kangarootwelve_hasher &operator=(const xkcp_kangarootwelve_hasher &) = delete;
    /// \brief No move assignment
    xkcp_kangarootwelve_hasher &operator=(xkcp_kangarootwelve_hasher &&) = delete;

    friend i_hasher<xkcp_kangarootwelve_hasher, std::integral_constant<int, 32>>;

    void do_begin(void);
    void do_add_data(const unsigned char *data, size_t length);
    void do_end(hash_type &hash);

    /// \brief Default constructor
    xkcp_kangarootwelve_hasher(void) = default;
    ~xkcp_kangarootwelve_hasher() = default;
};

} // namespace cartesi

#endif
