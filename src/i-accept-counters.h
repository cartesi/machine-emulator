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

#ifndef I_ACCEPT_COUNTERS_H
#define I_ACCEPT_COUNTERS_H

/// \file
/// \brief Accept counters interface

#include <cstdint>
#include <type_traits>

#include "meta.h"

namespace cartesi {

/// \class i_accept_counters
/// \brief Interface for state access classes (and others) that accept counters.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
template <typename DERIVED>
class i_accept_counters { // CRTP

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    void increment_counter(const char *name, const char *domain = nullptr) const {
        derived().do_increment_counter(name, domain);
    }

    uint64_t read_counter(const char *name, const char *domain = nullptr) const {
        return derived().do_read_counter(name, domain);
    }

    void write_counter(uint64_t val, const char *name, const char *domain = nullptr) const {
        derived().do_write_counter(val, name, domain);
    }
};

/// \brief SFINAE test implementation of the i_accept_counters interface
template <typename DERIVED>
using is_an_i_accept_counters =
    std::integral_constant<bool, is_template_base_of_v<i_accept_counters, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_accept_counters_v = is_an_i_accept_counters<DERIVED>::value;

} // namespace cartesi

#endif
