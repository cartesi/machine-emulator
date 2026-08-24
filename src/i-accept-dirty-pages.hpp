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

#ifndef I_ACCEPT_DIRTY_PAGES_HPP
#define I_ACCEPT_DIRTY_PAGES_HPP

/// \file
/// \brief Accept dirty pages interface

#include <cstdint>
#include <type_traits>

#include "meta.hpp"

namespace cartesi {

/// \class i_accept_dirty_pages
/// \brief Interface for state access classes that must mark pages dirty explicitly.
/// \tparam DERIVED Derived class implementing the interface. (An example of CRTP.)
/// \details Only a state access with a deferred store needs this. The native
/// state_access writes straight through the host pointer in do_write_memory_word
/// without marking the page, so it relies on this explicit call (and the eviction
/// marking in the machine) to keep the dirty page tree complete; record_step_state_access
/// records that same deferral. Every other context marks or hashes each page at the
/// moment of the write: native write_word marks dirty, and the uarch
/// record path hashes on the spot. This is why the uarch does not accept
/// dirty pages. If a batched uarch write path were ever added, that
/// assumption would no longer hold and this reasoning would need to be revisited.
template <typename DERIVED>
class i_accept_dirty_pages { // CRTP
    i_accept_dirty_pages() = default;
    friend DERIVED;

    /// \brief Returns object cast as the derived class
    DERIVED &derived() {
        return *static_cast<DERIVED *>(this);
    }

    /// \brief Returns object cast as the derived class
    const DERIVED &derived() const {
        return *static_cast<const DERIVED *>(this);
    }

public:
    /// \brief Marks a page as dirty
    /// \param paddr Target physical address within page
    /// \param pma_index Index of PMA where page falls
    void mark_dirty_page(uint64_t paddr, uint64_t pma_index) const {
        derived().do_mark_dirty_page(paddr, pma_index);
    }
};

/// \brief SFINAE test implementation of the i_accept_dirty_pages interface
template <typename DERIVED>
using is_an_i_accept_dirty_pages =
    std::integral_constant<bool, is_template_base_of_v<i_accept_dirty_pages, std::remove_cvref_t<DERIVED>>>;

template <typename DERIVED>
constexpr bool is_an_i_accept_dirty_pages_v = is_an_i_accept_dirty_pages<DERIVED>::value;

} // namespace cartesi

#endif
