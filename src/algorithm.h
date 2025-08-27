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

#ifndef ALGORITHM_H
#define ALGORITHM_H

#include "concepts.h"

namespace cartesi::algorithm {

/// \brief Adds new entry to back of container, if not already there
/// \param value Value to insert.
template <BackInsertableContainer Container, typename T>
    requires std::constructible_from<typename Container::value_type, T &&> &&
    std::equality_comparable_with<typename Container::value_type, T>
constexpr void try_push_back(Container &container, T &&value) {
    if (container.empty() || container.back() != value) {
        container.push_back(std::forward<T>(value));
    }
}

} // namespace cartesi::algorithm

#endif
