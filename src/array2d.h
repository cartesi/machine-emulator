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

#ifndef ARRAY2D_H
#define ARRAY2D_H

#include <array>
#include <cstddef>

namespace cartesi {

//??(edubart): In future C++ standards we should switch to `std::mdarray` or `std::mdspan`
template <class T, std::size_t M, std::size_t N>
using array2d = std::array<std::array<T, N>, M>;

} // namespace cartesi

#endif // ARRAY2D_H
