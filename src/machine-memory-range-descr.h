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

#ifndef MACHINE_MEMORY_RANGE_DESCR_H
#define MACHINE_MEMORY_RANGE_DESCR_H

#include <cstdint>
#include <string>
#include <vector>

namespace cartesi {

/// \brief Description of memory range used for introspection (i.e., get_memory_ranges())
struct machine_memory_range_descr { // NOLINT(bugprone-exception-escape)
    uint64_t start = 0;             ///< Start of memory range
    uint64_t length = 0;            ///< Length of memory range
    std::string description{};      ///< User-friendly description for memory range
};

/// \brief List of memory range descriptions used for introspection (i.e., get_memory_ranges())
using machine_memory_range_descrs = std::vector<machine_memory_range_descr>;

} // namespace cartesi

#endif
