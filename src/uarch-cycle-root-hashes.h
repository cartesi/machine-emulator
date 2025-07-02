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

#ifndef UARCH_CYCLE_ROOT_HASHES_H
#define UARCH_CYCLE_ROOT_HASHES_H

#include <cstdint>

#include "interpret.h"
#include "machine-hash.h"

namespace cartesi {

/// \brief Collected uarch cycle root hashes
struct uarch_cycle_root_hashes {
    machine_hashes hashes;                   ///< Root hashes after each uarch cycle
    std::vector<uint64_t> reset_indices;     ///< Indices into hashes[] after each uarch reset
    interpreter_break_reason break_reason{}; ///< Reason why function returned
};

} // namespace cartesi

#endif
