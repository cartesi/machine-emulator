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

#ifndef MCYCLE_ROOT_HASHES_H
#define MCYCLE_ROOT_HASHES_H

#include <cstdint>
#include <optional>

#include "back-merkle-tree.h"
#include "interpret.h"
#include "machine-hash.h"

namespace cartesi {

/// \brief Collected mcycle root hashes
struct mcycle_root_hashes {
    machine_hashes hashes;                     ///< Root hashes collected after each machine cycle period
    uint64_t mcycle_phase{};                   ///< Machine cycles elapsed since last collected root hash
    interpreter_break_reason break_reason{};   ///< Reason why function returned
    std::optional<back_merkle_tree> back_tree; ///< Root hashes context
};

} // namespace cartesi

#endif
