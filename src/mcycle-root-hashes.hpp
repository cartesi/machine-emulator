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

#ifndef MCYCLE_ROOT_HASHES_HPP
#define MCYCLE_ROOT_HASHES_HPP

#include <cstdint>
#include <optional>

#include "back-merkle-tree.hpp"
#include "interpret.hpp"
#include "machine-hash.hpp"

namespace cartesi {

/// \brief Result of collecting mcycle state root hashes
struct mcycle_root_hashes {
    machine_hashes hashes;                          ///< Result entries: state root hashes or bundle root hashes
    uint64_t mcycle_phase{};                        ///< Machine cycles elapsed in the current sampling period
    interpreter_break_reason break_reason{};        ///< Reason why function returned
    std::optional<back_merkle_tree> partial_bundle; ///< Partial bundle context
    std::string console_io_error;                   ///< Console I/O error message, if any
};

} // namespace cartesi

#endif
