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

#ifndef UARCH_CYCLE_ROOT_HASHES_HPP
#define UARCH_CYCLE_ROOT_HASHES_HPP

#include <cstdint>
#include <vector>

#include "interpret.hpp"
#include "machine-hash.hpp"

namespace cartesi {

/// \brief Result of collecting uarch cycle state root hashes
struct uarch_cycle_root_hashes {
    machine_hashes hashes;                        ///< Result entries: state root hashes or bundle root hashes
    std::vector<uint64_t> mcycle_hash_offsets{0}; ///< Half-open offsets delimiting each mcycle's entries in hashes[]
    interpreter_break_reason break_reason{};      ///< Reason why function returned
};

} // namespace cartesi

#endif
