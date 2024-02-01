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

#include "uarch-pristine-state-hash.h"
#include "uarch-pristine.h"

#include <algorithm>

namespace cartesi {

static machine_merkle_tree::hash_type get_uarch_pristine_state_hash() noexcept {
    machine_merkle_tree::hash_type h;
    for (std::size_t i = 0; i < h.size(); ++i) {
        h[i] = uarch_pristine_hash[i];
    }
    return h;
}

/// \brief Hash of the pristine uarch state.
/// \details This hash is computed at compile time by the program compute-uarch-pristine-hash.cpp
const machine_merkle_tree::hash_type uarch_pristine_state_hash = get_uarch_pristine_state_hash();

} // namespace cartesi
