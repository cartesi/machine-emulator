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

#ifndef HASH_TREE_TARGET_H
#define HASH_TREE_TARGET_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

namespace cartesi {

/// \brief  Target environment for hash tree verification
enum class hash_tree_target : uint64_t {
    uarch, ///< Micro-architecture
    risc0, ///< RISC0
};

static inline std::optional<hash_tree_target> parse_hash_tree_target(uint64_t value) {
    switch (static_cast<hash_tree_target>(value)) {
        case hash_tree_target::uarch:
        case hash_tree_target::risc0:
            return static_cast<hash_tree_target>(value);
        default:
            return std::nullopt;
    }
}

static inline std::optional<hash_tree_target> parse_hash_tree_target(const char *name) {
    if (strcmp(name, "uarch") == 0) {
        return hash_tree_target::uarch;
    }
    if (strcmp(name, "risc0") == 0) {
        return hash_tree_target::risc0;
    }
    return std::nullopt;
}

} // namespace cartesi

#endif // HASH_H
