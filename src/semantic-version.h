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

#ifndef SEMANTIC_VERSION_H
#define SEMANTIC_VERSION_H

#include <cstdint>
#include <string>

namespace cartesi {

struct semantic_version { // NOLINT(bugprone-exception-escape)
    uint32_t major{};
    uint32_t minor{};
    uint32_t patch{};
    std::string pre_release;
    std::string build;
};

} // namespace cartesi

#endif
