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

#ifndef IS_PRISTINE_H
#define IS_PRISTINE_H

#include "compiler-defines.h"
#include <stddef.h>
#include <stdint.h>

namespace cartesi {

// NOLINTNEXTLINE(clang-diagnostic-unknown-attributes)
static inline bool FORCE_OPTIMIZE_O3 is_pristine(const unsigned char *data, size_t length) {
    unsigned char bits = 0;
    for (size_t i = 0; i < length; ++i) {
        bits |= data[i];
    }
    return bits == 0;
}

} // namespace cartesi

#endif
