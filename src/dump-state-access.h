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

#ifndef DUMP_STATE_ACCESS_H
#define DUMP_STATE_ACCESS_H

#ifdef DUMP_STATE_ACCESS
template <typename... ARGS>
static inline auto DSA_PRINTF(ARGS... args) {
    return fprintf(stderr, args...);
}
#else
template <typename... ARGS>
static inline auto DSA_PRINTF(ARGS... /*args*/) {
    return 0;
}
#endif

#endif
