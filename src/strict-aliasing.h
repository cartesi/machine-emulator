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

#ifndef STRICT_ALIASING_H
#define STRICT_ALIASING_H

#include <cstdint>
#include <cstring>
#include <type_traits>

#include "host-addr.h"

/// \file
/// \brief Enforcement of the strict aliasing rule

namespace cartesi {

/// \brief Writes a value to memory.
/// \tparam T Type of value.
/// \tparam A Type to which \p haddr is aligned.
/// \param haddr Where to write. Must be aligned to sizeof(A).
/// \param v Value to write.
template <typename T, typename A = T>
static inline void aliased_aligned_write(host_addr haddr, T v) {
    memcpy(__builtin_assume_aligned(cast_host_addr_to_ptr(haddr), sizeof(A)), &v, sizeof(T));
}

/// \brief Reads a value from memory.
/// \tparam T Type of value.
/// \tparam A Type to which \p haddr is aligned.
/// \param haddr Where to find value. Must be aligned to sizeof(A).
/// \returns Value read.
template <typename T, typename A = T>
static inline T aliased_aligned_read(host_addr haddr) {
    T v;
    memcpy(&v, __builtin_assume_aligned(cast_host_addr_to_ptr(haddr), sizeof(A)), sizeof(T));
    return v;
}

/// \brief Writes a value to memory.
/// \tparam T Type of value.
/// \tparam A Type to which \p haddr is aligned.
/// \param p Where to write. Must be aligned to sizeof(A).
/// \param v Value to write.
template <typename T, typename A = T>
static inline void aliased_aligned_write(void *p, T v) {
    memcpy(__builtin_assume_aligned(p, sizeof(A)), &v, sizeof(T));
}

/// \brief Reads a value from memory.
/// \tparam T Type of value.
/// \tparam A Type to which \p haddr is aligned.
/// \param p Where to find value. Must be aligned to sizeof(A).
/// \returns Value read.
template <typename T, typename A = T>
static inline T aliased_aligned_read(const void *p) {
    T v;
    memcpy(&v, __builtin_assume_aligned(p, sizeof(A)), sizeof(T));
    return v;
}

} // namespace cartesi

#endif
