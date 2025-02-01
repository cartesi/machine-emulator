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

#ifndef UARCH_STRICT_ALIASING_H
#define UARCH_STRICT_ALIASING_H

/// \file
/// \brief Enforcement of the strict aliasing rule

#include "compiler-defines.h"
#include "strict-aliasing.h"

namespace cartesi {

/// \brief Casts a pointer to an unsigned integer.
/// \details The pointer returned by this function
/// must only be read/written using aliased_aligned_read/aliased_aligned_write,
/// otherwise strict aliasing rules may be violated.
/// \tparam T Unsigned integer type to cast to.
/// \tparam PTR Pointer type to perform the cast.
/// \param addr The address of the pointer represented by an unsigned integer.
/// \returns A pointer.
static inline void *cast_phys_addr_to_ptr(uint64_t paddr) {
    // Enforcement on type arguments
    static_assert(sizeof(void *) == sizeof(uintptr_t));
    static_assert(sizeof(paddr) >= sizeof(uintptr_t));
    // Note that bellow we cast the address to void* first,
    // according to the C spec this is required is to ensure the same presentation, before casting to PTR
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,bugprone-casting-through-void,performance-no-int-to-ptr)
    return reinterpret_cast<void *>(static_cast<uintptr_t>(paddr));
}

//??D I don't know why GCC warns about this overflow when there is none.
//??D The code generated seems to be pretty good as well.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
/// \brief Writes a value to memory.
/// \tparam T Type of value.
/// \tparam A Type to which \p paddr is aligned.
/// \param paddr Where to write. Must be aligned to sizeof(A).
/// \param v Value to write.
template <typename T, typename A = T>
static inline void ua_aliased_aligned_write(uint64_t paddr, T v) {
    aliased_aligned_write<T, A>(cast_phys_addr_to_ptr(paddr), v);
}

/// \brief Reads a value from memory.
/// \tparam T Type of value.
/// \tparam A Type to which \p paddr is aligned.
/// \param paddr Where to find value. Must be aligned to sizeof(A).
/// \returns Value read.
template <typename T, typename A = T>
static inline T ua_aliased_aligned_read(uint64_t paddr) {
    return aliased_aligned_read<T, A>(cast_phys_addr_to_ptr(paddr));
}
#pragma GCC diagnostic pop

} // namespace cartesi

#endif
