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

/// \file
/// \brief Enforcement of the strict aliasing rule

namespace cartesi {

/// \brief Writes a value to memory.
/// \tparam T Type of value.
/// \param p Where to write. Must be aligned to sizeof(T).
/// \param v Value to write.
template <typename T>
static inline void aliased_aligned_write(void *p, T v) {
    memcpy(__builtin_assume_aligned(p, sizeof(T)), &v, sizeof(T));
}

/// \brief Reads a value from memory.
/// \tparam T Type of value.
/// \param p Where to find value. Must be aligned to sizeof(T).
/// \returns Value.
template <typename T>
static inline T aliased_aligned_read(const void *p) {
    T v;
    memcpy(&v, __builtin_assume_aligned(p, sizeof(T)), sizeof(T));
    return v;
}

/// \brief Reads an unaligned value from memory.
/// \tparam T Type of unaligned value.
/// \tparam U Type of aligned value.
/// \tparam ALIGN Alignment of p.
/// \param p Where to find value. Must be aligned to sizeof(U).
/// \returns Value.
template <typename T, typename U>
static inline T aliased_unaligned_read(const void *p) {
    T v;
    memcpy(&v, __builtin_assume_aligned(p, sizeof(U)), sizeof(T));
    return v;
}

/// \brief Casts a pointer to an unsigned integer.
/// \details The address returned by this function,
/// can later be converted to a pointer using cast_addr_to_ptr,
/// and must be read/written using aliased_aligned_read/aliased_aligned_write,
/// otherwise strict aliasing rules may be violated.
/// \tparam T Unsigned integer type to cast to.
/// \tparam PTR Pointer type to perform the cast.
/// \param ptr The pointer to retrieve its unsigned integer representation.
/// \returns An unsigned integer.
template <typename T, typename PTR>
static inline uint64_t cast_ptr_to_addr(PTR ptr) {
    // Enforcement on type arguments
    static_assert(std::is_pointer_v<PTR>);
    static_assert(std::is_unsigned_v<T>);
    static_assert(sizeof(PTR) == sizeof(uintptr_t));
    // We can only cast to integers that large enough to contain a pointer
    static_assert(sizeof(T) >= sizeof(uintptr_t), "expected sizeof(T) >= sizeof(uintptr_t)");
    // Note that bellow we cast the pointer to void* first,
    // according to the C spec this is required is to ensure the same presentation, before casting to uintptr_t
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,bugprone-casting-through-void)
    return static_cast<T>(reinterpret_cast<uintptr_t>(static_cast<const void *>(ptr)));
}

/// \brief Casts a pointer to an unsigned integer.
/// \details The pointer returned by this function
/// must only be read/written using aliased_aligned_read/aliased_aligned_write,
/// otherwise strict aliasing rules may be violated.
/// \tparam T Unsigned integer type to cast to.
/// \tparam PTR Pointer type to perform the cast.
/// \param addr The address of the pointer represented by an unsigned integer.
/// \returns A pointer.
template <typename PTR, typename T>
static inline PTR cast_addr_to_ptr(T addr) {
    // Enforcement on type arguments
    static_assert(std::is_pointer_v<PTR>);
    static_assert(std::is_unsigned_v<T>);
    static_assert(sizeof(PTR) == sizeof(uintptr_t));
    // We can only cast from integer that are large enough to contain a pointer
    static_assert(sizeof(T) >= sizeof(uintptr_t), "expected sizeof(T) >= sizeof(uintptr_t)");
    // Note that bellow we cast the address to void* first,
    // according to the C spec this is required is to ensure the same presentation, before casting to PTR
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,bugprone-casting-through-void,performance-no-int-to-ptr)
    return static_cast<PTR>(reinterpret_cast<void *>(static_cast<uintptr_t>(addr)));
}

} // namespace cartesi

#endif
