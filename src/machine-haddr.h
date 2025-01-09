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

#ifndef MACHINE_HADDR_H
#define MACHINE_HADDR_H

namespace cartesi {

// This is simply an uint64_t as a separate type, not automatically convertible to uint64_t
// It prevents any attempt of passing a machine_haddr where one is not expected
enum class machine_haddr : uint64_t {};

// Comparison operaator
static constexpr bool operator<(machine_haddr a, machine_haddr b) {
    return static_cast<uint64_t>(a) < static_cast<uint64_t>(b);
}

// Addition between machine_haddr
static constexpr machine_haddr operator+(machine_haddr a, machine_haddr b) {
    return machine_haddr{static_cast<uint64_t>(a) + static_cast<uint64_t>(b)};
}

// Subtraction between machine_haddr
static constexpr machine_haddr operator-(machine_haddr a, machine_haddr b) {
    return machine_haddr{static_cast<uint64_t>(a) - static_cast<uint64_t>(b)};
}

// Addition between machine_haddr and uint64_t
static constexpr machine_haddr operator+(uint64_t a, machine_haddr b) {
    return machine_haddr{a + static_cast<uint64_t>(b)};
}

// Addition between machine_haddr and uint64_t
static constexpr machine_haddr operator+(machine_haddr a, uint64_t b) {
    return machine_haddr{static_cast<uint64_t>(a) + b};
}

// Subtraction between machine_haddr and uint64_t
static constexpr machine_haddr operator-(uint64_t a, machine_haddr b) {
    return machine_haddr{a - static_cast<uint64_t>(b)};
}

// Subtraction between machine_haddr and uint64_t
static constexpr machine_haddr operator-(machine_haddr a, uint64_t b) {
    return machine_haddr{static_cast<uint64_t>(a) - b};
}

/// \brief Converts pointer to machine_haddr.
/// \tparam PTR Pointer type to perform the cast.
/// \param ptr The pointer to retrieve its unsigned integer representation.
/// \returns Corresponding machine_haddr.
/// \details Use cast_haddr_to_ptr The address returned by this function,
/// can later be converted to a pointer using cast_addr_to_ptr,
/// and must be read/written using aliased_aligned_read/aliased_aligned_write,
/// otherwise strict aliasing rules may be violated.
static inline machine_haddr cast_ptr_to_haddr(const void *ptr) {
    static_assert(sizeof(void *) == sizeof(uintptr_t));
    static_assert(sizeof(machine_haddr) >= sizeof(uintptr_t));
    // Note that bellow we cast the pointer to void* first,
    // according to the C spec this is required is to ensure the same presentation, before casting to uintptr_t
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,bugprone-casting-through-void)
    return machine_haddr{reinterpret_cast<uintptr_t>(ptr)};
}

/// \brief Casts a pointer to an unsigned integer.
/// \details The pointer returned by this function
/// must only be read/written using aliased_aligned_read/aliased_aligned_write,
/// otherwise strict aliasing rules may be violated.
/// \tparam T Unsigned integer type to cast to.
/// \tparam PTR Pointer type to perform the cast.
/// \param addr The address of the pointer represented by an unsigned integer.
/// \returns A pointer.
static inline void *cast_haddr_to_ptr(machine_haddr haddr) {
    // Enforcement on type arguments
    static_assert(sizeof(void *) == sizeof(uintptr_t));
    static_assert(sizeof(machine_haddr) >= sizeof(uintptr_t));
    // Note that bellow we cast the address to void* first,
    // according to the C spec this is required is to ensure the same presentation, before casting to PTR
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast,bugprone-casting-through-void,performance-no-int-to-ptr)
    return reinterpret_cast<void *>(static_cast<uintptr_t>(haddr));
}

} // namespace cartesi

#endif
