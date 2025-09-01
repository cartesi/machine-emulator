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

/// \file simd_vector_type.h
/// \brief Defines SIMD vector type traits for uint64_t and uint32_t operations
///
/// This header provides template specializations that map lane counts to appropriate
/// SIMD vector types with their corresponding alignment requirements.
/// It supports both scalar (single lane) and vector operations for efficient SIMD computations.

#ifndef SIMD_VECTOR_TYPE
#define SIMD_VECTOR_TYPE

#include <cstddef>
#include <cstdint> // IWYU pragma: keep

namespace cartesi {

/// \brief Template struct to define uint64_t vector types based on lane count
/// \tparam LaneCount Number of 64-bit lanes in the vector
template <size_t LaneCount>
struct uint64_vector_type;

/// \brief Specialization for single uint64_t value (1 lane)
template <>
struct uint64_vector_type<1> {
    using type = uint64_t __attribute__((vector_size(8))); ///< Scalar uint64_t type
    static constexpr size_t align = 16;                    ///< Recommended memory alignment requirement
};

/// \brief Specialization for 2-lane uint64_t vector (128-bit)
template <>
struct uint64_vector_type<2> {
    using type = uint64_t __attribute__((vector_size(16))); ///< 2x64-bit vector type
    static constexpr size_t align = 16;                     ///< Recommended memory alignment requirement
};

/// \brief Specialization for 4-lane uint64_t vector (256-bit)
template <>
struct uint64_vector_type<4> {
    using type = uint64_t __attribute__((vector_size(32))); ///< 4x64-bit vector type
    static constexpr size_t align = 32;                     ///< Recommended memory alignment requirement
};

/// \brief Specialization for 8-lane uint64_t vector (512-bit)
template <>
struct uint64_vector_type<8> {
    using type = uint64_t __attribute__((vector_size(64))); ///< 8x64-bit vector type
    static constexpr size_t align = 64;                     ///< Recommended memory alignment requirement
};

/// \brief Specialization for 16-lane uint64_t vector (1024-bit)
template <>
struct uint64_vector_type<16> {
    using type = uint64_t __attribute__((vector_size(128))); ///< 16x64-bit vector type
    static constexpr size_t align = 128;                     ///< Recommended memory alignment requirement
};

/// \brief Template struct to define uint32_t vector types based on lane count
/// \tparam LaneCount Number of 32-bit lanes in the vector
template <size_t LaneCount>
struct uint32_vector_type;

/// \brief Specialization for single uint32_t value (1 lane)
template <>
struct uint32_vector_type<1> {
    using type = uint32_t __attribute__((vector_size(4))); ///< Scalar uint32_t type
    static constexpr size_t align = 16;                    ///< Recommended memory alignment requirement
};

/// \brief Specialization for 2-lane uint32_t vector (64-bit)
template <>
struct uint32_vector_type<2> {
    using type = uint32_t __attribute__((vector_size(8))); ///< 2x32-bit vector type
    static constexpr size_t align = 16;                    ///< Recommended memory alignment requirement
};

/// \brief Specialization for 4-lane uint32_t vector (128-bit)
template <>
struct uint32_vector_type<4> {
    using type = uint32_t __attribute__((vector_size(16))); ///< 4x32-bit vector type
    static constexpr size_t align = 16;                     ///< Recommended memory alignment requirement
};

/// \brief Specialization for 8-lane uint32_t vector (256-bit)
template <>
struct uint32_vector_type<8> {
    using type = uint32_t __attribute__((vector_size(32))); ///< 8x32-bit vector type
    static constexpr size_t align = 32;                     ///< Recommended memory alignment requirement
};

/// \brief Specialization for 16-lane uint32_t vector (512-bit)
template <>
struct uint32_vector_type<16> {
    using type = uint32_t __attribute__((vector_size(64))); ///< 16x32-bit vector type
    static constexpr size_t align = 64;                     ///< Recommended memory alignment requirement
};

} // namespace cartesi

#endif
