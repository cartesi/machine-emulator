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

#ifndef ASSERT_PRINTF_H
#define ASSERT_PRINTF_H

/// \file
/// \brief Microarchitecture-dependent includes for printf and assert

#ifdef MICROARCHITECTURE
#include "../uarch/uarch-runtime.h" // IWYU pragma: export
#else
#include <cassert> // IWYU pragma: export
#include <cstdio>  // IWYU pragma: export
#endif

#include <cinttypes> // IWYU pragma: export
#include <cstdarg>
#include <tuple>

static inline void d_vprintf(const char *fmt, va_list ap) {
    std::ignore = vfprintf(stderr, fmt, ap);
}

// Better to use C-style variadic function that checks for format!
// NOLINTNEXTLINE(cert-dcl50-cpp)
__attribute__((__format__(__printf__, 1, 2))) static inline void d_printf(const char *fmt, ...) {
    va_list ap{};
    va_start(ap, fmt);
    d_vprintf(fmt, ap);
    va_end(ap);
}

#endif
