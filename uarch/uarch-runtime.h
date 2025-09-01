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

#ifndef UARCH_RUNTIME_H
#define UARCH_RUNTIME_H

// This is redundant, however should fix linter errors when editing source files
#ifndef MICROARCHITECTURE
#define MICROARCHITECTURE
#endif

#include "compiler-defines.h"
#include "third-party/printf/printf.h"

#include <cinttypes>
#include <cstddef>

#ifndef NDEBUG
// NOLINTBEGIN(cppcoreguidelines-macro-usage,cppcoreguidelines-avoid-do-while,modernize-use-std-print)
#define assert(a)                                                                                                      \
    do {                                                                                                               \
        if (!(a)) {                                                                                                    \
            printf("Assertion failed: %s, %s:%d, %s\n", #a, __FILE__, __LINE__, __func__);                             \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
// NOLINTEND(cppcoreguidelines-macro-usage,cppcoreguidelines-avoid-do-while,modernize-use-std-print)
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define assert(a)
#endif

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define fprintf(f, ...) printf(__VA_ARGS__)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define vfprintf(f, fmt, ap) vprintf(fmt, ap)

extern "C" NO_RETURN void abort() noexcept;

#endif
