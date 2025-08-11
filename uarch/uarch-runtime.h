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

#include "compiler-defines.h"
#include "third-party/printf/printf.h"

#include <cinttypes>
#include <cstddef>

#ifndef NDEBUG
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define assert(a)                                                                                                      \
    do {                                                                                                               \
        if (!(a)) {                                                                                                    \
            printf("Assertion failed: %s, %s:%d, %s\n", #a, __FILE__, __LINE__, __func__);                             \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
#else
// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define assert(a)
#endif

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define fprintf(f, ...) printf(__VA_ARGS__)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define vfprintf(f, fmt, ap) vprintf(fmt, ap)

extern "C" NO_RETURN void abort();

namespace cartesi {

void os_open_tty();
void os_close_tty();
bool os_poll_tty(uint64_t /*timeout_us*/);
int os_getchar();
void os_putchar(uint8_t ch);

} // namespace cartesi

#endif
