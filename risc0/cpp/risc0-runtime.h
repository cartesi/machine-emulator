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

#ifndef RISC0_RUNTIME_H
#define RISC0_RUNTIME_H

// Include third-party printf FIRST - provides printf/snprintf/vprintf/etc
// These must be defined before any code that expects them
#include "printf/printf.h"

#include "compiler-defines.h"

#include <cinttypes>
#include <cstddef>

#define PRIu64 "llu"
#define PRIx64 "llx"
#define PRId64 "lld"

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define fprintf(f, ...) printf(__VA_ARGS__)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define vfprintf(f, fmt, ap) vprintf(fmt, ap)

// NOLINTNEXTLINE(cppcoreguidelines-macro-usage)
#define assert(a)                                                                                                      \
    if (!(a)) {                                                                                                        \
        abort();                                                                                                       \
    }

extern "C" NO_RETURN void abort(void);

#endif
