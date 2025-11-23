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

#include "compiler-defines.h"

#include <cinttypes>
#include <cstdarg>
#include <cstddef>
#include <cstdint>

// Define format macros if not already defined (freestanding environment)
#ifndef PRIx64
#define PRIx64 "llx"
#endif
#ifndef PRIu64
#define PRIu64 "llu"
#endif
#ifndef PRId64
#define PRId64 "lld"
#endif
#ifndef PRIx32
#define PRIx32 "x"
#endif
#ifndef PRIu32
#define PRIu32 "u"
#endif
#ifndef PRId32
#define PRId32 "d"
#endif

// Methods implemented in risc0 guest
extern "C" void print_from_c(const char *text);
extern "C" void abort_from_c();

// Mock printf/vprintf - just stubs for now
inline int printf(const char* /*fmt*/, ...) { return 0; }
inline int vprintf(const char* /*fmt*/, va_list /*ap*/) { return 0; }

// Mock stderr
//static void* const stderr = nullptr;

// Mock fprintf and vfprintf macros to match uarch-runtime.h behavior
#define fprintf(f, ...) printf(__VA_ARGS__)
#define vfprintf(f, fmt, ap) vprintf(fmt, ap)

#define assert(a)                                                                                                      \
    if (!(a)) {                                                                                                        \
        abort();                                                                                                       \
    }

extern "C" NO_RETURN void abort(void);

#endif
