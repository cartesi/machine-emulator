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

#ifndef ZISK_RUNTIME_H
#define ZISK_RUNTIME_H

// libc++ freestanding configuration (must come before any libc++ headers)

#define _LIBCPP___CONFIG_SITE
#define _LIBCPP_ABI_VERSION 1
#define _LIBCPP_ABI_NAMESPACE __1

// Hardening mode constants (required by libc++)
#define _LIBCPP_HARDENING_MODE_NONE (1 << 1)
#define _LIBCPP_HARDENING_MODE_FAST (1 << 2)
#define _LIBCPP_HARDENING_MODE_EXTENSIVE (1 << 3)
#define _LIBCPP_HARDENING_MODE_DEBUG (1 << 4)
#define _LIBCPP_HARDENING_MODE_DEFAULT _LIBCPP_HARDENING_MODE_NONE
#define _LIBCPP_HARDENING_MODE _LIBCPP_HARDENING_MODE_NONE

#define _LIBCPP_HAS_NO_EXCEPTIONS
#define _LIBCPP_HAS_NO_RTTI
#define _LIBCPP_FREESTANDING

// ============================================================================
// C library stubs for freestanding
// ============================================================================

typedef struct { unsigned char __mbstate8[128]; } mbstate_t;
typedef struct { int quot; int rem; } div_t;
typedef struct { long quot; long rem; } ldiv_t;
typedef struct { long long quot; long long rem; } lldiv_t;

#define EOF (-1)
#ifndef NULL
#define NULL ((void*)0)
#endif

#ifdef __cplusplus
typedef decltype(sizeof(int)) size_t;
#else
typedef unsigned long size_t;
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Memory functions (implemented in Rust)
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);
size_t strlen(const char *s);

// Division functions - required by <cstdlib>
div_t div(int numer, int denom);
ldiv_t ldiv(long numer, long denom);
lldiv_t lldiv(long long numer, long long denom);

// <cstdio> uses "using ::remove" which conflicts with std::remove algorithm
int remove(const char *pathname);
int rename(const char *oldpath, const char *newpath);

#ifdef __cplusplus
}
#endif

// ============================================================================
// Runtime support
// ============================================================================

#include "printf/printf.h"
#include "compiler-defines.h"

#include <stdint.h>
#include <stddef.h>

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
