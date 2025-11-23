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

#include <algorithm>
#include <cstdio>
#include <stdint.h>

#include "risc0-runtime.h"

extern "C" void __cxa_pure_virtual() {
    abort();
}

extern "C" int atexit([[maybe_unused]] void (*f)()) {
    return 0;
}

void operator delete(void* /*ptr*/) noexcept {}
void operator delete(void* /*ptr*/, size_t /*size*/) noexcept {}

extern "C" void __assert_func(const char* /*file*/, int /*line*/, const char* /*func*/, const char* /*e*/) {
    abort();
}

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
extern "C" void __assert_fail(const char* /*assertion*/, const char* /*file*/, unsigned int /*line*/,
    const char* /*function*/) {
    abort();
}

extern "C" NO_RETURN void zk_abort_with_msg(const char *msg);

extern "C" NO_RETURN void abort(void) {
    zk_abort_with_msg("abort() called");
    __builtin_trap();
}

// Unsigned comparison of two 64-bit integers.
// from GCC libgcc2.c
extern "C" int __ucmpdi2(uint64_t a, uint64_t b) {
    return (a > b) - (a < b) + 1;
}

// Count leading zeros for 64-bit integer.
// from GCC libgcc2.c __clzDI2
extern "C" int __clzdi2(uint64_t a) {
    uint32_t high = static_cast<uint32_t>(a >> 32);
    if (high != 0) {
        return __builtin_clz(high);
    }
    return 32 + __builtin_clz(static_cast<uint32_t>(a));
}

extern "C" void zk_putchar(char character);

extern "C" void _putchar(char character) {
    zk_putchar(character);
}

