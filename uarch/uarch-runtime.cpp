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

#include "uarch-runtime.h"
#include "compiler-defines.h"
#include "uarch-constants.h"

#include <cstddef>
#include <cstdint>

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
extern "C" void __cxa_pure_virtual() {
    abort();
}

// NOLINTNEXTLINE(cert-dcl54-cpp,misc-new-delete-overloads,hicpp-new-delete-operators)
void operator delete(void * /*ptr*/) {}

// NOLINTNEXTLINE(cert-dcl54-cpp,misc-new-delete-overloads,hicpp-new-delete-operators)
void operator delete(void * /*ptr*/, size_t /*size*/) {}

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
extern "C" void __assert_func(const char * /*file*/, int /*line*/, const char * /*func*/, const char * /*e*/) {}

// NOLINTNEXTLINE(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
extern "C" void __assert_fail(const char * /*__assertion*/, const char * /*__file*/, unsigned int /*__line*/,
    const char * /*__function*/) {}

extern "C" void *memmove(void *dest, const void *src, size_t n) {
    if (n == 0 || src == dest) {
        return dest;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast,cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *s = const_cast<char *>(reinterpret_cast<const char *>(src));
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *d = reinterpret_cast<char *>(dest);
    if (d < s) {
        for (; n != 0; n--) {
            *d++ = *s++;
        }
    } else {
        while (n-- != 0) {
            d[n] = s[n];
        }
    }
    return dest;
}

extern "C" void *memcpy(void *dest, const void *src, size_t n) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    const auto *s = reinterpret_cast<const unsigned char *>(src);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto *d = reinterpret_cast<unsigned char *>(dest);
    while (n-- != 0) {
        *d++ = *s++;
    }
    return dest;
}

extern "C" void *memset(void *ptr, int value, size_t num) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    volatile unsigned char *p = reinterpret_cast<unsigned char *>(ptr);
    while (num-- != 0) {
        *p++ = value;
    }
    return ptr;
}

extern "C" NO_RETURN void abort() {
    // NOLINTNEXTLINE(hicpp-no-assembler)
    asm volatile("ebreak"
                 : // no output
                 : // no input
                 : // no affected registers
    );
    // execution will never reach this point
    __builtin_trap();
}
