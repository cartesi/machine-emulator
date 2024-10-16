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
#include "uarch-constants.h"
#include <algorithm>

using namespace cartesi;

extern "C" void __cxa_pure_virtual() {
    abort();
}

void operator delete(void * /*ptr*/) {}
void operator delete(void * /*ptr*/, size_t /*size*/) {}

extern "C" void __assert_func(const char * /*file*/, int /*line*/, const char * /*func*/, const char * /*e*/) {}

extern "C" void __assert_fail(const char * /*__assertion*/, const char * /*__file*/, unsigned int /*__line*/,
    const char * /*__function*/) {}

extern "C" void *memmove(void *dest, const void *src, size_t n) {
    if (!n || src == dest) {
        return dest;
    }
    const auto *s = const_cast<char *>(reinterpret_cast<const char *>(src));
    auto *d = reinterpret_cast<char *>(dest);
    if (d < s) {
        for (; n; n--) {
            *d++ = *s++;
        }
    } else {
        while (n--) {
            d[n] = s[n];
        }
    }
    return dest;
}

extern "C" void *memcpy(void *dest, const void *src, size_t n) {
    const auto *s = reinterpret_cast<const unsigned char *>(src);
    auto *d = reinterpret_cast<unsigned char *>(dest);
    while (n--) {
        *d++ = *s++;
    }
    return dest;
}

extern "C" void *memset(void *ptr, int value, size_t num) {
    volatile unsigned char *p = reinterpret_cast<unsigned char *>(ptr);
    while (num--) {
        *p++ = value;
    }
    return ptr;
}

extern "C" void _putchar(char c) {
    asm volatile("mv a7, %0\n"
                 "mv a6, %1\n"
                 "ecall\n"
                 : // no output
                 : "r"(cartesi::uarch_ecall_functions::UARCH_ECALL_FN_PUTCHAR),
                 "r"(c)       // character to print
                 : "a7", "a6" // modified registers
    );
}

extern "C" NO_RETURN void abort() {
    asm volatile("ebreak"
                 : // no output
                 : // no input
                 : // no affected registers
    );
    // execution will never reach this point
    __builtin_trap();
}

namespace cartesi {

void os_open_tty() {}

void os_close_tty() {}

bool os_poll_tty(uint64_t timeout_us) {
    (void) timeout_us;
    return false;
}

int os_getchar() {
    return -1;
}

void os_putchar(uint8_t ch) {
    _putchar(ch);
}

} // namespace cartesi
