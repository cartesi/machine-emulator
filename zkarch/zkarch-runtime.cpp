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

#include "zkarch-runtime.h"
#include "os.h"
#include <algorithm>

using namespace cartesi;

extern "C" void __cxa_pure_virtual() {
    abort();
}

void operator delete(void *, unsigned long) {}
void operator delete(void *, unsigned int) {}

extern "C" void __assert_func(const char *file, int line, const char *, const char *e) {}

extern "C" void __assert_fail(const char *__assertion, const char *__file, unsigned int __line,
    // TODO: implement in rust risc0 guest mode and panic
    const char *__function) {}


extern "C" NO_RETURN void abort(void) {
    // TODO: implement in rust risc0 guest and panic
    __builtin_trap();
}

namespace cartesi {

void os_open_tty(void) {}

void os_close_tty(void) {}

bool os_poll_tty(uint64_t timeout_us) {
    (void) timeout_us;
    return false;
}

int os_getchar(void) {
    return -1;
}

void os_putchar(uint8_t ch) {
    // TODO: implement in rust risc0 guest mode
}

#include <stdint.h>

// The __ucmpdi2 function performs an unsigned comparison between two 64-bit integers.
// It returns 0 if a == b, a positive value if a > b, and a negative value if a < b.


extern "C" int __ucmpdi2(uint64_t a, uint64_t b) {
    uint32_t a_high = a >> 32;
    uint32_t b_high = b >> 32;
    if (a_high > b_high) {
        return 1;
    } else if (a_high < b_high) {
        return -1;
    }
    uint32_t a_low = (uint32_t)a;
    uint32_t b_low = (uint32_t)b;
    if (a_low > b_low) {
        return 1;
    } else if (a_low < b_low) {
        return -1;
    }
    return 0;
}

extern "C" int  __clzdi2(uint64_t a) {
    abort(); // TODO
}


} // namespace cartesi
