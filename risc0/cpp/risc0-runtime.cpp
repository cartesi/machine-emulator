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
#include "replay-step-state-access-interop.h"
#include "os.h"

using namespace cartesi;

extern "C" void __cxa_pure_virtual() {}
void operator delete(void *, unsigned long) {}
void operator delete(void *, unsigned int) {}

extern "C" void __assert_func(const char *file, int line, const char *, const char *e) {}

extern "C" void __assert_fail(const char *__assertion, const char *__file, unsigned int __line,
    const char *__function) {
    abort();

}

extern "C" NO_RETURN void abort(void) {
    interop_abort_with_msg("abort() called");
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
}


// The __ucmpdi2 function performs an unsigned comparison between two 64-bit integers.
// It returns 0 if a == b, a positive value if a > b, and a negative value if a < b.
extern "C" int __ucmpdi2(uint64_t a, uint64_t b) {
    uint32_t a_high = static_cast<uint32_t>(a >> 32);
    uint32_t b_high = static_cast<uint32_t>(b >> 32);
    if (a_high > b_high) {
        return 1;
    } else if (a_high < b_high) {
        return -1;
    }
    uint32_t a_low = static_cast<uint32_t>(a);
    uint32_t b_low = static_cast<uint32_t>(b);
    if (a_low > b_low) {
        return 1;
    } else if (a_low < b_low) {
        return -1;
    }
    return 0;
}

extern "C" int  __clzdi2(uint64_t a) {
    if ((a >> 32) != 0) {
        return __builtin_clz(static_cast<uint32_t>(a >> 32));
    } 
    return 32 + __builtin_clz(static_cast<uint32_t>(a));
}


} // namespace cartesi
