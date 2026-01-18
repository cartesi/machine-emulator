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

// Freestanding includes only - no standard library
#include <stdint.h>
#include <stddef.h>

#include "zisk-runtime.h"

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

extern "C" void __assert_fail(const char* /*assertion*/, const char* /*file*/, unsigned int /*line*/,
    const char* /*function*/) {
    abort();
}

extern "C" NO_RETURN void zk_abort_with_msg(const char *msg);

extern "C" NO_RETURN void abort(void) {
    zk_abort_with_msg("abort() called");
    __builtin_trap();
}

extern "C" void zk_putchar(char character);

extern "C" void _putchar(char character) {
    zk_putchar(character);
}

// This is in the std::__1 namespace but needs C++ linkage
namespace std {
namespace __1 {
    [[noreturn]] void __libcpp_verbose_abort(const char* /*format*/, ...) {
        abort();
    }
}
}
