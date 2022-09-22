// Copyright 2019 Cartesi Pte. Ltd.
//
// This file is part of the machine-emulator. The machine-emulator is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Lesser General Public License as published by the Free Software Foundation,
// either version 3 of the License, or (at your option) any later version.
//
// The machine-emulator is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the machine-emulator. If not, see http://www.gnu.org/licenses/.
//


#ifndef UARCH_RUNTIME_H
#define UARCH_RUNTIME_H

#include "uarch-printf.h"
#include <inttypes.h>

#include <stddef.h>

#define fprintf(a, ...) printf(__VA_ARGS__)

#define assert(a)                                                                                                      \
    if (!(a)) {                                                                                                        \
        printf("Assertion failed\n");                                                                                  \
        abort();                                                                                                       \
    }

extern "C" [[noreturn]] void abort(void);

#endif