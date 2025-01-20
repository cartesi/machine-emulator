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

#ifndef UARCH_STRICT_ALIASING_H
#define UARCH_STRICT_ALIASING_H

#include "compiler-defines.h"
#include <inttypes.h>

template <typename T, typename A = T>
static inline void ua_aliased_aligned_write(uint64_t paddr, T val);

template <typename T, typename A = T>
static inline T ua_aliased_aligned_read(uint64_t paddr);

#define UA_ALIASED_ALIGNED_WRITE(TYPE, INSN)                                                                           \
    template <>                                                                                                        \
    [[maybe_unused]] void ua_aliased_aligned_write<TYPE, TYPE>(uint64_t paddr, TYPE val) {                             \
        /* NOLINTNEXTLINE(hicpp-no-assembler) */                                                                       \
        asm volatile("mv a0, %0\n"                                                                                     \
                     "mv a1, %1\n" INSN " a1, (a0)\n"                                                                  \
                     : /* no output */                                                                                 \
                     : "r"(paddr), "r"(val)                                                                            \
                     : "a0", "a1" /* clobbered registers */                                                            \
        );                                                                                                             \
    }

UA_ALIASED_ALIGNED_WRITE(uint64_t, "sd")
UA_ALIASED_ALIGNED_WRITE(int64_t, "sd")
UA_ALIASED_ALIGNED_WRITE(uint32_t, "sw")
UA_ALIASED_ALIGNED_WRITE(int32_t, "sw")
UA_ALIASED_ALIGNED_WRITE(uint16_t, "sh")
UA_ALIASED_ALIGNED_WRITE(int16_t, "sh")
UA_ALIASED_ALIGNED_WRITE(uint8_t, "sb")
UA_ALIASED_ALIGNED_WRITE(int8_t, "sb")

//??D see if this is the best we can do
#define UA_ALIASED_ALIGNED_READ(TYPE, INSN)                                                                            \
    template <>                                                                                                        \
    [[maybe_unused]] TYPE ua_aliased_aligned_read<TYPE, TYPE>(uint64_t paddr) {                                        \
        /* NOLINTNEXTLINE(hicpp-no-assembler) */                                                                       \
        TYPE ret = 0;                                                                                                  \
        asm volatile("mv a0, %1\n" INSN " a1, (a0)\n"                                                                  \
                     "mv %0, a1\n"                                                                                     \
                     : "=r"(ret)                                                                                       \
                     : "r"(paddr), "r"(ret)                                                                            \
                     : "a0", "a1" /* clobbered registers */                                                            \
        );                                                                                                             \
        return ret;                                                                                                    \
    }

UA_ALIASED_ALIGNED_READ(uint64_t, "ld")
UA_ALIASED_ALIGNED_READ(int64_t, "ld")
UA_ALIASED_ALIGNED_READ(uint32_t, "lwu")
UA_ALIASED_ALIGNED_READ(int32_t, "lw")
UA_ALIASED_ALIGNED_READ(uint16_t, "lhu")
UA_ALIASED_ALIGNED_READ(int16_t, "lh")
UA_ALIASED_ALIGNED_READ(uint8_t, "lbu")
UA_ALIASED_ALIGNED_READ(int8_t, "lb")

//??D see if this is the best we can do
template <>
[[maybe_unused]] uint32_t ua_aliased_aligned_read<uint32_t, uint16_t>(uint64_t paddr) {
    // NOLINTNEXTLINE(hicpp-no-assembler)
    uint32_t ret = 0;
    asm volatile("mv a0, %1\n"
                 "lhu a1, (a0)\n"
                 "lhu a2, 2(a0)\n"
                 "slli a2, a2, 16\n"
                 "or a1, a2, a1\n"
                 "mv %0, a1\n"
                 : "=r"(ret)
                 : "r"(paddr), "r"(ret)
                 : "a0", "a1", "a2" // clobbered registers
    );
    return ret;
}

#endif
