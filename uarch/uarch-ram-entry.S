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

#include <address-range-defines.h>
#include <uarch-defines.h>

.section .text.init;
.align 3;
.global _start;
_start:
    // Initialize stack
    li sp, AR_UARCH_RAM_START_DEF
    li t0, AR_UARCH_RAM_LENGTH_DEF
    add sp, sp, t0 // stack pointer at the end of RAM
    call interpret_next_mcycle_with_uarch


