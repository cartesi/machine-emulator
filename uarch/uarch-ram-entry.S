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

#include <pma-defines.h>
#include <uarch-defines.h>

.section .text.init;
.align 2;
.global _start;
_start:    
    // Initialize stack
    li sp, PMA_UARCH_RAM_START_DEF  
    la t0, shadow_state_uarch_ram_length_abs_addr // t0=pointer to address of uarch_ram_length in state shadow
    ld t0, 0(t0)   // t0=address of uarch_ram_length in state shadow
    ld t0, 0(t0)   // t0=value of uarch_ram_length
    add sp, sp, t0 // stack pointer at the end of RAM

    call interpret_next_mcycle_with_uarch


